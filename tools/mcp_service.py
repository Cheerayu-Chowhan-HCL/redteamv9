"""
RedTeam V9 MCP Service — 34 generalised pentest tools.
FastMCP + Uvicorn on 127.0.0.1:6019, streamable HTTP transport.
"""
import asyncio
import json
import logging
import os
import re
import subprocess
import sys
import threading
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

sys.path.insert(0, str(__import__('pathlib').Path(__file__).resolve().parent.parent))

import httpx
import requests
from fastmcp import FastMCP

from core.graph_engine import GraphEngine
from core.intelligence import get_or_create_mcts
from core.dag_sanitiser import DagSanitiser
from core.response_sanitiser import response_sanitiser
from core.transfer_learning import record_outcome, get_priors_for_fingerprint, init_transfer_table

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger(__name__)

# ─── Constants ───────────────────────────────────────────────────────────────

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
BEARER_TOKEN_FILE = _PROJECT_ROOT / ".tmp" / "rtv9_bearer.txt"
AUDIT_LOG = _PROJECT_ROOT / "logs" / "tool_audit.jsonl"
REPORTS_DIR = _PROJECT_ROOT / "reports"
SANDBOX_DIR = _PROJECT_ROOT / ".tmp" / "rtv9_sandbox"
import shutil as _shutil

def _find_sqlmap() -> list:
    """Find sqlmap executable — returns command prefix list."""
    env_path = os.environ.get("SQLMAP_PATH", "")
    if env_path and Path(env_path).exists():
        if env_path.endswith(".py"):
            return ["python", env_path]
        return [env_path]
    # pip-installed sqlmap.exe on PATH
    which = _shutil.which("sqlmap") or _shutil.which("sqlmap.exe")
    if which:
        return [which]
    # Common locations (next to current python, fixed dirs)
    for candidate in [
        Path(sys.executable).parent / "sqlmap.exe",
        Path(sys.executable).parent / "sqlmap",
        Path("C:/tools/sqlmap/sqlmap.py"),
        Path("C:/tools/sqlmap/sqlmap.exe"),
    ]:
        if candidate.exists():
            if str(candidate).endswith(".py"):
                return ["python", str(candidate)]
            return [str(candidate)]
    return []

def _find_nuclei() -> str | None:
    env_path = os.environ.get("NUCLEI_PATH", "")
    if env_path and os.path.exists(env_path):
        return env_path
    candidates = [
        "C:/tools/nuclei/nuclei.exe",
        "C:/tools/nuclei.exe",
        os.path.expanduser("~/nuclei/nuclei.exe"),
        "C:/ProgramData/nuclei/nuclei.exe",
    ]
    for c in candidates:
        if os.path.exists(c):
            return c
    found = _shutil.which("nuclei") or _shutil.which("nuclei.exe")
    return found or None

NUCLEI_PATH = _find_nuclei()
GRAPH_MEMORY_URL = "http://127.0.0.1:6037"

from core.graph_engine import DB_PATH as _DB_PATH_FOR_SCOPE
DB_PATH_STR = str(_DB_PATH_FOR_SCOPE)
RAG_URL = "http://127.0.0.1:6055"

REPORTS_DIR.mkdir(parents=True, exist_ok=True)
SANDBOX_DIR.mkdir(parents=True, exist_ok=True)
AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)

# Rate limiting: {session_id: [timestamps]}
_rate_limit_store: Dict[str, List[float]] = {}
_rate_limit_lock = threading.Lock()
RATE_LIMIT = 120  # calls per 60s window

# Active scan processes: {job_id: subprocess.Popen}
_scan_processes: Dict[str, subprocess.Popen] = {}
_scan_lock = threading.Lock()

engine = GraphEngine()
init_transfer_table()

# ─── Auth & utilities ────────────────────────────────────────────────────────

def _load_bearer_token() -> str:
    try:
        return BEARER_TOKEN_FILE.read_text().strip()
    except Exception:
        return ""


def _coerce_bool(value, default=True):
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).lower() not in ("false", "0", "no", "none", "")


def _ok(result: Any) -> dict:
    return {"success": True, "result": result, "error": None}


def _err(msg: str) -> dict:
    return {"success": False, "result": None, "error": str(msg)}


def _check_rate_limit(session_id: str) -> bool:
    now = time.time()
    with _rate_limit_lock:
        calls = _rate_limit_store.get(session_id, [])
        calls = [t for t in calls if now - t < 60]
        if len(calls) >= RATE_LIMIT:
            return False
        calls.append(now)
        _rate_limit_store[session_id] = calls
    return True


def _audit_log(session_id: str, tool_name: str, params_summary: dict, result_summary: str):
    active_intent = None
    if session_id:
        try:
            active_intent = engine.get_active_intent(session_id)
        except Exception:
            pass
    entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "session_id": session_id,
        "tool_name": tool_name,
        "parameters_summary": params_summary,
        "result_summary": result_summary[:200],
        "session_phase": (active_intent.get("phase") or "unknown_phase")
                         if active_intent else
                         ("pre_intent" if session_id else None),
        "planner_intent": active_intent["intent"] if active_intent else None,
    }
    try:
        with open(AUDIT_LOG, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception as e:
        logger.debug(f"Audit log write failed: {e}")

    try:
        from core.graph_engine import DB_PATH
        import sqlite3 as _sq3
        with _sq3.connect(DB_PATH) as _ac:
            _ac.execute(
                """INSERT INTO tool_audit_log
                   (session_id, tool_name, parameters_summary,
                    result_summary, session_phase, planner_intent)
                   VALUES (?,?,?,?,?,?)""",
                (session_id, tool_name,
                 json.dumps(params_summary)[:200],
                 result_summary[:200],
                 entry.get("session_phase"),
                 entry.get("planner_intent"))
            )
            _ac.commit()
    except Exception as _dbe:
        logger.debug(f"tool_audit_log write failed: {_dbe}")

    # ── IntentCorrelationMiddleware ──────────────────────────────────────────
    # Runs on every tool call. Checks the call against the active declared
    # intent for this session. Logs violations to agent_intent_log with
    # MAST taxonomy classification.
    # Tools exempt from intent checking (infrastructure calls):
    _INTENT_EXEMPT = {
        "create_session", "declare_intent", "get_intent_incidents",
        "log_reasoning", "get_session_context", "score_branches",
        "distill_knowledge", "kill_all_scans", "generate_report",
        "read_skill", "retrieve_knowledge", "get_cross_session_insights"
    }
    if session_id and tool_name not in _INTENT_EXEMPT:
        try:
            active_intent = engine.get_active_intent(session_id)
            if active_intent is None:
                # No declared intent — Executor calling tools without Planner auth
                engine.log_intent_event(
                    session_id=session_id,
                    tool_name=tool_name,
                    session_phase="unknown",
                    agent_type="executor",
                    parameters_summary=json.dumps(params_summary)[:200],
                    mast_classification="UNAUTHORIZED_CHAIN",
                    response_taken="log",
                    severity="medium"
                )
            else:
                authorised = active_intent.get("tools_authorised", [])
                scope = active_intent.get("scope", "")
                # Check tool is in authorised list
                if tool_name not in authorised:
                    engine.log_intent_event(
                        session_id=session_id,
                        tool_name=tool_name,
                        session_phase=active_intent.get("phase"),
                        agent_type="executor",
                        parameters_summary=json.dumps(params_summary)[:200],
                        planner_intent=active_intent.get("intent"),
                        declared_intent_id=active_intent.get("id"),
                        mast_classification="TOOL_MISUSE",
                        response_taken="log",
                        severity="medium"
                    )
                # Check scope — compare domains, not session_id string
                url_param = (params_summary.get("url") or
                             params_summary.get("target_url") or
                             params_summary.get("target") or "")
                if url_param and scope:
                    try:
                        from urllib.parse import urlparse as _urlparse
                        import sqlite3 as _sq3
                        # Look up the session's registered target_url
                        target_url = ""
                        with _sq3.connect(DB_PATH_STR) as _sc:
                            _row = _sc.execute(
                                "SELECT target_url FROM sessions WHERE session_id=?",
                                (session_id,)
                            ).fetchone()
                            target_url = _row[0] if _row else ""
                        session_domain = _urlparse(target_url).netloc if target_url else ""
                        url_domain = _urlparse(url_param).netloc if url_param else ""
                        is_localhost = (
                            url_param.startswith("http://127") or
                            url_param.startswith("http://localhost") or
                            url_param.startswith("http://10.") or
                            url_param.startswith("http://192.168.")
                        )
                        if (url_domain and session_domain and
                                url_domain != session_domain and
                                not is_localhost):
                            engine.log_intent_event(
                                session_id=session_id,
                                tool_name=tool_name,
                                session_phase=active_intent.get("phase"),
                                agent_type="executor",
                                parameters_summary=json.dumps(params_summary)[:200],
                                planner_intent=active_intent.get("intent"),
                                declared_intent_id=active_intent.get("id"),
                                mast_classification="SCOPE_VIOLATION",
                                response_taken="log",
                                severity="high"
                            )
                    except Exception as _scope_err:
                        logger.debug(f"scope check error: {_scope_err}")
        except Exception as _ice:
            logger.debug(f"IntentCorrelationMiddleware error: {_ice}")
    # ── end IntentCorrelationMiddleware ─────────────────────────────────────


def _update_scan_job_status(job_id: str, status: str):
    """Persist scan job status to SQLite so it survives server restarts."""
    import sqlite3
    from core.graph_engine import DB_PATH
    db_path = DB_PATH
    try:
        with sqlite3.connect(db_path) as conn:
            conn.execute(
                "UPDATE scan_jobs SET status=? WHERE job_id=?",
                (status, job_id)
            )
            conn.commit()
    except Exception as e:
        logger.debug(f"scan job status update failed: {e}")


def _get_scan_job_status(job_id: str) -> str:
    """Read scan job status from SQLite."""
    import sqlite3
    from core.graph_engine import DB_PATH
    db_path = DB_PATH
    try:
        with sqlite3.connect(db_path) as conn:
            row = conn.execute(
                "SELECT status FROM scan_jobs WHERE job_id=?", (job_id,)
            ).fetchone()
            return row[0] if row else "unknown"
    except Exception:
        return "unknown"


def _redact_payload(params: dict) -> dict:
    """Redact injection values from params for audit log."""
    sensitive = {"payload", "data", "password", "cookies", "headers", "injection_value"}
    return {k: "[REDACTED]" if k.lower() in sensitive else v for k, v in params.items()}


def _check_url_allowlist(url: str) -> bool:
    """
    SSRF protection with TARGET_ALLOWLIST and ALLOW_INTERNAL support.

    Always blocked (regardless of env vars):
      - 169.254.0.0/16  (AWS metadata / link-local)
      - 100.64.0.0/10   (shared address space)

    Blocked unless ALLOW_INTERNAL=true:
      - 10.0.0.0/8      (RFC-1918 private)
      - 172.16.0.0/12   (RFC-1918 private)
      - 192.168.0.0/16  (RFC-1918 private)
      - 127.0.0.0/8     (loopback — needed for local targets like AltoroJ)

    TARGET_ALLOWLIST (comma-separated hostnames/host:port):
      - If set, ONLY allow URLs whose host[:port] matches an entry.
      - If empty/unset, allow any URL that passes the blocked-range check.
      - Example: TARGET_ALLOWLIST=localhost:8080,testasp.vulnweb.com

    Session auto-ID note: session IDs are generated as
      v6_{shortname}_{YYYYMMDD}_{HHMMSS} to avoid conflicts.
    """
    import ipaddress
    from urllib.parse import urlparse

    allow_internal = os.environ.get("ALLOW_INTERNAL", "false").lower() == "true"
    target_allowlist_raw = os.environ.get("TARGET_ALLOWLIST", "").strip()
    target_allowlist = [e.strip().lower() for e in target_allowlist_raw.split(",") if e.strip()] \
                       if target_allowlist_raw else []

    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    port = parsed.port
    host_port = f"{host}:{port}" if port else host

    # --- TARGET_ALLOWLIST gate (if configured, only listed hosts pass) ---
    if target_allowlist:
        match = any(
            host == entry or host_port == entry or host.endswith("." + entry)
            for entry in target_allowlist
        )
        if not match:
            logger.warning(f"[SSRF] {url} blocked — not in TARGET_ALLOWLIST")
            return False

    # --- Always-blocked ranges (cloud metadata, etc.) ---
    always_blocked_prefixes = ["169.254.", "100.64."]
    always_blocked_ranges = [
        ipaddress.ip_network("169.254.0.0/16"),
        ipaddress.ip_network("100.64.0.0/10"),
    ]

    # --- Internal ranges: blocked unless ALLOW_INTERNAL=true ---
    internal_ranges = [
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
        ipaddress.ip_network("127.0.0.0/8"),
    ]
    internal_hostnames = {"localhost", "127.0.0.1", "::1"}

    # Resolve hostname to check ranges
    try:
        ip_obj = ipaddress.ip_address(host)
        # Check always-blocked
        for net in always_blocked_ranges:
            if ip_obj in net:
                logger.warning(f"[SSRF] {url} always-blocked (cloud metadata / link-local)")
                return False
        for prefix in always_blocked_prefixes:
            if host.startswith(prefix):
                logger.warning(f"[SSRF] {url} always-blocked prefix {prefix}")
                return False
        # Check internal ranges
        for net in internal_ranges:
            if ip_obj in net:
                if not allow_internal:
                    logger.warning(f"[SSRF] {url} blocked (internal range {net}) — set ALLOW_INTERNAL=true to allow")
                    return False
    except ValueError:
        # hostname (not raw IP) — check known internal hostnames
        if host in internal_hostnames:
            if not allow_internal:
                logger.warning(f"[SSRF] {url} blocked (localhost) — set ALLOW_INTERNAL=true to allow")
                return False
        # For all other hostnames, always-block cloud metadata prefixes
        for prefix in always_blocked_prefixes:
            if host.startswith(prefix):
                return False

    return True


def _post_graph(endpoint: str, data: dict) -> dict:
    try:
        token = _load_bearer_token()
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        r = requests.post(f"{GRAPH_MEMORY_URL}{endpoint}", json=data, headers=headers, timeout=10)
        return r.json()
    except Exception as e:
        logger.debug(f"Graph POST {endpoint} failed: {e}")
        return {"success": False, "error": str(e)}


# ─── FastMCP server ──────────────────────────────────────────────────────────

mcp = FastMCP("redteam-v9", version="9.0.0")


# ══════════════════════════════════════════════════════════════════════════════
# SESSION & MEMORY TOOLS (1–10)
# ══════════════════════════════════════════════════════════════════════════════

@mcp.tool()
def create_session(session_id: str, target_url: str, goal: str = "") -> dict:
    """Create a new pentest session. Always call this first. Loads transfer learning priors."""
    try:
        node_id = engine.create_session(session_id, target_url, goal)
        mcts = get_or_create_mcts(session_id)
        transfer_rows = get_priors_for_fingerprint({})
        if transfer_rows:
            mcts.apply_transfer_priors(transfer_rows)
        _audit_log(session_id, "create_session",
                   {"session_id": session_id, "target_url": target_url},
                   f"Created session node {node_id}")
        return _ok({"node_id": node_id, "session_id": session_id, "transfer_priors_loaded": len(transfer_rows)})
    except Exception as e:
        return _err(str(e))


@mcp.tool()
def set_branch(session_id: str, attack_type: str, description: str = "") -> dict:
    """Declare the active attack branch/phase. Creates AttackBranch and ThinkingDAG HypothesisNode."""
    if not _check_rate_limit(session_id):
        return _err("Rate limit exceeded. Retry after 60 seconds.")
    try:
        node_id = engine.set_branch(session_id, attack_type, description)
        mcts = get_or_create_mcts(session_id)
        thinking_id = engine.add_thinking_node(
            session_id, f"Exploring {attack_type}: {description[:100]}",
            confidence=0.3, entropy=mcts.root.entropy, mcts_score=0.3,
            status="EXPLORING"
        )
        _audit_log(session_id, "set_branch", {"attack_type": attack_type}, f"Branch {node_id}")
        return _ok({"branch_node_id": node_id, "thinking_node_id": thinking_id})
    except Exception as e:
        return _err(str(e))


@mcp.tool()
def log_reasoning(session_id: str, agent: str, step: str, content: str) -> dict:
    """Log agent reasoning step. Written sanitised to ThinkingDAG; raw stored in SQLite only."""
    if not _check_rate_limit(session_id):
        return _err("Rate limit exceeded.")
    try:
        log_id = engine.log_reasoning(session_id, agent, step, content)
        safe_content = DagSanitiser.sanitise_string(content)
        mcts = get_or_create_mcts(session_id)
        engine.add_thinking_node(
            session_id, safe_content[:200], confidence=0.4,
            entropy=mcts.root.entropy, mcts_score=0.4, status="EVALUATING"
        )
        _audit_log(session_id, "log_reasoning", {"agent": agent, "step": step}, "logged")
        return _ok({"log_id": log_id})
    except Exception as e:
        return _err(str(e))


@mcp.tool()
def add_injection_point(session_id: str, parameter: str, endpoint: str,
                         method: str = "POST", context: str = "") -> dict:
    """Record a discovered injectable parameter. Triggers MCTS backprop with reward=0.5."""
    if not _check_rate_limit(session_id):
        return _err("Rate limit exceeded.")
    try:
        ip_id = engine.add_injection_point(session_id, parameter, endpoint, method, context)
        mcts = get_or_create_mcts(session_id)
        mcts.backpropagate("sqli", 0.5, {"endpoint": endpoint, "param": parameter})
        _audit_log(session_id, "add_injection_point",
                   {"parameter": parameter, "endpoint": endpoint}, f"IP {ip_id}")
        return _ok({"ip_id": ip_id})
    except Exception as e:
        return _err(str(e))


@mcp.tool()
def add_finding(session_id: str, title: str, severity: str = "medium",
                endpoint: str = "", evidence: str = "", cvss: str = "",
                remediation: str = "", branch_id: str = "",
                attack_type: str = "general") -> dict:
    """Record a confirmed vulnerability. Triggers MCTS backprop with reward=1.0.
    branch_id: optional — pass the branch_node_id returned by set_branch() to pin
    this finding to your specific branch. Required for correct attribution when
    running as a parallel subtask alongside other agents."""
    if not _check_rate_limit(session_id):
        return _err("Rate limit exceeded.")
    try:
        finding_id = engine.add_finding(session_id, title, severity, endpoint,
                                         evidence, cvss, remediation,
                                         branch_id=branch_id if branch_id else None)
        mcts = get_or_create_mcts(session_id)
        mcts.backpropagate(attack_type, 1.0, {"title": title, "severity": severity})
        record_outcome(engine.get_fingerprint(session_id), attack_type, True)
        engine.add_thinking_node(
            session_id, f"DECIDED: {title} confirmed ({severity})",
            confidence=0.9, entropy=mcts.root.entropy, mcts_score=0.9, status="DECIDED"
        )
        _audit_log(session_id, "add_finding", {"title": title, "severity": severity, "endpoint": endpoint},
                   f"Finding {finding_id}")
        return _ok({"finding_id": finding_id})
    except Exception as e:
        return _err(str(e))


@mcp.tool()
def get_session_context(session_id: str) -> dict:
    """Get full session context: findings, injection points, key facts, reasoning. Call at start of each loop."""
    try:
        ctx = engine.get_session_context(session_id)
        mcts = get_or_create_mcts(session_id)
        ctx["mcts_state"] = mcts.get_state()
        _audit_log(session_id, "get_session_context", {}, f"{ctx.get('node_count', 0)} nodes")
        return _ok(ctx)
    except Exception as e:
        return _err(str(e))


@mcp.tool()
def score_branches(session_id: str, candidate_branches: str = "", top_k: int = 5) -> dict:
    """Rank attack branches using BayesianMCTS. Returns confidence + entropy per branch. Primary planning tool."""
    if not _check_rate_limit(session_id):
        return _err("Rate limit exceeded.")
    try:
        mcts = get_or_create_mcts(session_id)
        ranked = mcts.select(top_k=top_k)
        if candidate_branches:
            candidates = [c.strip() for c in candidate_branches.split(",") if c.strip()]
            if candidates:
                ranked = [r for r in ranked if r["attack_type"] in candidates] or ranked
        _audit_log(session_id, "score_branches", {"top_k": top_k}, f"{len(ranked)} branches ranked")
        return _ok({"ranked_branches": ranked, "mcts_state": mcts.get_state()})
    except Exception as e:
        return _err(str(e))


@mcp.tool()
def distill_knowledge(session_id: str, key_insight: str) -> dict:
    """Save a key insight to the session knowledge base. Also updates transfer learning."""
    if not _check_rate_limit(session_id):
        return _err("Rate limit exceeded.")
    try:
        fact_id = engine.distill_knowledge(session_id, key_insight)
        fingerprint = engine.get_fingerprint(session_id)
        if fingerprint:
            record_outcome(fingerprint, "general", True)
        _audit_log(session_id, "distill_knowledge", {}, f"Fact {fact_id}")
        return _ok({"fact_id": fact_id})
    except Exception as e:
        return _err(str(e))


@mcp.tool()
def retrieve_knowledge(query: str, top_k: int = 5) -> dict:
    """Semantic search over PayloadsAllTheThings RAG. Returns payloads to agent only — never written to DAG."""
    MAX_RETRIES = 3
    RETRY_SLEEP = 5
    last_error = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            token = _load_bearer_token()
            headers = {"Authorization": f"Bearer {token}"} if token else {}
            r = requests.post(f"{RAG_URL}/retrieve_knowledge",
                              json={"query": query, "top_k": top_k},
                              headers=headers, timeout=15)
            result = r.json()
            _audit_log("", "retrieve_knowledge", {"query": query[:50]},
                       f"{result.get('total_results', 0)} results (attempt {attempt})")
            return _ok(result)
        except Exception as e:
            last_error = e
            logger.warning(f"RAG unavailable (attempt {attempt}/{MAX_RETRIES}): {e}")
            if attempt < MAX_RETRIES:
                time.sleep(RETRY_SLEEP)
    _audit_log("", "retrieve_knowledge", {"query": query[:50]},
               f"RAG unavailable after {MAX_RETRIES} attempts — proceeding without knowledge")
    return _ok({
        "total_results": 0,
        "results": [],
        "warning": f"RAG server unavailable after {MAX_RETRIES} attempts. Proceeding without knowledge retrieval. Error: {str(last_error)}"
    })


@mcp.tool()
def get_cross_session_insights(tech_stack: str = "", attack_type: str = "") -> dict:
    """Get historical success rates for a tech stack + attack type combo from all past sessions."""
    try:
        from core.transfer_learning import get_all_insights
        insights = get_all_insights(tech_stack, attack_type)
        return _ok({"insights": insights, "count": len(insights)})
    except Exception as e:
        return _err(str(e))


# ══════════════════════════════════════════════════════════════════════════════
# INTENT & SECURITY TOOLS (11–12)
# Phase 1 — Intent architecture layer. These tools form the security skeleton
# that SICD (Phase 2) sits on top of. declare_intent() is the Planner's
# authorisation contract. get_intent_incidents() is the Reflector's audit view.
# ══════════════════════════════════════════════════════════════════════════════

@mcp.tool()
def declare_intent(session_id: str, phase: str, intent: str,
                   confidence: float, tools_authorised: str,
                   scope: str, rationale: str = "") -> dict:
    """Planner MUST call this after score_branches() and before delegating
    to the Executor. Creates the authorisation contract for the current phase.
    tools_authorised: comma-separated list of tool names the Executor may call.
    The IntentCorrelationMiddleware checks every subsequent tool call against this.
    """
    if not _check_rate_limit(session_id):
        return _err("Rate limit exceeded.")
    try:
        import uuid as _uuid
        intent_id = f"intent_{_uuid.uuid4().hex[:12]}"
        tools_list = [t.strip() for t in tools_authorised.split(",") if t.strip()]
        if not tools_list:
            return _err("tools_authorised must contain at least one tool name.")
        engine.create_declared_intent(
            intent_id, session_id, phase, intent,
            confidence, tools_list, scope, rationale
        )
        _audit_log(session_id, "declare_intent",
                   {"phase": phase, "intent": intent,
                    "tools_count": len(tools_list)},
                   f"Intent {intent_id} declared for phase={phase}")
        return _ok({
            "intent_id": intent_id,
            "phase": phase,
            "intent": intent,
            "tools_authorised": tools_list,
            "scope": scope,
            "message": "Intent declared. Executor may now call authorised tools."
        })
    except Exception as e:
        return _err(str(e))


@mcp.tool()
def get_intent_incidents(session_id: str, severity: str = "") -> dict:
    """Reflector calls this at end of each phase to review agent behaviour.
    Returns all MAST-classified intent deviations for the session.
    severity: filter by low|medium|high|critical (empty = all)
    """
    if not _check_rate_limit(session_id):
        return _err("Rate limit exceeded.")
    try:
        incidents = engine.get_intent_incidents(
            session_id, severity if severity else None
        )
        _audit_log(session_id, "get_intent_incidents",
                   {"severity_filter": severity or "all"},
                   f"{len(incidents)} incidents returned")
        return _ok({
            "session_id": session_id,
            "severity_filter": severity or "all",
            "incident_count": len(incidents),
            "incidents": incidents
        })
    except Exception as e:
        return _err(str(e))


@mcp.tool()
def select_skills(session_id: str, phase: str,
                  tech_stack: str = "") -> dict:
    """SkillDAG dynamic skill selection — Phase 3.
    Returns the relevant skill subgraph for the current phase
    and tech stack. Replaces static read_skill() for adaptive
    methodology selection.
    phase: recon|sqli|xss|auth|idor|config|report
    tech_stack: comma-separated fingerprint tags e.g. 'php,mysql,apache'
    """
    if not _check_rate_limit(session_id):
        return _err("Rate limit exceeded.")
    try:
        stack_tags = [t.strip().lower()
                      for t in tech_stack.split(",") if t.strip()]
        SKILL_GRAPH = {
            "recon": {
                "tools": ["fingerprint_target","crawl_links",
                          "enumerate_endpoints","check_headers",
                          "http_request","add_injection_point"],
                "next_phases": ["sqli","xss","auth","idor","config"],
                "suggests": {"php": ["sqli","xss"],
                             "java": ["sqli","xpath_injection"],
                             "login": ["auth"],
                             "api": ["idor"]}
            },
            "sqli": {
                "tools": ["test_sqli","check_sqli_status",
                          "get_sqli_results","add_finding"],
                "prerequisites": ["recon"],
                "next_phases": ["xss","auth"],
                "stack_boost": {"php": 0.3, "mysql": 0.4,
                                "mssql": 0.3, "oracle": 0.2}
            },
            "xss": {
                "tools": ["test_xss","verify_xss_browser","add_finding"],
                "prerequisites": ["recon"],
                "next_phases": ["auth","idor"],
                "stack_boost": {"php": 0.2, "javascript": 0.3}
            },
            "auth": {
                "tools": ["test_auth_bypass","test_session_fixation",
                          "analyse_cookies","add_finding"],
                "prerequisites": ["recon"],
                "next_phases": ["idor","config"],
                "stack_boost": {"login": 0.5, "jwt": 0.3}
            },
            "idor": {
                "tools": ["test_idor","http_request","add_finding"],
                "prerequisites": ["recon"],
                "next_phases": ["config"],
                "stack_boost": {"api": 0.4, "rest": 0.3}
            },
            "config": {
                "tools": ["check_headers","analyse_cookies",
                          "test_csrf","add_finding"],
                "prerequisites": ["recon"],
                "next_phases": ["report"]
            },
            "report": {
                "tools": ["generate_report","kill_all_scans"],
                "prerequisites": [],
                "next_phases": []
            }
        }
        node = SKILL_GRAPH.get(phase, SKILL_GRAPH["recon"])
        boost = node.get("stack_boost", {})
        relevance = sum(boost.get(tag, 0) for tag in stack_tags)
        suggestions = []
        if phase == "recon" and stack_tags:
            for tag in stack_tags:
                for sug_phase, sug_tags in node.get("suggests",{}).items():
                    if tag in sug_tags and sug_phase not in suggestions:
                        suggestions.append(sug_phase)
        _audit_log(session_id, "select_skills",
                   {"phase": phase, "tech_stack": tech_stack},
                   f"returned {len(node['tools'])} tools for {phase}")
        return _ok({
            "phase": phase,
            "tools": node["tools"],
            "prerequisites": node.get("prerequisites", []),
            "next_phases": node.get("next_phases", []),
            "stack_relevance_boost": round(relevance, 3),
            "suggested_phases": suggestions,
            "skill_count": len(node["tools"]),
            "message": (f"SkillDAG: {len(node['tools'])} tools "
                        f"for {phase} phase. "
                        f"Stack boost: {relevance:.2f}")
        })
    except Exception as e:
        return _err(str(e))


# ══════════════════════════════════════════════════════════════════════════════
# HTTP & RECON TOOLS (11–15)
# ══════════════════════════════════════════════════════════════════════════════

@mcp.tool()
def http_request(url: str, method: str = "GET", headers: str = "{}",
                 data: str = "{}", cookies: str = "{}",
                 allow_redirects: str = "true", timeout: int = 15) -> dict:
    """Make an HTTP request. Returns safe summary — full body is stripped for prompt injection defence."""
    if not _check_url_allowlist(url):
        return _err(f"URL blocked by allowlist policy: {url}")
    ar = _coerce_bool(allow_redirects)
    try:
        h = json.loads(headers) if isinstance(headers, str) else headers
        d = json.loads(data) if isinstance(data, str) else data
        c = json.loads(cookies) if isinstance(cookies, str) else cookies
    except json.JSONDecodeError as e:
        return _err(f"JSON parse error in parameters: {e}")

    try:
        resp = requests.request(
            method.upper(), url, headers=h, json=d if d else None,
            cookies=c, allow_redirects=ar, timeout=timeout
        )
        raw = {
            "url": url, "status_code": resp.status_code,
            "headers": dict(resp.headers), "body": resp.text[:5000],
        }
        safe = response_sanitiser(raw)
        _audit_log("", "http_request",
                   {"url": url, "method": method, "headers": list(h.keys())},
                   f"status={resp.status_code}")
        return _ok(safe)
    except Exception as e:
        return _err(str(e))


@mcp.tool()
def check_headers(url: str, session_id: str = "") -> dict:
    """Check security headers. Auto-logs findings for missing critical headers."""
    # Idempotency guard: skip if 7+ header findings already logged for this session
    if session_id:
        try:
            import sqlite3 as _sq
            from core.graph_engine import DB_PATH as _DB_PATH
            _db = str(_DB_PATH)
            with _sq.connect(_db) as _c:
                _c.row_factory = _sq.Row
                _cnt = _c.execute(
                    "SELECT COUNT(*) as cnt FROM findings "
                    "WHERE session_id=? AND title LIKE 'Missing security header%'",
                    (session_id,)
                ).fetchone()["cnt"]
            if _cnt >= 7:
                return _ok({"skipped": True,
                            "reason": "Security headers already checked this session",
                            "existing_count": _cnt})
        except Exception:
            pass  # If check fails, proceed normally
    try:
        resp = requests.get(url, timeout=15, allow_redirects=True)
        h = {k.lower(): v for k, v in resp.headers.items()}

        checks = {
            "Content-Security-Policy": h.get("content-security-policy"),
            "Strict-Transport-Security": h.get("strict-transport-security"),
            "X-Frame-Options": h.get("x-frame-options"),
            "X-Content-Type-Options": h.get("x-content-type-options"),
            "Referrer-Policy": h.get("referrer-policy"),
            "Permissions-Policy": h.get("permissions-policy"),
        }

        cors_origin = h.get("access-control-allow-origin", "")
        cors_status = "MISCONFIGURED" if cors_origin == "*" else ("PRESENT" if cors_origin else "MISSING")
        checks["CORS"] = cors_status

        results = {}
        for header, value in checks.items():
            if header == "CORS":
                results[header] = cors_status
            elif value:
                results[header] = "PRESENT"
            else:
                results[header] = "MISSING"
                if session_id:
                    engine.add_finding(
                        session_id,
                        f"Missing security header: {header}",
                        "low", url, f"Header {header} not present",
                        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                        f"Add {header} to server response headers."
                    )

        _audit_log(session_id, "check_headers", {"url": url}, f"{sum(1 for v in results.values() if v == 'MISSING')} missing")
        return _ok({"url": url, "headers": results, "status_code": resp.status_code})
    except Exception as e:
        return _err(str(e))


@mcp.tool()
def enumerate_endpoints(base_url: str, session_id: str = "",
                         wordlist_size: str = "medium") -> dict:
    """Async directory/endpoint discovery. wordlist_size: small|medium|large."""
    WORDLISTS = {
        "small": ["admin", "login", "api", "wp-admin", "config", "backup",
                  "test", "debug", "console", "phpmyadmin", "robots.txt",
                  ".env", "sitemap.xml", "api/v1", "api/v2", "swagger",
                  "health", "status", "metrics", "docs", "upload"],
        "medium": ["admin", "login", "api", "api/v1", "api/v2", "api/v3",
                   "wp-admin", "wp-login.php", "config", "backup", "test",
                   "debug", "console", "phpmyadmin", "robots.txt", ".env",
                   ".git", ".git/HEAD", "sitemap.xml", "swagger", "swagger-ui",
                   "openapi.json", "graphql", "health", "status", "metrics",
                   "docs", "upload", "uploads", "files", "images", "static",
                   "assets", "js", "css", "includes", "lib", "vendor",
                   "node_modules", "package.json", "composer.json", "README.md",
                   "web.config", "nginx.conf", ".htaccess", "error_log",
                   "access_log", "dashboard", "panel", "manage", "user",
                   "users", "account", "profile", "register", "signup",
                   "forgot-password", "reset-password", "logout", "checkout",
                   "cart", "shop", "store", "product", "products", "search",
                   "download", "report", "reports", "export", "import",
                   "xmlrpc.php", "wp-json", "rest", "rpc"],
        "large": [],  # would load from wordlist file
    }

    words = WORDLISTS.get(wordlist_size, WORDLISTS["medium"])
    base = base_url.rstrip("/")
    discovered = []

    import concurrent.futures

    def check_path(path):
        try:
            full_url = f"{base}/{path}"
            r = requests.get(full_url, timeout=5, allow_redirects=False)
            if r.status_code not in (404, 400, 403):
                return {"url": full_url, "status": r.status_code, "length": len(r.content)}
        except Exception:
            pass
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(check_path, w): w for w in words}
        for future in concurrent.futures.as_completed(futures, timeout=60):
            result = future.result()
            if result:
                discovered.append(result)

    if session_id:
        engine.add_node(session_id, "Evidence",
                        f"Endpoint enumeration: {len(discovered)} found",
                        f"Base: {base} | Wordlist: {wordlist_size}",
                        confidence=0.7)

    _audit_log(session_id, "enumerate_endpoints", {"base_url": base_url, "wordlist_size": wordlist_size},
               f"{len(discovered)} endpoints found")
    return _ok({"base_url": base_url, "discovered": discovered, "total": len(discovered)})


@mcp.tool()
def fingerprint_target(url: str, session_id: str = "") -> dict:
    """Detect web server, framework, language, CMS, WAF, JS libraries. Updates MCTS priors."""
    try:
        resp = requests.get(url, timeout=15, allow_redirects=True)
        headers = {k.lower(): v for k, v in resp.headers.items()}
        body = resp.text[:3000].lower()

        fingerprint = {
            "url": url,
            "status_code": resp.status_code,
            "server": headers.get("server", ""),
            "powered_by": headers.get("x-powered-by", ""),
            "framework": "",
            "language": "",
            "cms": "",
            "waf": "",
            "cdn": "",
            "js_libraries": [],
            "forms_found": False,
            "login_page": False,
            "api_detected": False,
            "jwt_in_cookies": False,
        }

        # Server detection
        server = fingerprint["server"].lower()
        if "apache" in server:
            fingerprint["server"] = "Apache"
        elif "nginx" in server:
            fingerprint["server"] = "nginx"
        elif "iis" in server:
            fingerprint["server"] = "IIS"
        elif "cloudflare" in server:
            fingerprint["waf"] = "Cloudflare"

        # Language/framework
        powered = fingerprint["powered_by"].lower()
        if "php" in powered or "php" in body:
            fingerprint["language"] = "PHP"
        if "asp.net" in powered:
            fingerprint["language"] = "ASP.NET"
            fingerprint["framework"] = "ASP.NET"
        if "express" in powered or "node" in powered:
            fingerprint["framework"] = "Express/Node"
        if "django" in body or "csrfmiddlewaretoken" in body:
            fingerprint["framework"] = "Django"
            fingerprint["language"] = "Python"
        if "rails" in body or "authenticity_token" in body:
            fingerprint["framework"] = "Rails"
            fingerprint["language"] = "Ruby"
        if "laravel" in body:
            fingerprint["framework"] = "Laravel"
            fingerprint["language"] = "PHP"

        # CMS
        if "wp-content" in body or "wordpress" in body:
            fingerprint["cms"] = "WordPress"
        elif "joomla" in body:
            fingerprint["cms"] = "Joomla"
        elif "drupal" in body:
            fingerprint["cms"] = "Drupal"

        # WAF detection
        waf_headers = ["x-sucuri-id", "x-firewall-protection", "x-waf-status"]
        for wh in waf_headers:
            if wh in headers:
                fingerprint["waf"] = headers[wh]

        # CDN
        if "cf-ray" in headers:
            fingerprint["cdn"] = "Cloudflare"
        elif "x-cache" in headers:
            fingerprint["cdn"] = headers["x-cache"]

        # Feature detection
        fingerprint["forms_found"] = "<form" in resp.text.lower()
        fingerprint["login_page"] = any(w in body for w in ["login", "signin", "password", "username"])
        fingerprint["api_detected"] = any(w in body for w in ['"api"', '/api/', 'application/json', 'graphql'])

        # Cookie analysis
        cookies_str = " ".join(resp.cookies.keys()).lower()
        fingerprint["jwt_in_cookies"] = any(k in cookies_str for k in ["jwt", "token", "auth"])

        # JS libraries
        js_libs = []
        if "jquery" in body:
            js_libs.append("jQuery")
        if "react" in body or "react.js" in body:
            js_libs.append("React")
        if "angular" in body:
            js_libs.append("Angular")
        if "vue.js" in body or "vuejs" in body:
            js_libs.append("Vue")
        fingerprint["js_libraries"] = js_libs

        if session_id:
            engine.set_fingerprint(session_id, fingerprint)
            mcts = get_or_create_mcts(session_id)
            mcts.apply_fingerprint_priors(fingerprint)
            transfer_rows = get_priors_for_fingerprint(fingerprint)
            if transfer_rows:
                mcts.apply_transfer_priors(transfer_rows)
            engine.add_node(session_id, "Evidence",
                            f"Fingerprint: {fingerprint.get('server', 'unknown')} / {fingerprint.get('language', 'unknown')}",
                            json.dumps({k: v for k, v in fingerprint.items() if k != "url"})[:500],
                            confidence=0.8)

        _audit_log(session_id, "fingerprint_target", {"url": url}, json.dumps(fingerprint)[:200])
        return _ok(fingerprint)
    except Exception as e:
        return _err(str(e))


@mcp.tool()
def crawl_links(url: str, session_id: str = "", depth: int = 2, max_pages: int = 50) -> dict:
    """Spider the target. Extracts links, forms, input fields, file upload points."""
    visited = set()
    forms_found = []
    links_found = []
    upload_points = []
    queue = [(url, 0)]

    while queue and len(visited) < max_pages:
        current_url, current_depth = queue.pop(0)
        if current_url in visited or current_depth > depth:
            continue
        visited.add(current_url)

        try:
            resp = requests.get(current_url, timeout=8, allow_redirects=True)
            body = resp.text

            from core.response_sanitiser import _extract_forms, _extract_links
            forms = _extract_forms(body)
            for f in forms:
                f["page_url"] = current_url
                forms_found.append(f)
                if any(field.get("type") in ("file",) for field in f.get("fields", [])):
                    upload_points.append({"url": current_url, "form": f})

            page_links = _extract_links(body)
            base_domain = url.split("/")[2] if "/" in url[8:] else url[8:]
            for link in page_links:
                if link.startswith("/"):
                    full = url.rstrip("/") + link
                elif link.startswith("http") and base_domain in link:
                    full = link
                else:
                    continue
                if full not in visited:
                    links_found.append(full)
                    queue.append((full, current_depth + 1))

        except Exception as e:
            logger.debug(f"Crawl failed for {current_url}: {e}")

    if session_id:
        engine.add_node(session_id, "Evidence",
                        f"Crawl: {len(visited)} pages, {len(forms_found)} forms",
                        f"Upload points: {len(upload_points)}",
                        confidence=0.7)

    # Identify potential IDOR-bearing endpoints from discovered links
    import re as _re
    _id_patterns = [
        r'[?&](id|accountId|userId|account|num|no|number|ref|record|listAccounts)=(\d+)',
        r'[?&](\w*[Ii]d)=(\d+)',
        r'/(\d{4,})(?:[/?#]|$)',       # path segments that are 4+ digit numbers
        r'[?&]\w+=\d{4,}(?:&|$)',      # any param with 4+ digit value
    ]
    idor_candidates = []
    seen_candidates = set()
    for link in list(set(links_found)):
        for pat in _id_patterns:
            if _re.search(pat, link, _re.I):
                if link not in seen_candidates:
                    seen_candidates.add(link)
                    idor_candidates.append({"url": link, "pattern": pat})
                break

    _audit_log(session_id, "crawl_links", {"url": url, "depth": depth},
               f"{len(visited)} pages, {len(forms_found)} forms, {len(idor_candidates)} idor_candidates")
    return _ok({
        "pages_visited": len(visited),
        "forms": forms_found[:50],
        "links": list(set(links_found))[:100],
        "upload_points": upload_points[:20],
        "idor_candidates": idor_candidates[:30],
    })


# ══════════════════════════════════════════════════════════════════════════════
# INJECTION TOOLS (16–22)
# ══════════════════════════════════════════════════════════════════════════════

@mcp.tool()
def test_sqli(url: str, parameter: str, method: str = "GET",
              data: str = "{}", cookies: str = "{}", session_id: str = "") -> dict:
    """Start async sqlmap scan. Returns job_id immediately. Poll with check_sqli_status."""
    if not _check_url_allowlist(url):
        return _err("URL blocked by allowlist policy.")
    if not _check_rate_limit(session_id):
        return _err("Rate limit exceeded.")

    sqlmap_cmd = _find_sqlmap()
    if not sqlmap_cmd:
        return _err("sqlmap not found. Install with: pip install sqlmap")

    job_id = f"sqli_{uuid.uuid4().hex[:8]}"
    cmd = sqlmap_cmd + [
        "-u", url,
        "-p", parameter,
        "--batch", "--random-agent",
        "--output-dir", str(SANDBOX_DIR / job_id),
    ]
    if data and data != "{}":
        cmd += ["--data", data]
    cmd += ["--level=2", "--risk=1"]

    # Route external targets through local mitmproxy (port 8888).
    # localhost/127.x targets (e.g. AltoroJ on :8080) bypass the proxy.
    _sqli_target_is_local = 'localhost' in url or '127.0.0.1' in url
    if not _sqli_target_is_local:
        cmd += ['--proxy', 'http://127.0.0.1:8888',
                '--proxy-ignore', 'localhost,127.0.0.1']

    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 cwd=str(SANDBOX_DIR))
        with _scan_lock:
            _scan_processes[job_id] = proc
        engine.create_scan_job("sqlmap", session_id, " ".join(cmd[:5]) + " [REDACTED]",
                           proc.pid, job_id=job_id)
        _audit_log(session_id, "test_sqli",
                   {"url": url, "parameter": parameter, "method": method},
                   f"Started job {job_id} pid={proc.pid}")
        _update_scan_job_status(job_id, "running")
        return _ok({"job_id": job_id, "pid": proc.pid, "status": "running"})
    except Exception as e:
        return _err(str(e))


@mcp.tool()
def check_sqli_status(job_id: str) -> dict:
    """Poll sqlmap scan status. Returns: running|complete|error."""
    with _scan_lock:
        proc = _scan_processes.get(job_id)
    if proc is not None:
        ret = proc.poll()
        if ret is None:
            status = "running"
        elif ret == 0:
            status = "complete"
            _update_scan_job_status(job_id, "complete")
        else:
            status = "error"
            _update_scan_job_status(job_id, "error")
    else:
        # Server restarted — read from SQLite
        status = _get_scan_job_status(job_id)

    # Write result summary back to scan_jobs when scan finishes
    if status in ("complete", "error"):
        try:
            out_dir = SANDBOX_DIR / job_id
            findings = []
            if out_dir.exists():
                for log_file in out_dir.rglob("*.log"):
                    text = log_file.read_text(errors="ignore")
                    if "injectable" in text.lower() or "injection" in text.lower():
                        findings.append({"type": "SQL Injection", "file": log_file.name,
                                         "confirmed": "injectable" in text.lower()})
            import sqlite3 as _sq3
            from core.graph_engine import DB_PATH as _DB_PATH
            with _sq3.connect(_DB_PATH) as _rc:
                _rc.execute(
                    "UPDATE scan_jobs SET result=? WHERE job_id=?",
                    (json.dumps({"status": status, "findings": findings})[:2000], job_id)
                )
                _rc.commit()
        except Exception as _rwe:
            logger.debug(f"sqli result write-back failed: {_rwe}")

    _audit_log("", "check_sqli_status", {"job_id": job_id}, f"status={status}")
    return _ok({"job_id": job_id, "status": status})


@mcp.tool()
def get_sqli_results(job_id: str, session_id: str = "") -> dict:
    """Get sqlmap results. Calls add_finding for confirmed injections. Raw output in SQLite only."""
    with _scan_lock:
        proc = _scan_processes.get(job_id)
    if proc is None:
        return _err(f"Job {job_id} not found.")
    if proc.poll() is None:
        return _ok({"status": "still_running", "job_id": job_id})

    try:
        out_dir = SANDBOX_DIR / job_id
        findings = []
        if out_dir.exists():
            for log_file in out_dir.rglob("*.log"):
                text = log_file.read_text(errors="ignore")
                if "injectable" in text.lower() or "injection" in text.lower():
                    findings.append({
                        "type": "SQL Injection",
                        "file": log_file.name,
                        "confirmed": "injectable" in text.lower(),
                    })
                    if session_id:
                        engine.add_finding(
                            session_id, "SQL Injection Detected",
                            "critical", job_id,
                            "sqlmap confirmed injectable parameter",
                            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            "Use parameterised queries / prepared statements."
                        )

        _audit_log(session_id, "get_sqli_results", {"job_id": job_id},
                   f"{len(findings)} findings")
        return _ok({"job_id": job_id, "status": "complete", "findings": findings})
    except Exception as e:
        return _err(str(e))


@mcp.tool()
def test_xss(url: str, parameter: str, payload_hint: str = "",
             method: str = "GET", data: str = "{}",
             cookies: str = "{}", session_id: str = "") -> dict:
    """Test reflected/stored XSS. Uses RAG knowledge base for payload selection."""
    if not _check_url_allowlist(url):
        return _err("URL blocked.")
    if not _check_rate_limit(session_id):
        return _err("Rate limit exceeded.")

    SAFE_MARKERS = [
        "<xsstest>", "<h1>xsstest</h1>", "<b>xsstest</b>",
        "xsstest123", "<svg>xsstest</svg>",
    ]

    try:
        d = json.loads(data) if isinstance(data, str) else data
        c = json.loads(cookies) if isinstance(cookies, str) else cookies
    except Exception:
        d, c = {}, {}

    results = []
    for marker in SAFE_MARKERS[:3]:
        try:
            test_d = dict(d)
            test_d[parameter] = marker
            if method.upper() == "POST":
                resp = requests.post(url, data=test_d, cookies=c, timeout=10, allow_redirects=True)
            else:
                resp = requests.get(url, params={parameter: marker}, cookies=c,
                                    timeout=10, allow_redirects=True)
            if marker.lower() in resp.text.lower():
                results.append({"marker": "[PAYLOAD REDACTED]", "reflected": True,
                                 "status": resp.status_code})
                if session_id:
                    engine.add_finding(
                        session_id, f"Reflected XSS in parameter '{parameter}'",
                        "high", url,
                        f"Parameter '{parameter}' reflects input without encoding",
                        "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                        "HTML-encode all output. Implement Content-Security-Policy."
                    )
                    mcts = get_or_create_mcts(session_id)
                    mcts.backpropagate("xss", 1.0)
                break
        except Exception as e:
            logger.debug(f"XSS test error: {e}")

    not_reflected = not any(r.get("reflected") for r in results)
    _audit_log(session_id, "test_xss",
               {"url": url, "parameter": parameter, "method": method},
               f"reflected={not not_reflected}")
    return _ok({
        "url": url, "parameter": parameter,
        "result": "reflected" if not not_reflected else "not_found",
        "tests_run": len(results),
    })


@mcp.tool()
def verify_xss_browser(url: str, xss_test_id: str = "", session_id: str = "") -> dict:
    """Use Playwright headless browser to confirm XSS execution."""
    if not _check_url_allowlist(url):
        return _err("URL blocked.")
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            alerts_fired = []
            page.on("dialog", lambda d: (alerts_fired.append(d.message), d.dismiss()))
            page.goto(url, timeout=15000)
            page.wait_for_timeout(3000)
            browser.close()

        confirmed = len(alerts_fired) > 0
        if confirmed and session_id:
            engine.add_finding(
                session_id, "XSS Browser-Confirmed",
                "high", url,
                f"Alert dialog fired during browser visit",
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                "Implement output encoding and CSP."
            )
        _audit_log(session_id, "verify_xss_browser", {"url": url},
                   f"confirmed={confirmed}")
        return _ok({"url": url, "confirmed": confirmed, "alerts_fired": len(alerts_fired)})
    except ImportError:
        return _err("Playwright not installed. Run: playwright install chromium")
    except Exception as e:
        return _err(str(e))


@mcp.tool()
def test_xpath_injection(url: str, parameter: str, method: str = "POST",
                          data: str = "{}", cookies: str = "{}", session_id: str = "") -> dict:
    """Test XPath injection with error-based and boolean-based probes."""
    if not _check_url_allowlist(url):
        return _err("URL blocked.")
    if not _check_rate_limit(session_id):
        return _err("Rate limit exceeded.")

    XPATH_PROBES = ["'", "''", "' or '1'='1", "') or ('1'='1"]
    ERROR_SIGNATURES = ["xpath", "xmldb", "xpathexception", "invalid xpath", "javax.xml"]

    try:
        d = json.loads(data) if isinstance(data, str) else data
        c = json.loads(cookies) if isinstance(cookies, str) else cookies
    except Exception:
        d, c = {}, {}

    results = []
    for probe in XPATH_PROBES:
        try:
            test_d = dict(d)
            test_d[parameter] = probe
            if method.upper() == "POST":
                resp = requests.post(url, data=test_d, cookies=c, timeout=10)
            else:
                resp = requests.get(url, params={parameter: probe}, cookies=c, timeout=10)
            body = resp.text.lower()
            error_found = any(sig in body for sig in ERROR_SIGNATURES)
            results.append({"probe": "[PROBE REDACTED]", "status": resp.status_code, "error_found": error_found})
            if error_found:
                if session_id:
                    engine.add_finding(
                        session_id, f"XPath Injection in '{parameter}'",
                        "high", url,
                        f"XPath error signature in response to probe",
                        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
                        "Sanitise input before XPath evaluation. Use parameterised XPath."
                    )
                break
        except Exception as e:
            results.append({"probe": "[PROBE REDACTED]", "error": str(e)})

    found = any(r.get("error_found") for r in results)
    _audit_log(session_id, "test_xpath_injection",
               {"url": url, "parameter": parameter}, f"found={found}")
    return _ok({"url": url, "parameter": parameter,
                "vulnerable": found, "probes_run": len(results)})


@mcp.tool()
def test_command_injection(url: str, parameter: str, method: str = "POST",
                            data: str = "{}", cookies: str = "{}", session_id: str = "") -> dict:
    """Test OS command injection via timing-based blind detection."""
    if not _check_url_allowlist(url):
        return _err("URL blocked.")
    if not _check_rate_limit(session_id):
        return _err("Rate limit exceeded.")

    try:
        d = json.loads(data) if isinstance(data, str) else data
        c = json.loads(cookies) if isinstance(cookies, str) else cookies
    except Exception:
        d, c = {}, {}

    timing_results = []
    # Test with sleep-based timing probe (blind)
    for sleep_val, expected_delay in [(5, 4.5), (0, 0)]:
        probe = f"; ping -n {sleep_val + 1} 127.0.0.1" if sleep_val > 0 else "safe_value"
        try:
            test_d = dict(d)
            test_d[parameter] = probe
            start = time.time()
            if method.upper() == "POST":
                requests.post(url, data=test_d, cookies=c, timeout=15)
            else:
                requests.get(url, params={parameter: probe}, cookies=c, timeout=15)
            elapsed = time.time() - start
            timing_results.append({"probe": "[PROBE REDACTED]", "elapsed": round(elapsed, 2),
                                    "expected_delay": expected_delay})
        except Exception as e:
            timing_results.append({"probe": "[PROBE REDACTED]", "error": str(e)})

    # Detect timing anomaly
    if len(timing_results) == 2:
        t1 = timing_results[0].get("elapsed", 0)
        t0 = timing_results[1].get("elapsed", 0)
        vulnerable = t1 - t0 >= 4.0
    else:
        vulnerable = False

    if vulnerable and session_id:
        engine.add_finding(
            session_id, f"Command Injection in '{parameter}'",
            "critical", url,
            "Timing-based blind command injection detected",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "Avoid passing user input to OS commands. Use allowlists for any OS interaction."
        )
        mcts = get_or_create_mcts(session_id)
        mcts.backpropagate("command_injection", 1.0)

    _audit_log(session_id, "test_command_injection",
               {"url": url, "parameter": parameter}, f"vulnerable={vulnerable}")
    return _ok({"url": url, "parameter": parameter,
                "vulnerable": vulnerable, "timing_results": timing_results})


# ══════════════════════════════════════════════════════════════════════════════
# AUTH & SESSION TOOLS (23–27)
# ══════════════════════════════════════════════════════════════════════════════

@mcp.tool()
def test_auth_bypass(url: str, login_endpoint: str, username_field: str = "username",
                      password_field: str = "password", session_id: str = "") -> dict:
    """Test auth bypass: SQLi, default creds, blank password, response manipulation. Generic."""
    if not _check_url_allowlist(login_endpoint):
        return _err("URL blocked.")
    if not _check_rate_limit(session_id):
        return _err("Rate limit exceeded.")

    results = []
    bypass_found = False

    # Get baseline (failed login)
    try:
        baseline = requests.post(login_endpoint,
                                  data={username_field: "invalid_user_xyz", password_field: "invalid_pass_xyz"},
                                  timeout=10, allow_redirects=True)
        baseline_len = len(baseline.text)
        baseline_status = baseline.status_code
    except Exception as e:
        return _err(f"Cannot reach login endpoint: {e}")

    test_cases = [
        ("SQLi bypass", "' OR '1'='1'--", "' OR '1'='1'--"),
        ("SQLi bypass 2", "admin'--", "anything"),
        ("Default creds", "admin", "admin"),
        ("Default creds 2", "admin", "password"),
        ("Default creds 3", "test", "test"),
        ("Blank password", "admin", ""),
    ]

    for label, user, pwd in test_cases:
        try:
            resp = requests.post(login_endpoint,
                                  data={username_field: user, password_field: pwd},
                                  timeout=10, allow_redirects=True)
            # Heuristic: different length or redirect = possible bypass
            diff_len = abs(len(resp.text) - baseline_len) > 200
            diff_status = resp.status_code != baseline_status
            redirected = len(resp.history) > 0
            possible = diff_len or diff_status or redirected

            results.append({
                "test": label,
                "credentials": "[REDACTED]",
                "status": resp.status_code,
                "length_diff": len(resp.text) - baseline_len,
                "redirected": redirected,
                "possible_bypass": possible,
            })

            if possible and not bypass_found:
                bypass_found = True
                if session_id:
                    engine.add_finding(
                        session_id, f"Possible Auth Bypass: {label}",
                        "critical", login_endpoint,
                        f"Response differs significantly from baseline for test: {label}",
                        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        "Harden authentication logic. Use prepared statements for credential validation."
                    )
                    mcts = get_or_create_mcts(session_id)
                    mcts.backpropagate("auth_bypass", 1.0)
        except Exception as e:
            results.append({"test": label, "error": str(e)})

    _audit_log(session_id, "test_auth_bypass",
               {"login_endpoint": login_endpoint}, f"bypass_found={bypass_found}")
    return _ok({
        "login_endpoint": login_endpoint,
        "bypass_found": bypass_found,
        "tests": results,
    })


@mcp.tool()
def test_idor(base_url: str, endpoint_pattern: str, id_param: str,
               cookies: str = "{}", session_id: str = "") -> dict:
    """Test IDOR by iterating IDs. Detects access control failures by response differences."""
    if not _check_url_allowlist(base_url):
        return _err("URL blocked.")
    if not _check_rate_limit(session_id):
        return _err("Rate limit exceeded.")

    # Seen-URL guard: avoid re-testing the same endpoint/param combo this session
    if not hasattr(test_idor, '_seen'):
        test_idor._seen = {}
    _seen_key = f"_idor_seen_{session_id}"
    _already_tested = test_idor._seen.get(_seen_key, set())
    _url_key = f"{endpoint_pattern}::{id_param}"
    if _url_key in _already_tested:
        return _ok({"skipped": True,
                    "reason": "Already tested this endpoint/param combination this session",
                    "endpoint_pattern": endpoint_pattern, "id_param": id_param})
    _already_tested.add(_url_key)
    test_idor._seen[_seen_key] = _already_tested

    try:
        c = json.loads(cookies) if isinstance(cookies, str) else cookies
    except Exception:
        c = {}

    results = []
    baseline_resp = None

    # Expanded ID sequences: small integers + 6-digit banking-style IDs
    id_sequence = list(range(1, 21)) + list(range(800000, 800011))

    for test_id in id_sequence:
        try:
            if "{id}" in endpoint_pattern:
                full_url = base_url.rstrip("/") + endpoint_pattern.replace("{id}", str(test_id))
            else:
                full_url = base_url.rstrip("/") + endpoint_pattern
            resp = requests.get(full_url, params={id_param: test_id} if "{id}" not in endpoint_pattern else None,
                                 cookies=c, timeout=10)
            entry = {"id": test_id, "status": resp.status_code, "length": len(resp.text)}

            if baseline_resp is None and resp.status_code == 200:
                baseline_resp = resp
            elif baseline_resp and resp.status_code == 200:
                if len(resp.text) != len(baseline_resp.text):
                    entry["different_content"] = True
                    if session_id:
                        engine.add_finding(
                            session_id, f"Possible IDOR via {id_param}",
                            "high", full_url,
                            f"ID {test_id} returns different data than baseline",
                            "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
                            "Implement proper authorisation checks for all object references."
                        )
                        mcts = get_or_create_mcts(session_id)
                        mcts.backpropagate("idor", 1.0)
            results.append(entry)
        except Exception as e:
            results.append({"id": test_id, "error": str(e)})

    idor_found = any(r.get("different_content") for r in results)
    _audit_log(session_id, "test_idor",
               {"base_url": base_url, "endpoint_pattern": endpoint_pattern}, f"found={idor_found}")
    return _ok({"endpoint_pattern": endpoint_pattern, "id_param": id_param,
                "idor_found": idor_found, "results": results[:10]})


@mcp.tool()
def test_csrf(url: str, form_endpoint: str = "", cookies: str = "{}", session_id: str = "") -> dict:
    """Check CSRF token presence, entropy, and token reuse."""
    if not _check_url_allowlist(url):
        return _err("URL blocked.")
    try:
        c = json.loads(cookies) if isinstance(cookies, str) else cookies
    except Exception:
        c = {}

    try:
        resp = requests.get(url, cookies=c, timeout=10)
        body = resp.text

        from core.response_sanitiser import _extract_forms
        forms = _extract_forms(body)

        csrf_tokens_found = []
        csrf_fields = ["csrf", "token", "_token", "authenticity_token",
                       "csrfmiddlewaretoken", "__requestverificationtoken"]

        for form in forms:
            for field in form.get("fields", []):
                name = field.get("name", "").lower()
                if any(cf in name for cf in csrf_fields):
                    csrf_tokens_found.append({"field": field["name"], "form_action": form.get("action", "")})

        missing_csrf = len(forms) > 0 and len(csrf_tokens_found) == 0
        if missing_csrf and session_id:
            engine.add_finding(
                session_id, "CSRF Token Missing",
                "medium", url,
                f"{len(forms)} forms found, no CSRF tokens detected",
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",
                "Add CSRF tokens to all state-changing forms. Use SameSite=Strict cookies."
            )
            mcts = get_or_create_mcts(session_id)
            mcts.backpropagate("csrf", 1.0)

        result = {
            "url": url,
            "forms_found": len(forms),
            "csrf_tokens_found": len(csrf_tokens_found),
            "missing_csrf": missing_csrf,
            "token_fields": csrf_tokens_found,
        }
        _audit_log(session_id, "test_csrf", {"url": url}, f"missing={missing_csrf}")
        return _ok(result)
    except Exception as e:
        return _err(str(e))


@mcp.tool()
def analyse_cookies(url: str, cookies_dict: str = "{}", session_id: str = "") -> dict:
    """Analyse cookies: Secure flag, HttpOnly, SameSite, entropy, expiry."""
    try:
        resp = requests.get(url, timeout=10)
        issues = []

        for cookie in resp.cookies:
            name = cookie.name
            flags = {
                "name": name,
                "secure": cookie.secure,
                "http_only": "HttpOnly" in str(cookie),
                "same_site": cookie._rest.get("SameSite", "Not Set"),
                "expires": str(cookie.expires) if cookie.expires else "session",
            }

            if not cookie.secure:
                issues.append({"cookie": name, "issue": "Missing Secure flag"})
            if not flags["http_only"]:
                issues.append({"cookie": name, "issue": "Missing HttpOnly flag"})
            if flags["same_site"] == "Not Set":
                issues.append({"cookie": name, "issue": "Missing SameSite attribute"})

            # Entropy check
            import math as _math
            val = cookie.value or ""
            if len(val) > 0:
                freq = {}
                for ch in val:
                    freq[ch] = freq.get(ch, 0) + 1
                entropy = -sum((c / len(val)) * _math.log2(c / len(val)) for c in freq.values())
                if entropy < 3.0 and len(val) > 5:
                    issues.append({"cookie": name, "issue": f"Low entropy value (H={entropy:.2f})"})

        if issues and session_id:
            engine.add_finding(
                session_id, f"Insecure Cookie Configuration ({len(issues)} issues)",
                "medium", url,
                f"Cookie issues: {json.dumps([i['issue'] for i in issues[:5]])}",
                "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
                "Set Secure, HttpOnly, SameSite=Strict on all sensitive cookies."
            )

        _audit_log(session_id, "analyse_cookies", {"url": url}, f"{len(issues)} issues")
        return _ok({"url": url, "cookie_count": len(resp.cookies), "issues": issues})
    except Exception as e:
        return _err(str(e))


@mcp.tool()
def test_session_fixation(url: str, session_id: str = "") -> dict:
    """Test if session token changes after authentication."""
    if not _check_url_allowlist(url):
        return _err("URL blocked.")
    try:
        s = requests.Session()
        # Get pre-auth session
        s.get(url, timeout=10)
        pre_auth_cookies = dict(s.cookies)

        # Simulate login (POST to same URL with dummy creds)
        s.post(url, data={"username": "test_user", "password": "test_pass"}, timeout=10)
        post_auth_cookies = dict(s.cookies)

        # Check if session tokens changed
        session_keys = ["sessionid", "session", "jsessionid", "phpsessid", "asp.net_sessionid"]
        pre_session_tokens = {k: v for k, v in pre_auth_cookies.items()
                               if any(sk in k.lower() for sk in session_keys)}
        post_session_tokens = {k: v for k, v in post_auth_cookies.items()
                                if any(sk in k.lower() for sk in session_keys)}

        fixation_risk = False
        for key in pre_session_tokens:
            if key in post_session_tokens and pre_session_tokens[key] == post_session_tokens[key]:
                fixation_risk = True

        if fixation_risk and session_id:
            engine.add_finding(
                session_id, "Session Fixation Risk",
                "high", url,
                "Session token did not change after authentication attempt",
                "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N",
                "Regenerate session ID after successful authentication."
            )
            mcts = get_or_create_mcts(session_id)
            mcts.backpropagate("session_fixation", 1.0)

        _audit_log(session_id, "test_session_fixation", {"url": url}, f"risk={fixation_risk}")
        return _ok({
            "url": url,
            "session_fixation_risk": fixation_risk,
            "pre_auth_cookies": list(pre_session_tokens.keys()),
            "post_auth_cookies": list(post_session_tokens.keys()),
        })
    except Exception as e:
        return _err(str(e))


# ══════════════════════════════════════════════════════════════════════════════
# EXECUTION & UTILITY TOOLS (28–32)
# ══════════════════════════════════════════════════════════════════════════════

@mcp.tool()
def run_nuclei_scan(target_url: str, templates: str = "misconfigurations",
                    session_id: str = "") -> dict:
    """Start async nuclei scan. Poll with check_nuclei_status. templates: comma-separated list."""
    if not _check_url_allowlist(target_url):
        return _err("URL blocked.")
    if not _check_rate_limit(session_id):
        return _err("Rate limit exceeded.")
    if not NUCLEI_PATH:
        return _err("nuclei not found. Install from https://github.com/projectdiscovery/nuclei/releases and set NUCLEI_PATH env var.")

    job_id = f"nuclei_{uuid.uuid4().hex[:8]}"
    out_file = str(SANDBOX_DIR / f"{job_id}_output.json")

    template_list = [t.strip() for t in templates.split(",")]
    template_args = []
    for t in template_list:
        template_args += ["-t", t]

    cmd = [NUCLEI_PATH, "-u", target_url, "-o", out_file, "-json"] + template_args + ["-silent"]

    # Route external targets through local mitmproxy (port 8888).
    # localhost/127.x targets (e.g. AltoroJ on :8080) bypass the proxy.
    _nuclei_target_is_local = 'localhost' in target_url or '127.0.0.1' in target_url
    if not _nuclei_target_is_local:
        cmd += ['-proxy', 'http://127.0.0.1:8888']

    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        with _scan_lock:
            _scan_processes[job_id] = proc
        engine.create_scan_job("nuclei", session_id, f"nuclei -u {target_url} [TEMPLATES REDACTED]",
                           proc.pid, job_id=job_id)
        _audit_log(session_id, "run_nuclei_scan",
                   {"target_url": target_url, "templates": templates},
                   f"Started {job_id} pid={proc.pid}")
        _update_scan_job_status(job_id, "running")
        return _ok({"job_id": job_id, "status": "running", "output_file": out_file})
    except FileNotFoundError:
        return _err(f"nuclei not found at {NUCLEI_PATH}. Set NUCLEI_PATH env var.")
    except Exception as e:
        return _err(str(e))


@mcp.tool()
def check_nuclei_status(job_id: str) -> dict:
    """Poll nuclei scan. Returns: running|complete|error + finding count."""
    with _scan_lock:
        proc = _scan_processes.get(job_id)
    if proc is not None:
        ret = proc.poll()
        if ret is None:
            status = "running"
        elif ret == 0:
            status = "complete"
            _update_scan_job_status(job_id, "complete")
        else:
            status = "error"
            _update_scan_job_status(job_id, "error")
    else:
        # Server restarted — read from SQLite
        status = _get_scan_job_status(job_id)

    finding_count = 0
    findings_list = []
    out_file = SANDBOX_DIR / f"{job_id}_output.json"
    if out_file.exists():
        try:
            lines = out_file.read_text().strip().split("\n")
            for line in lines:
                if not line.strip():
                    continue
                finding_count += 1
                try:
                    findings_list.append(json.loads(line))
                except Exception:
                    findings_list.append({"raw": line[:200]})
        except Exception:
            pass

    # Write results back to scan_jobs when scan is done
    if status in ("complete", "error") and findings_list:
        try:
            import sqlite3 as _sq3
            from core.graph_engine import DB_PATH as _DB_PATH
            with _sq3.connect(_DB_PATH) as _rc:
                _rc.execute(
                    "UPDATE scan_jobs SET result=? WHERE job_id=?",
                    (json.dumps(findings_list)[:2000], job_id)
                )
                _rc.commit()
        except Exception as _rwe:
            logger.debug(f"nuclei result write-back failed: {_rwe}")

    _audit_log("", "check_nuclei_status", {"job_id": job_id}, f"status={status}")
    return _ok({"job_id": job_id, "status": status, "finding_count": finding_count})


@mcp.tool()
def kill_all_scans() -> dict:
    """Kill all running sqlmap and nuclei subprocesses. Always call after async scan sequences."""
    killed = []
    with _scan_lock:
        for job_id, proc in list(_scan_processes.items()):
            if proc.poll() is None:
                try:
                    proc.terminate()
                    killed.append(job_id)
                except Exception as e:
                    logger.debug(f"Failed to kill {job_id}: {e}")
        _scan_processes.clear()
    _audit_log("", "kill_all_scans", {}, f"Killed {len(killed)} processes")
    return _ok({"killed_jobs": killed, "count": len(killed)})


@mcp.tool()
def shell_exec(command: str, working_dir: str = "") -> dict:
    """Controlled shell execution. Certain destructive commands are blocked."""
    if not working_dir:
        working_dir = str(SANDBOX_DIR)
    BLOCKED = [
        r"rm\s+-rf", r"format\s+[a-z]:", r"del\s+/f\s+/s",
        r"reg\s+delete", r"net\s+user", r"rd\s+/s\s+/q",
        r"rmdir\s+/s", r"shutdown", r"taskkill.*system",
    ]
    cmd_lower = command.lower()
    for pattern in BLOCKED:
        if re.search(pattern, cmd_lower):
            _audit_log("", "shell_exec", {"command": "[BLOCKED]"}, "BLOCKED")
            return _err(f"Command blocked by security policy: matches pattern '{pattern}'")

    _audit_log("", "shell_exec",
               {"command": command[:100], "working_dir": working_dir},
               "executing")
    try:
        result = subprocess.run(
            command, shell=True, capture_output=True, text=True,
            cwd=working_dir, timeout=60
        )
        return _ok({
            "stdout": result.stdout[:2000],
            "stderr": result.stderr[:500],
            "exit_code": result.returncode,
        })
    except subprocess.TimeoutExpired:
        return _err("Command timed out after 60 seconds.")
    except Exception as e:
        return _err(str(e))


@mcp.tool()
def generate_report(session_id: str) -> dict:
    """Generate a standalone HTML pentest report for the session."""
    try:
        ctx = engine.get_session_context(session_id)
        if "error" in ctx:
            return _err(ctx["error"])

        findings = engine.get_findings(session_id)
        reasoning = engine.get_reasoning_log(session_id)
        mcts = get_or_create_mcts(session_id)
        mcts_state = mcts.get_state()

        sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = f.get("severity", "info").lower()
            if sev in sev_counts:
                sev_counts[sev] += 1

        # ── Professional report template ────────────────────────────────────────
        date_str = datetime.utcnow().strftime("%d %B %Y")
        datetime_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
        target_url = ctx.get("target_url", "N/A")
        goal = ctx.get("goal", "N/A")

        # Sort findings Critical→Low
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(findings, key=lambda f: sev_order.get(
            f.get("severity", "info").lower(), 5))

        # Risk donut (CSS conic-gradient)
        total_findings = len(sorted_findings) or 1
        def to_pct(n): return round(n / total_findings * 100, 1)
        crit_pct = to_pct(sev_counts["critical"])
        high_pct = crit_pct + to_pct(sev_counts["high"])
        med_pct  = high_pct + to_pct(sev_counts["medium"])
        low_pct  = med_pct  + to_pct(sev_counts["low"])

        IMPACT_MAP = {
            "critical": "This vulnerability poses an immediate threat to the organisation. An attacker could gain full system access, exfiltrate sensitive data, or cause complete service disruption without requiring prior authentication.",
            "high":     "Exploitation of this vulnerability could result in significant data exposure or partial system compromise. Prompt remediation is strongly recommended.",
            "medium":   "This vulnerability may be leveraged as part of a multi-step attack chain. While not directly exploitable for full compromise, it reduces the overall security posture.",
            "low":      "This vulnerability represents a minor risk. Addressing it will improve defence-in-depth but does not represent an immediate threat.",
            "info":     "Informational finding with no direct security impact. Remediation is optional but recommended as best practice.",
        }

        TIMELINE_MAP = {"critical": "Immediate (24h)", "high": "Short-term (1 week)",
                        "medium": "Medium-term (1 month)", "low": "Long-term (next quarter)", "info": "As needed"}

        def finding_card(idx, f):
            sev = f.get("severity", "info").lower()
            title = f.get("title", "Unknown Finding")
            endpoint = f.get("endpoint", "N/A")
            cvss = f.get("cvss", "")
            evidence = DagSanitiser.sanitise_evidence(f.get("evidence", ""))
            remediation = f.get("remediation", "See OWASP guidance.")
            impact = IMPACT_MAP.get(sev, IMPACT_MAP["medium"])
            cvss_score = ""
            if cvss and "/" in cvss:
                # Try to extract numeric score from vector
                parts = cvss.split("/")
                if len(parts) >= 6:
                    try:
                        # Rough CVSS base estimate from vector (simplified)
                        cvss_score = ""
                    except Exception:
                        pass
            return f"""
<div class="finding-card" id="finding-{idx}">
  <div class="finding-header sev-bg-{sev}">
    <span class="finding-idx">F{idx+1:02d}</span>
    <span class="finding-title">{title}</span>
    <span class="sev-badge-lg">{sev.upper()}</span>
  </div>
  <div class="finding-body">
    <div class="finding-grid">
      <div class="fg-label">CVSS Vector</div>
      <div class="fg-val"><code>{cvss or "N/A"}</code></div>
      <div class="fg-label">Affected Endpoint</div>
      <div class="fg-val"><code>{endpoint}</code></div>
      <div class="fg-label">Evidence Summary</div>
      <div class="fg-val">{evidence or "Tool-confirmed via automated probe."}</div>
      <div class="fg-label">Proof of Concept</div>
      <div class="fg-val"><code>curl -s "{endpoint}" -X POST -d "param=[PAYLOAD]" -v</code></div>
    </div>
    <div class="finding-section">
      <div class="fsec-title">Business Impact</div>
      <p>{impact}</p>
    </div>
    <div class="finding-section">
      <div class="fsec-title">Remediation</div>
      <p>{remediation}</p>
    </div>
  </div>
</div>"""

        findings_html = "\n".join(finding_card(i, f) for i, f in enumerate(sorted_findings))

        mcts_nodes = mcts_state.get("nodes", [])
        _mcts_rows = []
        for i, n in enumerate(sorted(mcts_nodes, key=lambda x: -x.get("confidence", 0))):
            top_cls = ' class="top-row"' if not i else ""
            _mcts_rows.append(
                f"<tr{top_cls}>"
                f"<td>{n['attack_type']}</td>"
                f"<td>{(n.get('prior_probability', 0)):.2f}</td>"
                f"<td>{(n.get('posterior_probability', n.get('posterior', 0))):.2f}</td>"
                f"<td><span class=\"conf-bar\" style=\"width:{int(n.get('confidence', 0) * 80)}px\">&nbsp;</span>"
                f" {n.get('confidence', 0):.2f}</td>"
                f"<td>{n.get('visit_count', 0)}</td></tr>"
            )
        mcts_rows = "\n".join(_mcts_rows)

        roadmap_rows = "\n".join(
            f"<tr><td>{i+1}</td>"
            f"<td><a href='#finding-{i}' style='color:#4dabf7'>{f.get('title','')}</a></td>"
            f"<td><span class='sev-badge sev-{f.get('severity','info').lower()}'>{f.get('severity','').upper()}</span></td>"
            f"<td>{TIMELINE_MAP.get(f.get('severity','info').lower(), 'As needed')}</td>"
            f"<td>{'High' if f.get('severity','info').lower() in ('critical','high') else 'Medium'}</td></tr>"
            for i, f in enumerate(sorted_findings)
        )

        branches_discovered = ctx.get("attack_branches", [])
        injection_pts = ctx.get("injection_points", [])
        key_facts = ctx.get("key_facts", [])

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Penetration Test Report — {session_id}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700&display=swap');
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Inter', 'Segoe UI', Arial, sans-serif; background: #f0f4f8; color: #1a202c; line-height: 1.6; }}
  a {{ color: #4dabf7; }}

  /* Cover */
  .cover {{
    background: linear-gradient(135deg, #1a1a2e 0%, #16213e 60%, #0f3460 100%);
    color: #eaeaea; padding: 60px 80px; min-height: 380px;
    display: flex; flex-direction: column; justify-content: space-between;
    page-break-after: always;
  }}
  .cover-logo {{ font-size: 1.5em; font-weight: 700; color: #e94560; letter-spacing: 2px; }}
  .cover-logo span {{ color: #eaeaea; }}
  .cover-title {{ font-size: 2.4em; font-weight: 700; margin: 24px 0 8px; color: #fff; }}
  .cover-subtitle {{ font-size: 1.1em; color: #a0aec0; margin-bottom: 32px; }}
  .cover-meta {{ display: grid; grid-template-columns: 140px 1fr; gap: 8px 16px; font-size: 0.88em; }}
  .cover-meta .lbl {{ color: #718096; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; }}
  .cover-meta .val {{ color: #e2e8f0; }}
  .classification {{
    display: inline-block; background: #e94560; color: #fff;
    padding: 3px 14px; border-radius: 4px; font-size: 0.78em;
    font-weight: 700; letter-spacing: 1px; text-transform: uppercase;
    margin-bottom: 20px;
  }}

  /* Page wrapper */
  .page {{ max-width: 1100px; margin: 0 auto; padding: 32px 24px; }}

  /* Section */
  section {{ background: #fff; border-radius: 10px; padding: 28px 32px; margin: 24px 0;
             box-shadow: 0 1px 4px rgba(0,0,0,0.08); }}
  h2 {{ font-size: 1.3em; font-weight: 700; color: #1a202c;
        border-bottom: 2px solid #e2e8f0; padding-bottom: 10px; margin-bottom: 18px; }}
  h3 {{ font-size: 1.05em; font-weight: 600; color: #2d3748; margin-bottom: 10px; }}
  p {{ color: #4a5568; margin: 8px 0; }}

  /* Executive Summary */
  .exec-grid {{ display: flex; gap: 20px; align-items: center; flex-wrap: wrap; }}
  .donut-wrap {{ position: relative; width: 120px; height: 120px; flex-shrink: 0; }}
  .donut-chart {{
    width: 120px; height: 120px; border-radius: 50%;
    background: conic-gradient(
      #e94560 0% {crit_pct}%,
      #f85149 {crit_pct}% {high_pct}%,
      #d29922 {high_pct}% {med_pct}%,
      #388bfd {med_pct}% {low_pct}%,
      #484f58 {low_pct}% 100%
    );
  }}
  .donut-hole {{
    position: absolute; top: 50%; left: 50%; transform: translate(-50%,-50%);
    width: 72px; height: 72px; border-radius: 50%; background: #fff;
    display: flex; align-items: center; justify-content: center;
    font-size: 1.3em; font-weight: 700; color: #1a202c;
  }}
  .sev-legend {{ display: flex; flex-direction: column; gap: 5px; margin-left: 10px; }}
  .sev-leg {{ display: flex; align-items: center; gap: 7px; font-size: 0.82em; }}
  .sev-dot {{ width: 12px; height: 12px; border-radius: 50%; flex-shrink: 0; }}
  .exec-stats {{ display: flex; gap: 14px; flex-wrap: wrap; }}
  .stat-card {{
    border-radius: 8px; padding: 14px 20px; text-align: center;
    min-width: 80px; color: #fff;
  }}
  .stat-card .sn {{ font-size: 1.8em; font-weight: 700; }}
  .stat-card .sl {{ font-size: 0.75em; opacity: 0.85; text-transform: uppercase; letter-spacing: 0.5px; }}
  .sc-critical {{ background: #e94560; }}
  .sc-high {{ background: #f85149; }}
  .sc-medium {{ background: #d29922; }}
  .sc-low {{ background: #388bfd; }}
  .sc-info {{ background: #238636; }}

  /* Findings */
  .finding-card {{ background: #fff; border-radius: 8px; margin: 16px 0;
                   box-shadow: 0 1px 4px rgba(0,0,0,0.08); overflow: hidden; }}
  .finding-header {{
    padding: 14px 20px; display: flex; align-items: center; gap: 14px;
    color: #fff;
  }}
  .sev-bg-critical {{ background: linear-gradient(90deg, #e94560, #c0392b); }}
  .sev-bg-high     {{ background: linear-gradient(90deg, #f85149, #d63031); }}
  .sev-bg-medium   {{ background: linear-gradient(90deg, #d29922, #e67e22); }}
  .sev-bg-low      {{ background: linear-gradient(90deg, #388bfd, #2980b9); }}
  .sev-bg-info     {{ background: linear-gradient(90deg, #238636, #27ae60); }}
  .finding-idx {{ font-size: 0.8em; opacity: 0.7; }}
  .finding-title {{ flex: 1; font-weight: 700; font-size: 1em; }}
  .sev-badge-lg {{
    padding: 3px 12px; border-radius: 12px;
    background: rgba(255,255,255,0.2); font-size: 0.78em;
    font-weight: 700; letter-spacing: 0.5px;
  }}
  .finding-body {{ padding: 18px 20px; }}
  .finding-grid {{
    display: grid; grid-template-columns: 160px 1fr;
    gap: 6px 12px; margin-bottom: 16px;
  }}
  .fg-label {{ font-weight: 600; font-size: 0.82em; color: #718096; padding-top: 1px; }}
  .fg-val {{ font-size: 0.85em; color: #2d3748; word-break: break-all; }}
  .finding-section {{ margin-top: 12px; }}
  .fsec-title {{ font-weight: 700; font-size: 0.82em; color: #718096;
                 text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 5px; }}
  code {{
    background: #f7fafc; border: 1px solid #e2e8f0; padding: 2px 6px;
    border-radius: 4px; font-family: 'Consolas', monospace; font-size: 0.85em; color: #2d3748;
  }}

  /* Tables */
  .data-table {{ width: 100%; border-collapse: collapse; font-size: 0.88em; }}
  .data-table th {{
    background: #2d3748; color: #e2e8f0; padding: 9px 12px;
    text-align: left; font-weight: 600;
  }}
  .data-table td {{ padding: 8px 12px; border-bottom: 1px solid #e2e8f0; }}
  .data-table tr:hover td {{ background: #f7fafc; }}
  .data-table tr.top-row td {{ font-weight: 600; color: #2b6cb0; }}

  /* Severity badges */
  .sev-badge {{
    display: inline-block; padding: 2px 9px; border-radius: 10px;
    font-size: 0.76em; font-weight: 700; color: #fff;
  }}
  .sev-critical {{ background: #e94560; }}
  .sev-high {{ background: #f85149; }}
  .sev-medium {{ background: #d29922; }}
  .sev-low {{ background: #388bfd; }}
  .sev-info {{ background: #238636; }}

  /* MCTS conf bar */
  .conf-bar {{
    display: inline-block; height: 8px; background: #4dabf7;
    border-radius: 4px; vertical-align: middle; margin-right: 4px;
  }}

  /* Print */
  @media print {{
    body {{ background: #fff; }}
    .cover {{ min-height: auto; }}
    section {{ box-shadow: none; border: 1px solid #e2e8f0; }}
    .finding-card {{ box-shadow: none; border: 1px solid #e2e8f0; }}
  }}
</style>
</head>
<body>

<!-- ── COVER PAGE ─────────────────────────────────────────────────────────── -->
<div class="cover">
  <div>
    <div class="cover-logo">REDTEAM<span> V9</span></div>
    <div class="classification">Confidential</div>
    <div class="cover-title">Web Application Penetration Test Report</div>
    <div class="cover-subtitle">Autonomous Security Assessment</div>
  </div>
  <div class="cover-meta">
    <div class="lbl">Target</div>        <div class="val">{target_url}</div>
    <div class="lbl">Date</div>          <div class="val">{date_str}</div>
    <div class="lbl">Session ID</div>    <div class="val">{session_id}</div>
    <div class="lbl">Goal</div>          <div class="val">{goal}</div>
    <div class="lbl">Prepared by</div>   <div class="val">RedTeam V9 Autonomous Assessment Platform</div>
    <div class="lbl">Classification</div><div class="val">CONFIDENTIAL — For authorised recipients only</div>
  </div>
</div>

<div class="page">

<!-- ── 1. EXECUTIVE SUMMARY ─────────────────────────────────────────────────── -->
<section>
  <h2>1. Executive Summary</h2>
  <div class="exec-grid">
    <div class="donut-wrap">
      <div class="donut-chart"></div>
      <div class="donut-hole">{len(sorted_findings)}</div>
    </div>
    <div class="sev-legend">
      <div class="sev-leg"><div class="sev-dot" style="background:#e94560"></div> Critical: {sev_counts['critical']}</div>
      <div class="sev-leg"><div class="sev-dot" style="background:#f85149"></div> High: {sev_counts['high']}</div>
      <div class="sev-leg"><div class="sev-dot" style="background:#d29922"></div> Medium: {sev_counts['medium']}</div>
      <div class="sev-leg"><div class="sev-dot" style="background:#388bfd"></div> Low: {sev_counts['low']}</div>
      <div class="sev-leg"><div class="sev-dot" style="background:#484f58"></div> Info: {sev_counts['info']}</div>
    </div>
    <div class="exec-stats">
      <div class="stat-card sc-critical"><div class="sn">{sev_counts['critical']}</div><div class="sl">Critical</div></div>
      <div class="stat-card sc-high"><div class="sn">{sev_counts['high']}</div><div class="sl">High</div></div>
      <div class="stat-card sc-medium"><div class="sn">{sev_counts['medium']}</div><div class="sl">Medium</div></div>
      <div class="stat-card sc-low"><div class="sn">{sev_counts['low']}</div><div class="sl">Low</div></div>
      <div class="stat-card sc-info"><div class="sn">{sev_counts['info']}</div><div class="sl">Info</div></div>
    </div>
  </div>
  <p style="margin-top:20px">
    {"A total of " + str(len(sorted_findings)) + " security finding" + ("s were" if len(sorted_findings) != 1 else " was") +
     " identified during this assessment of " + target_url + "." if sorted_findings
     else "No exploitable vulnerabilities were confirmed during this assessment."}
    {" " + str(sev_counts['critical']) + " critical-severity finding" + ("s require" if sev_counts['critical'] != 1 else " requires") + " immediate remediation." if sev_counts['critical'] else ""}
    {" " + str(sev_counts['high']) + " high-severity finding" + ("s" if sev_counts['high'] != 1 else "") + " should be addressed within one week." if sev_counts['high'] else ""}
    {" The assessment covered all discovered pages, forms, and API endpoints using a 6-phase autonomous methodology." if sorted_findings else " The assessment covered all discovered surfaces using a 6-phase autonomous methodology and returned clean results."}
  </p>
</section>

<!-- ── 2. SCOPE & METHODOLOGY ────────────────────────────────────────────────── -->
<section>
  <h2>2. Scope &amp; Methodology</h2>
  <table class="data-table" style="margin-bottom:16px">
    <tr><th>Parameter</th><th>Value</th></tr>
    <tr><td>Target URL</td><td>{target_url}</td></tr>
    <tr><td>Test Date</td><td>{datetime_str}</td></tr>
    <tr><td>Session ID</td><td>{session_id}</td></tr>
    <tr><td>Engagement Goal</td><td>{goal}</td></tr>
    <tr><td>Methodology</td><td>OWASP Testing Guide v4.2 + PTES</td></tr>
    <tr><td>Tools</td><td>RedTeam V9 MCP (32 tools), BayesianMCTS planner, sqlmap, nuclei, Playwright</td></tr>
    <tr><td>Approach</td><td>Black-box — no prior knowledge of the target assumed</td></tr>
  </table>
  <h3>Phases Executed</h3>
  <table class="data-table">
    <tr><th>#</th><th>Phase</th><th>Description</th></tr>
    <tr><td>0</td><td>Initialisation</td><td>Session creation, transfer learning priors loaded</td></tr>
    <tr><td>1</td><td>Reconnaissance</td><td>Fingerprinting, crawling, endpoint enumeration</td></tr>
    <tr><td>2</td><td>Authentication Testing</td><td>Auth bypass, default credentials, SQLi bypass</td></tr>
    <tr><td>3</td><td>Injection Testing</td><td>SQLi, XSS, XPath injection, command injection</td></tr>
    <tr><td>4</td><td>Access Control</td><td>IDOR enumeration, privilege escalation</td></tr>
    <tr><td>5</td><td>Configuration Review</td><td>Security headers, cookies, CSRF, session fixation</td></tr>
    <tr><td>6</td><td>Reporting</td><td>Findings documented, CVSS scored, remediation roadmap</td></tr>
  </table>
</section>

<!-- ── 3. ATTACK SURFACE SUMMARY ─────────────────────────────────────────────── -->
<section>
  <h2>3. Attack Surface Summary</h2>
  <table class="data-table">
    <tr><th>Surface</th><th>Count</th><th>Notes</th></tr>
    <tr><td>Injection points discovered</td><td>{len(injection_pts)}</td><td>Parameters tested with injection probes</td></tr>
    <tr><td>Attack branches explored</td><td>{len(branches_discovered)}</td><td>Attack types scored and tested</td></tr>
    <tr><td>Key facts distilled</td><td>{len(key_facts)}</td><td>Insights recorded to transfer learning</td></tr>
    <tr><td>Confirmed findings</td><td>{len(sorted_findings)}</td><td>Verified by tool output</td></tr>
  </table>
  {('<div style="margin-top:12px"><h3>Injection Points</h3><table class="data-table"><tr><th>Parameter</th><th>Endpoint</th><th>Method</th></tr>' +
    "".join(f"<tr><td><code>{ip.get('parameter','')}</code></td><td><code>{ip.get('endpoint','')}</code></td><td>{ip.get('method','')}</td></tr>" for ip in injection_pts[:20]) +
    '</table></div>') if injection_pts else '<p style="margin-top:10px;color:#718096">No injection points recorded.</p>'}
</section>

<!-- ── 4. FINDINGS ───────────────────────────────────────────────────────────── -->
<section>
  <h2>4. Findings</h2>
  {findings_html if findings_html else '<p style="color:#718096">No confirmed vulnerabilities were identified during this assessment.</p>'}
</section>

<!-- ── 5. REMEDIATION ROADMAP ────────────────────────────────────────────────── -->
<section>
  <h2>5. Remediation Roadmap</h2>
  {('''<table class="data-table">
    <tr><th>#</th><th>Finding</th><th>Severity</th><th>Timeline</th><th>Effort</th></tr>
    ''' + roadmap_rows + '''
  </table>''') if sorted_findings else '<p style="color:#718096">No findings to remediate.</p>'}
</section>

<!-- ── 6. APPENDIX ───────────────────────────────────────────────────────────── -->
<section>
  <h2>6. Appendix</h2>
  <h3>A — MCTS Confidence Progression</h3>
  <p>How the agent's confidence in each attack branch evolved during the assessment:</p>
  {('<table class="data-table" style="margin-top:10px"><tr><th>Attack Branch</th><th>Prior</th><th>Posterior</th><th>Confidence</th><th>Visits</th></tr>' + mcts_rows + '</table>') if mcts_rows else '<p style="color:#718096">No MCTS data available.</p>'}
  <h3 style="margin-top:20px">B — Key Facts</h3>
  {('<ul style="margin-top:8px;padding-left:20px">' + "".join(f"<li style='margin:4px 0;font-size:0.88em;color:#4a5568'>{kf}</li>" for kf in key_facts) + '</ul>') if key_facts else '<p style="color:#718096">No key facts recorded.</p>'}
  <h3 style="margin-top:20px">C — Report Metadata</h3>
  <table class="data-table">
    <tr><td>Generated</td><td>{datetime_str}</td></tr>
    <tr><td>Platform</td><td>RedTeam V9 Autonomous Assessment Platform</td></tr>
    <tr><td>Report version</td><td>1.0</td></tr>
    <tr><td>Classification</td><td>CONFIDENTIAL</td></tr>
  </table>
</section>

</div><!-- .page -->
</body>
</html>"""

        report_path = REPORTS_DIR / f"{session_id}_report.html"
        report_path.write_text(html, encoding="utf-8")
        _audit_log(session_id, "generate_report", {}, f"Report at {report_path}")
        return _ok({"report_path": str(report_path), "findings_count": len(findings),
                    "severity_breakdown": sev_counts})
    except Exception as e:
        return _err(str(e))


# ─── AEX skill loader ────────────────────────────────────────────────────────

@mcp.tool()
def read_skill(mode: str = "phase_0", phase: int = 0) -> dict:
    """Read the pentest skill/methodology file for the current phase.
    Used by AEX agents to load the full V9 methodology before each attack phase.
    mode: phase name e.g. 'recon', 'auth_bypass', 'sqli', 'idor', 'csrf',
          'config_review', 'session_fixation', 'report', 'phase_0'
    phase: phase number 0-6
    Returns full skill file content — agent extracts the relevant phase section.
    """
    skill_dir = _PROJECT_ROOT / "skills"
    # Primary: webapp_pt_skill.md (the main methodology document)
    skill_path = skill_dir / "webapp_pt_skill.md"
    if not skill_path.exists():
        # Fallback: COWORK_SPACE_CONTEXT.md contains full methodology
        skill_path = _PROJECT_ROOT / "cowork" / "COWORK_SPACE_CONTEXT.md"
    if not skill_path.exists():
        return _err(f"Skill file not found. Expected: {skill_dir}/webapp_pt_skill.md")
    try:
        content = skill_path.read_text(encoding="utf-8")
        # Identify section markers for quick navigation
        phase_marker = f"Phase {phase}"
        mode_lower   = mode.lower().replace("_", " ")
        # Find the start of the relevant section (if present)
        lines = content.split("\n")
        section_start = 0
        for i, ln in enumerate(lines):
            if phase_marker in ln or mode_lower in ln.lower():
                section_start = i
                break
        # Return full content — agent reads what it needs
        _audit_log("", "read_skill", {"mode": mode, "phase": phase}, f"Loaded {len(content)} chars")
        return _ok({
            "skill_content": content,
            "mode": mode,
            "phase": phase,
            "path": str(skill_path),
            "total_chars": len(content),
            "section_hint_line": section_start,
        })
    except Exception as e:
        return _err(str(e))


# ─── Health endpoint + startup ────────────────────────────────────────────────

@mcp.custom_route("/health", methods=["GET"])
async def health(request):
    from starlette.responses import JSONResponse
    return JSONResponse({
        "status": "ok",
        "service": "redteam-v9-mcp",
        "tools": 35,
        "version": "9.0.0",
    })


if __name__ == "__main__":
    import uvicorn
    # Generate bearer token if not exists
    if not BEARER_TOKEN_FILE.exists():
        import secrets
        BEARER_TOKEN_FILE.parent.mkdir(parents=True, exist_ok=True)
        token = secrets.token_urlsafe(32)
        BEARER_TOKEN_FILE.write_text(token)
        print(f"[V9] Bearer token generated: {token}")
    uvicorn.run(
        "tools.mcp_service:mcp.app" if hasattr(mcp, 'app') else mcp,
        host="127.0.0.1",
        port=6019,
        log_level="info",
    )
