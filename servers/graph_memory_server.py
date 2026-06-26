"""
Graph Memory Server — FastAPI on port 6037 (127.0.0.1 only).
Provides REST API for session/branch/node management + DAG data.
"""
import os
import sys
import logging
import json
import sqlite3
import uuid
from datetime import datetime
sys.path.insert(0, str(__import__('pathlib').Path(__file__).resolve().parent.parent))
import pathlib as _pathlib
_PROJECT_ROOT = _pathlib.Path(__file__).resolve().parent.parent

from fastapi import FastAPI, HTTPException, Header, Depends, Request
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List, Any
import uvicorn

from core.graph_engine import GraphEngine, DB_PATH
from core.intelligence import get_or_create_mcts
from core.transfer_learning import init_transfer_table, get_all_insights
from core.dag_sanitiser import DagSanitiser

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="RedTeam V9 Graph Memory Server", version="9.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

engine = GraphEngine()
init_transfer_table()

_sicd_cache = {"score": 0.29, "ts": 0.0, "session": ""}

# Bearer token auth (write endpoints only)
BEARER_TOKEN_FILE = str(__import__('pathlib').Path(__file__).resolve().parent.parent / ".tmp" / "rtv9_bearer.txt")

def _load_token() -> str:
    try:
        with open(BEARER_TOKEN_FILE) as f:
            return f.read().strip()
    except Exception:
        return ""

def require_auth(request: Request, authorization: Optional[str] = Header(None)):
    """Auth with localhost bypass — AEX gateway connects from 127.0.0.1 without Bearer."""
    # Allow unauthenticated access from localhost (AEX gateway)
    client_host = request.client.host if request.client else ""
    if client_host in ("127.0.0.1", "localhost", "::1"):
        return  # AEX connects from localhost — allow through

    # Require Bearer token for non-localhost connections
    token = _load_token()
    if not token:
        return  # no token configured, skip auth
    if not authorization or authorization != f"Bearer {token}":
        raise HTTPException(status_code=401, detail="Unauthorized")

# ─── Models ────────────────────────────────────────────────────────────────

class SessionCreate(BaseModel):
    session_id: str
    target_url: str
    goal: str = ""

class BranchSet(BaseModel):
    session_id: str
    attack_type: str
    description: str = ""

class NodeAdd(BaseModel):
    session_id: str
    node_type: str
    label: str
    description: str = ""
    confidence: float = 0.0
    severity: str = "info"
    metadata: dict = {}

class EdgeAdd(BaseModel):
    session_id: str
    source_id: str
    target_id: str
    label: str = "leads_to"

class ReasoningLog(BaseModel):
    session_id: str
    agent: str = ""
    step: str = ""
    content: str = ""

class InjectionPoint(BaseModel):
    session_id: str
    parameter: str
    endpoint: str
    method: str = "POST"
    context: str = ""

class Finding(BaseModel):
    session_id: str
    title: str
    severity: str = "medium"
    endpoint: str = ""
    evidence: str = ""
    cvss: str = ""
    remediation: str = ""

class KnowledgeDistill(BaseModel):
    session_id: str
    key_insight: str

class ScoreBranches(BaseModel):
    session_id: str
    candidate_branches: List[str] = []
    top_k: int = 5

class FingerprintUpdate(BaseModel):
    session_id: str
    fingerprint: dict

class ChaosInject(BaseModel):
    session_id: str
    test_id: str
    mast_classification: str = "SYNTHETIC_CHAOS"
    severity: str = "high"
    phase: str = "sicd_dashboard_test"
    intent: str = "synthetic_dashboard_validation"

# ─── Endpoints ─────────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    sessions = engine.get_all_sessions()
    return {"status": "ok", "service": "redteam-v9", "sessions": len(sessions)}

@app.get("/ping")
async def ping():
    """Raw connectivity check — no auth required. Use to verify AEX can reach V9."""
    return {"status": "ok", "service": "redteam-v9", "version": "9.0"}

def _get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn

def _is_local_request(request: Request) -> bool:
    host = request.client.host if request.client else ""
    return host in ("127.0.0.1", "localhost", "::1")

def _safe_text(value: Any, limit: int = 220) -> str:
    if value is None:
        return ""
    text = str(value)
    return text if len(text) <= limit else text[:limit] + "..."

def _rows(query: str, params: tuple = ()) -> list[dict]:
    with _get_conn() as conn:
        return [dict(r) for r in conn.execute(query, params).fetchall()]

def _count_rows(query: str, params: tuple = ()) -> list[dict]:
    return _rows(query, params)

def _parse_tools(value: str) -> list[str]:
    try:
        parsed = json.loads(value or "[]")
        if isinstance(parsed, list):
            return [str(v) for v in parsed]
    except Exception:
        pass
    return []

@app.get("/intent_status")
async def intent_status(limit: int = 25):
    """Read-only SICD dashboard state. Sanitised; no raw payload/evidence fields."""
    limit = max(1, min(limit, 100))
    try:
        sessions = _rows(
            """SELECT session_id, target_url, goal, status, created_at
               FROM sessions
               ORDER BY created_at DESC"""
        )
        active_sessions = [s for s in sessions if (s.get("status") or "active") == "active"]

        if not active_sessions:
            try:
                with _get_conn() as conn:
                    last = conn.execute(
                        "SELECT session_id, target_url FROM sessions ORDER BY rowid DESC LIMIT 1"
                    ).fetchone()
                    if last:
                        last_findings = conn.execute(
                            "SELECT COUNT(*) FROM findings WHERE session_id=?",
                            (last["session_id"],)
                        ).fetchone()[0]
                        return {
                            "status": "no_active_session",
                            "last_session_id": last["session_id"],
                            "last_target": last["target_url"],
                            "last_findings": last_findings,
                            "session_id": None,
                            "message": f"Last: {last['session_id']} ({last_findings} findings)",
                            "divergence_score": 0.0,
                            "total_incidents": 0,
                            "calls_last_60s": 0,
                            "active_declared_intents": [],
                            "adk_cards": {},
                            "recent_incidents": [],
                            "agent_cards": {},
                        }
            except Exception:
                pass
            return {
                "status": "no_session",
                "session_id": None,
                "divergence_score": 0.0,
                "total_incidents": 0,
                "calls_last_60s": 0,
                "active_declared_intents": [],
                "adk_cards": {},
                "recent_incidents": [],
                "agent_cards": {},
            }

        active_intents = _rows(
            """SELECT id, phase, intent, confidence, tools_authorised, scope
               FROM declare_intents
               WHERE active=1
               ORDER BY created_at DESC
               LIMIT 3"""
        )
        for item in active_intents:
            item["tools_authorised"] = _parse_tools(item.get("tools_authorised", "[]"))

        incidents = _rows(
            """SELECT mast_classification, severity, tool_name,
                      datetime(timestamp) as timestamp
               FROM agent_intent_log
               WHERE mast_classification IS NOT NULL AND mast_classification != ''
               ORDER BY timestamp DESC
               LIMIT 5"""
        )

        summary = {
            "counts": {
                "sessions_total": len(sessions),
                "sessions_active": len(active_sessions),
                "active_intents": len(active_intents),
                "recent_incidents": len(incidents),
            },
            "by_phase": _count_rows(
                """SELECT COALESCE(phase, session_phase, 'unknown') AS key, COUNT(*) AS count
                   FROM (
                     SELECT phase, NULL AS session_phase FROM declare_intents
                     UNION ALL
                     SELECT NULL AS phase, session_phase FROM agent_intent_log
                   )
                   GROUP BY key ORDER BY count DESC"""
            ),
            "by_intent": _count_rows(
                """SELECT COALESCE(intent, planner_intent, 'unknown') AS key, COUNT(*) AS count
                   FROM (
                     SELECT intent, NULL AS planner_intent FROM declare_intents
                     UNION ALL
                     SELECT NULL AS intent, planner_intent FROM agent_intent_log
                   )
                   GROUP BY key ORDER BY count DESC"""
            ),
            "findings_by_severity": _count_rows(
                """SELECT COALESCE(severity, 'unknown') AS key, COUNT(*) AS count
                   FROM findings GROUP BY key ORDER BY count DESC"""
            ),
            "incidents_by_severity": _count_rows(
                """SELECT COALESCE(severity, 'unknown') AS key, COUNT(*) AS count
                   FROM agent_intent_log GROUP BY key ORDER BY count DESC"""
            ),
            "by_mast_classification": _count_rows(
                """SELECT COALESCE(mast_classification, 'none') AS key, COUNT(*) AS count
                   FROM agent_intent_log GROUP BY key ORDER BY count DESC"""
            ),
        }

        # Use trained SICD model if available; fall back to heuristic
        _latest_sid = (active_sessions[0]["session_id"]
                       if active_sessions else None)
        import time as _time, asyncio as _asyncio
        _now = _time.time()
        if (_latest_sid and
                (_latest_sid != _sicd_cache["session"] or
                 _now - _sicd_cache["ts"] > 6)):
            try:
                _ge = engine
                _fresh = await _asyncio.to_thread(
                    _ge.get_sicd_score, _latest_sid, 30)
                _sicd_cache["score"]   = round(_fresh, 3)
                _sicd_cache["ts"]      = _now
                _sicd_cache["session"] = _latest_sid
            except Exception:
                high_crit = [i for i in incidents
                             if i.get("severity") in ("high", "critical")]
                _sicd_cache["score"] = round(
                    min(0.05 + len(high_crit) * 0.18, 0.99), 3)
                _sicd_cache["ts"]      = _now
                _sicd_cache["session"] = _latest_sid or ""
        divergence_score = _sicd_cache["score"] if _latest_sid else 0.05

        total_calls = 0
        if _latest_sid:
            try:
                with _get_conn() as conn:
                    total_calls = conn.execute(
                        "SELECT COUNT(*) FROM tool_audit_log WHERE session_id=?",
                        (_latest_sid,)
                    ).fetchone()[0]
            except Exception:
                pass

        # Per-session recent incidents and call rate for dashboard
        recent_incidents = []
        calls_last_60s = 0
        if _latest_sid:
            try:
                with _get_conn() as conn:
                    ri = conn.execute(
                        """SELECT mast_classification, severity,
                                  tool_name, agent_type,
                                  datetime(timestamp) as ts
                           FROM agent_intent_log
                           WHERE session_id=?
                           ORDER BY id DESC LIMIT 5""",
                        (_latest_sid,)
                    ).fetchall()
                    recent_incidents = [
                        {"mast_classification": r[0],
                         "severity": r[1],
                         "tool_name": r[2],
                         "agent_type": r[3],
                         "timestamp": r[4]}
                        for r in ri
                    ]
                    calls_last_60s = conn.execute(
                        """SELECT COUNT(*) FROM tool_audit_log
                           WHERE session_id=?
                           AND timestamp >= datetime('now', '-60 seconds')""",
                        (_latest_sid,)
                    ).fetchone()[0]
            except Exception:
                pass

        # ADK agent card status
        adk_cards = {}
        try:
            import sys as _sys
            _sys.path.insert(0, str(_PROJECT_ROOT))
            from core.opena2a import ADK_AGENTS, _load_card, SIGNING_KEY
            import hmac as _hmac, hashlib as _hs
            for name in list(ADK_AGENTS.keys()):
                try:
                    card = _load_card(name)
                    signed = False
                    if card is not None:
                        expected = _hmac.new(SIGNING_KEY,
                                             card["payload"].encode(),
                                             _hs.sha256).hexdigest()
                        signed = _hmac.compare_digest(
                            card.get("signature", ""), expected)
                    adk_cards[name] = {
                        "signed": signed,
                        "name": name,
                        "role": ADK_AGENTS[name].get("role", ""),
                        "framework": "secure-agent",
                        "model": "v9-model",
                    }
                except Exception:
                    adk_cards[name] = {
                        "signed": False,
                        "name": name,
                        "role": "",
                        "framework": "secure-agent",
                        "model": "v9-model",
                    }
        except Exception as _e:
            pass  # adk_cards stays empty dict — safe

        return {
            "service": "redteam-v9-sicd",
            "status": "ok",
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "session_id": _latest_sid,
            "divergence_score": divergence_score,
            "total_tool_calls": total_calls,
            "total_incidents": len(incidents),
            "calls_last_60s": calls_last_60s,
            "recent_incidents": recent_incidents,
            "active_sessions": active_sessions[:5],
            "active_declared_intents": active_intents,
            "recent_mast_incidents": incidents,
            "adk_cards": adk_cards,
            "summary": {"counts": summary["counts"]},
        }
    except Exception as e:
        raise HTTPException(500, str(e))

@app.get("/report/{session_id}")
async def get_report(session_id: str):
    """Download the HTML report for a session."""
    from fastapi.responses import JSONResponse
    reports_dir = _PROJECT_ROOT / "reports"
    report_file = reports_dir / f"{session_id}_report.html"
    if report_file.exists():
        return FileResponse(
            path=str(report_file),
            filename=f"{session_id}_report.html",
            media_type="text/html"
        )
    return JSONResponse(
        {"error": f"Report not found for {session_id}", "looked_in": str(report_file)},
        status_code=404
    )


@app.get("/findings/{session_id}")
async def get_findings(session_id: str):
    import sqlite3
    from core.graph_engine import DB_PATH
    try:
        conn = sqlite3.connect(DB_PATH)
        rows = conn.execute(
            """SELECT title, severity, endpoint, cvss,
                      evidence, remediation, attack_type
               FROM findings WHERE session_id=?
               ORDER BY rowid""",
            (session_id,)
        ).fetchall()
        conn.close()
        return {"findings": [
            {"title": r[0], "severity": r[1], "endpoint": r[2],
             "cvss": r[3], "evidence": r[4][:100] if r[4] else "",
             "attack_type": r[6]}
            for r in rows
        ]}
    except Exception as e:
        return {"findings": [], "error": str(e)}


@app.post("/inject_chaos", dependencies=[Depends(require_auth)])
async def inject_chaos(body: ChaosInject, request: Request):
    """Local-only synthetic SICD anomaly injection for dashboard validation."""
    if not _is_local_request(request):
        raise HTTPException(403, "inject_chaos is local-only")
    if not body.session_id.strip() or not body.test_id.strip():
        raise HTTPException(400, "session_id and test_id are required")

    session_id = body.session_id.strip()
    test_id = body.test_id.strip()
    synthetic = {
        "synthetic": True,
        "test_id": test_id,
        "source": "inject_chaos",
        "note": "dashboard validation only; no network traffic performed",
    }
    try:
        with _get_conn() as conn:
            conn.execute(
                """INSERT OR IGNORE INTO sessions
                   (session_id, target_url, goal, status, metadata)
                   VALUES (?,?,?,?,?)""",
                (
                    session_id,
                    "sicd://synthetic-local-test",
                    "Synthetic SICD dashboard validation",
                    "active",
                    json.dumps(synthetic),
                )
            )
            incident = conn.execute(
                """INSERT INTO agent_intent_log
                   (session_id, session_phase, agent_type, tool_name,
                    parameters_summary, planner_intent, mast_classification,
                    response_taken, severity)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (
                    session_id,
                    body.phase,
                    "sicd_test_harness",
                    "synthetic_chaos_probe",
                    json.dumps(synthetic),
                    body.intent,
                    body.mast_classification,
                    "synthetic_test_logged",
                    body.severity,
                )
            )
            conn.execute(
                """INSERT INTO tool_audit_log
                   (session_id, tool_name, parameters_summary, result_summary,
                    session_phase, planner_intent)
                   VALUES (?,?,?,?,?,?)""",
                (
                    session_id,
                    "inject_chaos",
                    json.dumps(synthetic),
                    "SYNTHETIC TEST DATA: no attack traffic performed",
                    body.phase,
                    body.intent,
                )
            )
            conn.commit()
            incident_id = incident.lastrowid
        return {
            "success": True,
            "synthetic": True,
            "session_id": session_id,
            "test_id": test_id,
            "incident_id": incident_id,
            "chaos_type": body.mast_classification,
            "mast_classification": body.mast_classification,
            "severity": body.severity,
            "message": "Synthetic SICD incident injected; no network traffic performed.",
        }
    except Exception as e:
        raise HTTPException(500, str(e))

@app.post("/emergency_disconnect")
async def emergency_disconnect():
    import subprocess
    script = str(_PROJECT_ROOT / "scripts" / "kill_executor.ps1")
    try:
        subprocess.Popen([
            "powershell", "-NoProfile",
            "-ExecutionPolicy", "Bypass",
            "-File", script
        ], creationflags=subprocess.CREATE_NEW_CONSOLE)
        return {"launched": True, "script": script}
    except Exception as e:
        return {"launched": False, "error": str(e)}


@app.post("/restore_mcp")
async def restore_mcp():
    import subprocess
    script = str(_PROJECT_ROOT / "DEMO_START.ps1")
    try:
        subprocess.Popen([
            "powershell", "-NoProfile",
            "-ExecutionPolicy", "Bypass",
            "-File", script
        ], creationflags=subprocess.CREATE_NEW_CONSOLE)
        return {"launched": True}
    except Exception as e:
        return {"launched": False, "error": str(e)}


@app.post("/revoke_adk_agent/{agent_name}")
async def revoke_adk_agent_endpoint(agent_name: str):
    try:
        from core.opena2a import revoke_adk_agent
        revoke_adk_agent(agent_name)
        return {"revoked": True, "agent": agent_name}
    except Exception as e:
        return {"revoked": False, "error": str(e)}


@app.post("/restore_adk_agents")
async def restore_adk_agents_endpoint():
    try:
        from core.opena2a import restore_adk_agents
        restore_adk_agents()
        return {"restored": True}
    except Exception as e:
        return {"restored": False, "error": str(e)}


@app.post("/session/create", dependencies=[Depends(require_auth)])
async def create_session(body: SessionCreate):
    try:
        node_id = engine.create_session(body.session_id, body.target_url, body.goal)
        return {"success": True, "node_id": node_id, "session_id": body.session_id}
    except Exception as e:
        raise HTTPException(500, str(e))

@app.post("/causal/set_branch", dependencies=[Depends(require_auth)])
async def set_branch(body: BranchSet):
    try:
        node_id = engine.set_branch(body.session_id, body.attack_type, body.description)
        mcts = get_or_create_mcts(body.session_id)
        thinking_id = engine.add_thinking_node(
            body.session_id,
            f"Hypothesis: explore {body.attack_type}",
            confidence=0.3, entropy=mcts.root.entropy, mcts_score=0.3,
            status="EXPLORING"
        )
        return {"success": True, "branch_node_id": node_id, "thinking_node_id": thinking_id}
    except Exception as e:
        raise HTTPException(500, str(e))

@app.post("/causal/add_node", dependencies=[Depends(require_auth)])
async def add_node(body: NodeAdd):
    try:
        node_id = engine.add_node(
            body.session_id, body.node_type, body.label,
            body.description, body.confidence, body.severity, body.metadata
        )
        return {"success": True, "node_id": node_id}
    except Exception as e:
        raise HTTPException(500, str(e))

@app.post("/causal/add_edge", dependencies=[Depends(require_auth)])
async def add_edge(body: EdgeAdd):
    try:
        engine.add_edge(body.session_id, body.source_id, body.target_id, body.label)
        return {"success": True}
    except Exception as e:
        raise HTTPException(500, str(e))

@app.post("/causal/log_reasoning", dependencies=[Depends(require_auth)])
async def log_reasoning(body: ReasoningLog):
    try:
        log_id = engine.log_reasoning(body.session_id, body.agent, body.step, body.content)
        return {"success": True, "log_id": log_id}
    except Exception as e:
        raise HTTPException(500, str(e))

@app.post("/causal/add_injection_point", dependencies=[Depends(require_auth)])
async def add_injection_point(body: InjectionPoint):
    try:
        ip_id = engine.add_injection_point(
            body.session_id, body.parameter, body.endpoint, body.method, body.context
        )
        mcts = get_or_create_mcts(body.session_id)
        mcts.backpropagate("sqli", 0.5, {"endpoint": body.endpoint, "param": body.parameter})
        return {"success": True, "ip_id": ip_id}
    except Exception as e:
        raise HTTPException(500, str(e))

@app.post("/causal/add_finding", dependencies=[Depends(require_auth)])
async def add_finding(body: Finding):
    try:
        finding_id = engine.add_finding(
            body.session_id, body.title, body.severity,
            body.endpoint, body.evidence, body.cvss, body.remediation
        )
        mcts = get_or_create_mcts(body.session_id)
        mcts.backpropagate("sqli", 1.0, {"title": body.title, "severity": body.severity})
        return {"success": True, "finding_id": finding_id}
    except Exception as e:
        raise HTTPException(500, str(e))

@app.post("/causal/distill_knowledge", dependencies=[Depends(require_auth)])
async def distill_knowledge(body: KnowledgeDistill):
    try:
        fact_id = engine.distill_knowledge(body.session_id, body.key_insight)
        return {"success": True, "fact_id": fact_id}
    except Exception as e:
        raise HTTPException(500, str(e))

@app.post("/score_branches", dependencies=[Depends(require_auth)])
async def score_branches(body: ScoreBranches):
    try:
        mcts = get_or_create_mcts(body.session_id)
        ranked = mcts.select(top_k=body.top_k)
        # Filter to requested candidates if provided
        if body.candidate_branches:
            ranked = [r for r in ranked if r["attack_type"] in body.candidate_branches]
        return {"success": True, "ranked_branches": ranked, "mcts_state": mcts.get_state()}
    except Exception as e:
        raise HTTPException(500, str(e))

@app.post("/fingerprint_update", dependencies=[Depends(require_auth)])
async def fingerprint_update(body: FingerprintUpdate):
    try:
        engine.set_fingerprint(body.session_id, body.fingerprint)
        mcts = get_or_create_mcts(body.session_id)
        mcts.apply_fingerprint_priors(body.fingerprint)
        return {"success": True}
    except Exception as e:
        raise HTTPException(500, str(e))

@app.get("/causal/graph_summary")
async def graph_summary(session_id: str):
    try:
        ctx = engine.get_session_context(session_id)
        return {"success": True, "summary": ctx}
    except Exception as e:
        raise HTTPException(500, str(e))

@app.get("/causal/attack_paths")
async def attack_paths(session_id: str, top_n: int = 5):
    ctx = engine.get_session_context(session_id)
    findings = ctx.get("findings", [])
    injection_points = ctx.get("injection_points", [])
    return {
        "success": True,
        "attack_paths": findings[:top_n],
        "injection_points": injection_points[:top_n],
    }

# DAG endpoints — read-only, NO auth required (sanitised output only)

@app.get("/dag/session_data")
async def dag_session_data(session_id: str):
    try:
        data = engine.get_dag_data(session_id)
        return data
    except Exception as e:
        raise HTTPException(500, str(e))

@app.get("/dag/sessions")
async def dag_sessions():
    sessions = engine.get_all_sessions()
    return {"sessions": sessions}

@app.get("/dag/mcts_state")
async def dag_mcts_state(session_id: str):
    mcts = get_or_create_mcts(session_id)
    return mcts.get_state()

@app.get("/cross_session_insights")
async def cross_session_insights(tech_stack: str = "", attack_type: str = ""):
    rows = get_all_insights(tech_stack, attack_type)
    return {"success": True, "insights": rows}

# Alias with /causal/ prefix for consistency
@app.get("/causal/cross_session_insights")
async def cross_session_insights_causal(tech_stack: str = "", attack_type: str = ""):
    rows = get_all_insights(tech_stack, attack_type)
    return {"success": True, "insights": rows}

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=6037, log_level="info")
