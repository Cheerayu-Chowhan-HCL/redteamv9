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
sys.path.insert(0, "C:/users/chirayu/redteamv9")

from fastapi import FastAPI, HTTPException, Header, Depends, Request
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

# Bearer token auth (write endpoints only)
BEARER_TOKEN_FILE = "C:/Users/chirayu/redteamv9/.tmp/rtv9_bearer.txt"

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
def health():
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
def intent_status(limit: int = 25):
    """Read-only SICD dashboard state. Sanitised; no raw payload/evidence fields."""
    limit = max(1, min(limit, 100))
    try:
        sessions = _rows(
            """SELECT session_id, target_url, goal, status, created_at
               FROM sessions
               ORDER BY created_at DESC"""
        )
        active_sessions = [s for s in sessions if (s.get("status") or "active") == "active"]

        active_intents = _rows(
            """SELECT id, session_id, phase, intent, confidence, tools_authorised,
                      scope, rationale, created_at, active
               FROM declare_intents
               WHERE active=1
               ORDER BY created_at DESC"""
        )
        for item in active_intents:
            item["tools_authorised"] = _parse_tools(item.get("tools_authorised", "[]"))
            item["rationale"] = _safe_text(item.get("rationale"), 160)

        incidents = _rows(
            """SELECT id, timestamp, session_id, session_phase, agent_type, tool_name,
                      parameters_summary, planner_intent, declared_intent_id,
                      mast_classification, response_taken, severity
               FROM agent_intent_log
               WHERE mast_classification IS NOT NULL AND mast_classification != ''
               ORDER BY timestamp DESC
               LIMIT ?""",
            (limit,)
        )
        for item in incidents:
            item["parameters_summary"] = _safe_text(item.get("parameters_summary"), 180)

        audit_events = _rows(
            """SELECT id, timestamp, session_id, tool_name, parameters_summary,
                      result_summary, session_phase, planner_intent
               FROM tool_audit_log
               ORDER BY timestamp DESC
               LIMIT ?""",
            (limit,)
        )
        for item in audit_events:
            item["parameters_summary"] = _safe_text(item.get("parameters_summary"), 180)
            item["result_summary"] = _safe_text(item.get("result_summary"), 180)

        summary = {
            "counts": {
                "sessions_total": len(sessions),
                "sessions_active": len(active_sessions),
                "active_intents": len(active_intents),
                "recent_incidents": len(incidents),
                "recent_tool_events": len(audit_events),
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

        return {
            "service": "redteam-v9-sicd",
            "status": "ok",
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "active_sessions": active_sessions,
            "active_declared_intents": active_intents,
            "recent_mast_incidents": incidents,
            "recent_tool_audit_events": audit_events,
            "summary": summary,
        }
    except Exception as e:
        raise HTTPException(500, str(e))

@app.post("/inject_chaos", dependencies=[Depends(require_auth)])
def inject_chaos(body: ChaosInject, request: Request):
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
            "mast_classification": body.mast_classification,
            "severity": body.severity,
            "message": "Synthetic SICD incident injected; no network traffic performed.",
        }
    except Exception as e:
        raise HTTPException(500, str(e))

@app.post("/session/create", dependencies=[Depends(require_auth)])
def create_session(body: SessionCreate):
    try:
        node_id = engine.create_session(body.session_id, body.target_url, body.goal)
        return {"success": True, "node_id": node_id, "session_id": body.session_id}
    except Exception as e:
        raise HTTPException(500, str(e))

@app.post("/causal/set_branch", dependencies=[Depends(require_auth)])
def set_branch(body: BranchSet):
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
def add_node(body: NodeAdd):
    try:
        node_id = engine.add_node(
            body.session_id, body.node_type, body.label,
            body.description, body.confidence, body.severity, body.metadata
        )
        return {"success": True, "node_id": node_id}
    except Exception as e:
        raise HTTPException(500, str(e))

@app.post("/causal/add_edge", dependencies=[Depends(require_auth)])
def add_edge(body: EdgeAdd):
    try:
        engine.add_edge(body.session_id, body.source_id, body.target_id, body.label)
        return {"success": True}
    except Exception as e:
        raise HTTPException(500, str(e))

@app.post("/causal/log_reasoning", dependencies=[Depends(require_auth)])
def log_reasoning(body: ReasoningLog):
    try:
        log_id = engine.log_reasoning(body.session_id, body.agent, body.step, body.content)
        return {"success": True, "log_id": log_id}
    except Exception as e:
        raise HTTPException(500, str(e))

@app.post("/causal/add_injection_point", dependencies=[Depends(require_auth)])
def add_injection_point(body: InjectionPoint):
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
def add_finding(body: Finding):
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
def distill_knowledge(body: KnowledgeDistill):
    try:
        fact_id = engine.distill_knowledge(body.session_id, body.key_insight)
        return {"success": True, "fact_id": fact_id}
    except Exception as e:
        raise HTTPException(500, str(e))

@app.post("/score_branches", dependencies=[Depends(require_auth)])
def score_branches(body: ScoreBranches):
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
def fingerprint_update(body: FingerprintUpdate):
    try:
        engine.set_fingerprint(body.session_id, body.fingerprint)
        mcts = get_or_create_mcts(body.session_id)
        mcts.apply_fingerprint_priors(body.fingerprint)
        return {"success": True}
    except Exception as e:
        raise HTTPException(500, str(e))

@app.get("/causal/graph_summary")
def graph_summary(session_id: str):
    try:
        ctx = engine.get_session_context(session_id)
        return {"success": True, "summary": ctx}
    except Exception as e:
        raise HTTPException(500, str(e))

@app.get("/causal/attack_paths")
def attack_paths(session_id: str, top_n: int = 5):
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
def dag_session_data(session_id: str):
    try:
        data = engine.get_dag_data(session_id)
        return data
    except Exception as e:
        raise HTTPException(500, str(e))

@app.get("/dag/sessions")
def dag_sessions():
    sessions = engine.get_all_sessions()
    return {"sessions": sessions}

@app.get("/dag/mcts_state")
def dag_mcts_state(session_id: str):
    mcts = get_or_create_mcts(session_id)
    return mcts.get_state()

@app.get("/cross_session_insights")
def cross_session_insights(tech_stack: str = "", attack_type: str = ""):
    rows = get_all_insights(tech_stack, attack_type)
    return {"success": True, "insights": rows}

# Alias with /causal/ prefix for consistency
@app.get("/causal/cross_session_insights")
def cross_session_insights_causal(tech_stack: str = "", attack_type: str = ""):
    rows = get_all_insights(tech_stack, attack_type)
    return {"success": True, "insights": rows}

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=6037, log_level="info")
