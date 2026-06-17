"""
OpenA2A Agent Identity Registry — Phase 4.
Issues signed agent cards, enforces per-agent capability boundaries,
and persists the registry to SQLite + disk.
"""
import hashlib
import hmac
import json
import pathlib
import sqlite3
import uuid
from datetime import datetime

from core.graph_engine import DB_PATH

CARDS_DIR = pathlib.Path(__file__).resolve().parent.parent / "agent_cards"
CARDS_DIR.mkdir(exist_ok=True)

SIGNING_KEY = b"redteam_v9_opena2a_signing_key_2026"
ORG = "hcltech-redteam-v9"
VERSION = "9.0.0"

# ── Agent capability manifests ────────────────────────────────────────────────

AGENT_MANIFEST = {
    "orchestrator": {
        "description": "Top-level engagement controller. Reads skills, creates sessions, routes phases.",
        "capabilities": [
            "create_session", "read_skill", "retrieve_knowledge",
            "get_cross_session_insights", "score_branches", "set_branch",
            "declare_intent", "get_intent_incidents", "select_skills",
            "distill_knowledge", "log_reasoning", "generate_report",
            "kill_all_scans", "get_session_context",
        ],
    },
    "planner": {
        "description": "BayesianMCTS attack planner. Scores branches and selects next attack vector.",
        "capabilities": [
            "score_branches", "set_branch", "declare_intent",
            "get_intent_incidents", "select_skills", "log_reasoning",
            "get_session_context", "get_cross_session_insights",
            "add_injection_point",
        ],
    },
    "executor": {
        "description": "Attack tool executor. Runs all active pentest tools against the target.",
        "capabilities": [
            "http_request", "fingerprint_target", "crawl_links",
            "enumerate_endpoints", "check_headers", "analyse_cookies",
            "test_sqli", "check_sqli_status", "get_sqli_results",
            "test_xss", "verify_xss_browser",
            "test_auth_bypass", "test_session_fixation",
            "test_idor", "test_csrf", "test_xpath_injection",
            "test_command_injection", "test_path_traversal",
            "run_nuclei_scan", "check_nuclei_status", "get_nuclei_results",
            "shell_exec", "add_finding", "add_injection_point",
            "log_reasoning",
        ],
    },
    "reflector": {
        "description": "Post-phase reflector. Reviews incidents, distils knowledge, triggers transfer.",
        "capabilities": [
            "get_intent_incidents", "get_session_context",
            "distill_knowledge", "log_reasoning",
            "get_cross_session_insights", "generate_report",
            "kill_all_scans",
        ],
    },
}

# ── SQLite helpers ────────────────────────────────────────────────────────────

def _ensure_table():
    with sqlite3.connect(str(DB_PATH)) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS agent_registry (
                id            TEXT PRIMARY KEY,
                agent_type    TEXT NOT NULL,
                org           TEXT NOT NULL,
                version       TEXT NOT NULL,
                capabilities  TEXT NOT NULL,
                card_path     TEXT NOT NULL,
                issued_at     TEXT NOT NULL,
                signature     TEXT NOT NULL
            )
        """)
        conn.commit()


def _sign(payload: str) -> str:
    return hmac.new(SIGNING_KEY, payload.encode(), hashlib.sha256).hexdigest()


# ── Public API ────────────────────────────────────────────────────────────────

def register_agent(agent_type: str) -> dict:
    """Issue and persist a signed agent card for one agent type."""
    if agent_type not in AGENT_MANIFEST:
        raise ValueError(f"Unknown agent type: {agent_type}")

    manifest = AGENT_MANIFEST[agent_type]
    card_id = str(uuid.uuid4())
    issued_at = datetime.utcnow().isoformat() + "Z"

    payload_obj = {
        "id": card_id,
        "agent_type": agent_type,
        "org": ORG,
        "version": VERSION,
        "description": manifest["description"],
        "capabilities": manifest["capabilities"],
        "issued_at": issued_at,
    }
    payload_str = json.dumps(payload_obj, separators=(",", ":"), sort_keys=True)
    signature = _sign(payload_str)

    card = {
        "payload": payload_str,
        "signature": signature,
    }

    card_path = CARDS_DIR / f"{agent_type}_card.json"
    card_path.write_text(json.dumps(card, indent=2))

    _ensure_table()
    with sqlite3.connect(str(DB_PATH)) as conn:
        conn.execute("DELETE FROM agent_registry WHERE agent_type=?", (agent_type,))
        conn.execute(
            """INSERT INTO agent_registry
               (id, agent_type, org, version, capabilities, card_path,
                issued_at, signature)
               VALUES (?,?,?,?,?,?,?,?)""",
            (
                card_id, agent_type, ORG, VERSION,
                json.dumps(manifest["capabilities"]),
                str(card_path), issued_at, signature,
            ),
        )
        conn.commit()

    return card


def register_all_agents() -> dict:
    """Register all 4 agents and return their cards."""
    return {agent: register_agent(agent) for agent in AGENT_MANIFEST}


def verify_card(agent_type: str) -> tuple:
    """Return (valid: bool, reason: str) for an agent's card."""
    card_path = CARDS_DIR / f"{agent_type}_card.json"
    if not card_path.exists():
        return False, f"No card file found for {agent_type}"
    try:
        card = json.loads(card_path.read_text())
        expected = _sign(card["payload"])
        if not hmac.compare_digest(card["signature"], expected):
            return False, "Signature mismatch"
        payload = json.loads(card["payload"])
        if payload.get("agent_type") != agent_type:
            return False, "Agent type mismatch in payload"
        return True, f"Card valid — issued {payload.get('issued_at','')}"
    except Exception as e:
        return False, f"Verification error: {e}"


def verify_intent_authorised(agent_type: str, tool_name: str) -> tuple:
    """Return (authorised: bool, reason: str) for an agent/tool pair."""
    if agent_type not in AGENT_MANIFEST:
        return False, f"Unknown agent: {agent_type}"
    allowed = AGENT_MANIFEST[agent_type]["capabilities"]
    if tool_name in allowed:
        return True, f"{agent_type} is authorised to call {tool_name}"
    return False, f"{agent_type} is NOT authorised to call {tool_name}"


def get_registry_status() -> dict:
    """Return status dict for all registered agents."""
    _ensure_table()
    status = {}
    with sqlite3.connect(str(DB_PATH)) as conn:
        rows = conn.execute(
            "SELECT agent_type, issued_at, version FROM agent_registry"
        ).fetchall()
    registered = {r[0]: {"issued_at": r[1], "version": r[2]} for r in rows}
    for agent in AGENT_MANIFEST:
        if agent in registered:
            valid, reason = verify_card(agent)
            status[agent] = {
                "status": "registered" if valid else "invalid",
                "issued_at": registered[agent]["issued_at"],
                "version": registered[agent]["version"],
                "reason": reason,
            }
        else:
            status[agent] = {"status": "unregistered", "reason": "no card"}
    return status


if __name__ == "__main__":
    print("Registering all agents...")
    cards = register_all_agents()
    print(f"Issued cards: {list(cards.keys())}")
    print()
    for agent in AGENT_MANIFEST:
        valid, reason = verify_card(agent)
        print(f"  {agent}: {'OK' if valid else 'FAIL'} — {reason}")
