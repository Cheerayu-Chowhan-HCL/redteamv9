"""
GraphEngine for RedTeam V9 — SQLite persistence + Neo4j sync.
All nodes MUST carry session_id. Cross-session queries only for transfer learning.
"""
import json
import logging
import sqlite3
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

DB_PATH = Path("C:/users/chirayu/redteamv9/redteamv9.db")

NEO4J_URI = "bolt://localhost:7687"
NEO4J_USER = "neo4j"
NEO4J_PASS = "redteam123"

_neo4j_driver = None
_neo4j_lock = threading.Lock()


def _get_neo4j():
    global _neo4j_driver
    with _neo4j_lock:
        if _neo4j_driver is None:
            try:
                from neo4j import GraphDatabase
                _neo4j_driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))
                logger.info("Neo4j connected")
            except Exception as e:
                logger.warning(f"Neo4j unavailable: {e}")
        return _neo4j_driver


def _get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def _neo4j_write_with_retry(write_fn, max_retries=3):
    """Execute a Neo4j write operation with exponential backoff retry."""
    import functools
    delays = [1, 2, 4]
    last_exc = None
    for attempt, delay in enumerate(delays[:max_retries], 1):
        try:
            return write_fn()
        except Exception as e:
            last_exc = e
            logger.warning(f"Neo4j write failed (attempt {attempt}/{max_retries}): {e}")
            if attempt < max_retries:
                time.sleep(delay)
    raise last_exc


class GraphEngine:
    """Thread-safe singleton graph engine."""

    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialised = False
            return cls._instance

    def __init__(self):
        if self._initialised:
            return
        self._initialised = True
        self._session_roots: Dict[str, str] = {}
        self._current_branch: Dict[str, str] = {}
        self._fingerprints: Dict[str, dict] = {}
        self._init_db()
        self._init_neo4j_indexes()
        logger.info("GraphEngine initialised")

    def _init_db(self):
        with _get_conn() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS sessions (
                    session_id TEXT PRIMARY KEY,
                    target_url TEXT,
                    goal TEXT,
                    status TEXT DEFAULT 'active',
                    created_at TEXT DEFAULT (datetime('now')),
                    metadata TEXT DEFAULT '{}'
                );
                CREATE TABLE IF NOT EXISTS causal_nodes (
                    node_id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    node_type TEXT NOT NULL,
                    label TEXT,
                    description TEXT,
                    confidence REAL DEFAULT 0.0,
                    severity TEXT DEFAULT 'info',
                    metadata TEXT DEFAULT '{}',
                    created_at TEXT DEFAULT (datetime('now'))
                );
                CREATE TABLE IF NOT EXISTS causal_edges (
                    edge_id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    source_id TEXT NOT NULL,
                    target_id TEXT NOT NULL,
                    label TEXT DEFAULT 'leads_to'
                );
                CREATE TABLE IF NOT EXISTS key_facts (
                    fact_id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    fact TEXT NOT NULL,
                    created_at TEXT DEFAULT (datetime('now'))
                );
                CREATE TABLE IF NOT EXISTS reasoning_log (
                    log_id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    agent TEXT,
                    step TEXT,
                    content TEXT,
                    created_at TEXT DEFAULT (datetime('now'))
                );
                CREATE TABLE IF NOT EXISTS injection_points (
                    ip_id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    parameter TEXT,
                    endpoint TEXT,
                    method TEXT,
                    context TEXT,
                    created_at TEXT DEFAULT (datetime('now'))
                );
                CREATE TABLE IF NOT EXISTS findings (
                    finding_id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    title TEXT,
                    severity TEXT,
                    endpoint TEXT,
                    evidence TEXT,
                    cvss TEXT,
                    remediation TEXT,
                    created_at TEXT DEFAULT (datetime('now'))
                );
                CREATE TABLE IF NOT EXISTS scan_jobs (
                    job_id TEXT PRIMARY KEY,
                    session_id TEXT,
                    tool TEXT,
                    status TEXT DEFAULT 'running',
                    pid INTEGER,
                    command TEXT,
                    result TEXT,
                    created_at TEXT DEFAULT (datetime('now'))
                );
                CREATE TABLE IF NOT EXISTS thinking_nodes (
                    node_id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    thought_text TEXT,
                    confidence REAL DEFAULT 0.0,
                    entropy REAL DEFAULT 1.0,
                    mcts_score REAL DEFAULT 0.0,
                    status TEXT DEFAULT 'EXPLORING',
                    created_at TEXT DEFAULT (datetime('now'))
                );
                CREATE TABLE IF NOT EXISTS agent_intent_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT DEFAULT (datetime('now')),
                    session_id TEXT NOT NULL,
                    session_phase TEXT,
                    agent_type TEXT,
                    tool_name TEXT NOT NULL,
                    parameters_summary TEXT,
                    planner_intent TEXT,
                    declared_intent_id TEXT,
                    divergence_score REAL,
                    mast_classification TEXT,
                    response_taken TEXT DEFAULT 'log',
                    severity TEXT DEFAULT 'low'
                );
                CREATE TABLE IF NOT EXISTS declare_intents (
                    id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    phase TEXT NOT NULL,
                    intent TEXT NOT NULL,
                    confidence REAL DEFAULT 0.0,
                    tools_authorised TEXT NOT NULL,
                    scope TEXT NOT NULL,
                    rationale TEXT,
                    created_at TEXT DEFAULT (datetime('now')),
                    active INTEGER DEFAULT 1
                );
                CREATE TABLE IF NOT EXISTS tool_audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT DEFAULT (datetime('now')),
                    session_id TEXT,
                    tool_name TEXT NOT NULL,
                    parameters_summary TEXT,
                    result_summary TEXT,
                    session_phase TEXT,
                    planner_intent TEXT
                );
            """)
            conn.commit()

    def _init_neo4j_indexes(self):
        driver = _get_neo4j()
        if not driver:
            return
        try:
            with driver.session() as s:
                s.run("CREATE INDEX session_idx IF NOT EXISTS FOR (n:Session) ON (n.session_id)")
                s.run("CREATE INDEX branch_idx IF NOT EXISTS FOR (n:AttackBranch) ON (n.session_id)")
                logger.info("Neo4j indexes created")
        except Exception as e:
            logger.warning(f"Neo4j index creation failed: {e}")

    # --- Session -----------------------------------------------------------

    def create_session(self, session_id: str, target_url: str, goal: str) -> str:
        node_id = f"session_{session_id}"
        with _get_conn() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO sessions (session_id, target_url, goal) VALUES (?,?,?)",
                (session_id, target_url, goal)
            )
            conn.execute(
                """INSERT OR REPLACE INTO causal_nodes
                   (node_id, session_id, node_type, label, description, confidence)
                   VALUES (?,?,?,?,?,?)""",
                (node_id, session_id, "SessionRoot",
                 f"Session: {session_id}", f"Target: {target_url} | Goal: {goal}", 1.0)
            )
            conn.commit()
        self._session_roots[session_id] = node_id
        self._neo4j_create_node(session_id, node_id, "Session", {
            "session_id": session_id, "target_url": target_url, "goal": goal
        })
        # Auto-create phase_0 AttackBranch so pre-set_branch Evidence/Fingerprint
        # nodes always have a parent — eliminates orphans from early recon tools.
        branch_node_id = f"branch_{session_id}_phase_0"
        with _get_conn() as conn:
            conn.execute(
                """INSERT OR IGNORE INTO causal_nodes
                   (node_id, session_id, node_type, label, description, confidence)
                   VALUES (?,?,?,?,?,?)""",
                (branch_node_id, session_id, "AttackBranch", "phase_0",
                 "Auto-created recon branch — holds nodes logged before first set_branch()", 1.0)
            )
            conn.commit()
        self._current_branch[session_id] = branch_node_id
        self._neo4j_create_node(session_id, branch_node_id, "AttackBranch", {
            "session_id": session_id, "attack_type": "phase_0",
            "description": "Auto-created phase_0 branch"
        })
        self.add_edge(session_id, node_id, branch_node_id, "HAS_BRANCH")
        return node_id

    def set_branch(self, session_id: str, attack_type: str, description: str) -> str:
        node_id = f"branch_{session_id}_{attack_type}_{uuid.uuid4().hex[:6]}"
        with _get_conn() as conn:
            conn.execute(
                """INSERT INTO causal_nodes (node_id, session_id, node_type, label, description)
                   VALUES (?,?,?,?,?)""",
                (node_id, session_id, "AttackBranch", attack_type, description)
            )
            conn.commit()
        self._current_branch[session_id] = node_id
        # Create Neo4j node BEFORE edge so MATCH can find both endpoints
        self._neo4j_create_node(session_id, node_id, "AttackBranch", {
            "session_id": session_id, "attack_type": attack_type, "description": description
        })
        root = self._session_roots.get(session_id)
        if root:
            self.add_edge(session_id, root, node_id, "HAS_BRANCH")
        return node_id

    def add_node(self, session_id: str, node_type: str, label: str,
                 description: str, confidence: float = 0.0,
                 severity: str = "info", metadata: dict = None,
                 branch_id: Optional[str] = None) -> str:
        node_id = f"node_{uuid.uuid4().hex}"
        meta_str = json.dumps(metadata or {})
        with _get_conn() as conn:
            conn.execute(
                """INSERT INTO causal_nodes
                   (node_id, session_id, node_type, label, description, confidence, severity, metadata)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (node_id, session_id, node_type, label, description, confidence, severity, meta_str)
            )
            conn.commit()
        # Create Neo4j node BEFORE edge so MATCH can find both endpoints
        self._neo4j_create_node(session_id, node_id, node_type, {
            "session_id": session_id, "label": label,
            "description": description[:500], "confidence": confidence
        })
        self._auto_edge(session_id, node_id, node_type, branch_id=branch_id)
        return node_id

    def add_edge(self, session_id: str, source_id: str, target_id: str, label: str = "leads_to"):
        edge_id = f"edge_{uuid.uuid4().hex}"
        with _get_conn() as conn:
            conn.execute(
                "INSERT INTO causal_edges (edge_id, session_id, source_id, target_id, label) VALUES (?,?,?,?,?)",
                (edge_id, session_id, source_id, target_id, label)
            )
            conn.commit()
        driver = _get_neo4j()
        if driver:
            try:
                cypher = (
                    f"MATCH (a {{node_id: $src}}), (b {{node_id: $tgt}}) "
                    f"MERGE (a)-[:{label}]->(b)"
                )
                with driver.session() as s:
                    _neo4j_write_with_retry(
                        lambda: s.run(cypher, src=source_id, tgt=target_id)
                    )
            except Exception as e:
                logger.debug(f"Neo4j edge failed: {e}")

    def _recover_branch(self, session_id: str) -> Optional[str]:
        """Recover _current_branch from SQLite after server restart (orphan-node fix)."""
        try:
            with _get_conn() as conn:
                row = conn.execute(
                    "SELECT node_id FROM causal_nodes "
                    "WHERE session_id=? AND node_type='AttackBranch' "
                    "ORDER BY created_at DESC LIMIT 1",
                    (session_id,)
                ).fetchone()
            if row:
                self._current_branch[session_id] = row["node_id"]
                return row["node_id"]
        except Exception as e:
            logger.debug(f"Branch recovery failed: {e}")
        return None

    def _auto_edge(self, session_id: str, child_node_id: str, node_type: str,
                   branch_id: Optional[str] = None):
        """Create edge from active branch ? child.
        branch_id: explicit override — use this when running as a parallel subtask
                   to avoid _current_branch race conditions. Falls back to
                   _current_branch singleton (recovered from DB if empty).
        """
        effective_branch = branch_id or self._current_branch.get(session_id) or self._recover_branch(session_id)
        if not effective_branch:
            logger.warning(f"_auto_edge: no active branch for {session_id}, node {child_node_id} will be orphan")
            return
        label = "HAS_FINDING" if node_type == "ConfirmedVulnerability" else "HAS_ATTEMPT"
        self.add_edge(session_id, effective_branch, child_node_id, label)

    def log_reasoning(self, session_id: str, agent: str, step: str, content: str) -> str:
        log_id = f"log_{uuid.uuid4().hex}"
        with _get_conn() as conn:
            conn.execute(
                "INSERT INTO reasoning_log (log_id, session_id, agent, step, content) VALUES (?,?,?,?,?)",
                (log_id, session_id, agent, step, content)
            )
            conn.commit()
        return log_id

    def add_injection_point(self, session_id: str, parameter: str, endpoint: str,
                             method: str, context: str) -> str:
        ip_id = f"ip_{uuid.uuid4().hex}"
        with _get_conn() as conn:
            conn.execute(
                """INSERT INTO injection_points
                   (ip_id, session_id, parameter, endpoint, method, context)
                   VALUES (?,?,?,?,?,?)""",
                (ip_id, session_id, parameter, endpoint, method, context)
            )
            conn.commit()
        self.add_node(session_id, "InjectionPoint", f"Injectable: {parameter} @ {endpoint}",
                      f"Method: {method} | Context: {context}", confidence=0.5)
        return ip_id

    def add_finding(self, session_id: str, title: str, severity: str, endpoint: str,
                    evidence: str, cvss: str, remediation: str,
                    branch_id: Optional[str] = None) -> str:
        # branch_id: explicit branch for parallel-agent attribution.
        # When provided, findings are attributed to this specific branch instead of
        # _current_branch, eliminating race conditions in parallel subtask execution.
        # -- Semantic dedup: 60% token overlap ? same finding ------------------
        def _similar(a: str, b: str) -> bool:
            ta = set(a.lower().split())
            tb = set(b.lower().split())
            if not ta or not tb:
                return False
            return len(ta & tb) / len(ta | tb) > 0.6

        with _get_conn() as conn:
            existing = conn.execute(
                "SELECT finding_id, title, evidence FROM findings WHERE session_id=?",
                (session_id,)
            ).fetchall()

        for ex in existing:
            if _similar(title, ex["title"]):
                # Update evidence if the new one is richer; either way skip duplicate
                if len(str(evidence)) > len(str(ex["evidence"] or "")):
                    with _get_conn() as conn:
                        conn.execute(
                            "UPDATE findings SET evidence=?, cvss=? WHERE finding_id=?",
                            (str(evidence)[:2000], cvss, ex["finding_id"])
                        )
                        conn.commit()
                logger.debug(f"add_finding dedup: '{title}' ~ '{ex['title']}' — skipped")
                return ex["finding_id"]
        # ---------------------------------------------------------------------
        finding_id = f"finding_{uuid.uuid4().hex}"
        with _get_conn() as conn:
            conn.execute(
                """INSERT INTO findings
                   (finding_id, session_id, title, severity, endpoint, evidence, cvss, remediation)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (finding_id, session_id, title, severity, endpoint, evidence, cvss, remediation)
            )
            conn.commit()
        self.add_node(session_id, "ConfirmedVulnerability", title,
                      f"Severity: {severity} | Endpoint: {endpoint}", confidence=1.0,
                      severity=severity, branch_id=branch_id)
        return finding_id

    def distill_knowledge(self, session_id: str, key_insight: str) -> str:
        fact_id = f"fact_{uuid.uuid4().hex}"
        with _get_conn() as conn:
            conn.execute(
                "INSERT INTO key_facts (fact_id, session_id, fact) VALUES (?,?,?)",
                (fact_id, session_id, key_insight)
            )
            conn.commit()
        return fact_id

    def get_session_context(self, session_id: str) -> dict:
        with _get_conn() as conn:
            session = conn.execute(
                "SELECT * FROM sessions WHERE session_id = ?", (session_id,)
            ).fetchone()
            if not session:
                return {"error": f"Session {session_id} not found"}

            nodes = conn.execute(
                "SELECT node_type, label, description, confidence, severity FROM causal_nodes "
                "WHERE session_id = ? ORDER BY created_at DESC LIMIT 50",
                (session_id,)
            ).fetchall()

            findings = conn.execute(
                "SELECT title, severity, endpoint, cvss FROM findings WHERE session_id = ?",
                (session_id,)
            ).fetchall()

            injection_points = conn.execute(
                "SELECT parameter, endpoint, method FROM injection_points WHERE session_id = ?",
                (session_id,)
            ).fetchall()

            facts = conn.execute(
                "SELECT fact FROM key_facts WHERE session_id = ? ORDER BY created_at DESC LIMIT 20",
                (session_id,)
            ).fetchall()

            reasoning = conn.execute(
                "SELECT agent, step, content, created_at FROM reasoning_log "
                "WHERE session_id = ? ORDER BY created_at DESC LIMIT 10",
                (session_id,)
            ).fetchall()

        return {
            "session_id": session_id,
            "target_url": session["target_url"],
            "goal": session["goal"],
            "status": session["status"],
            "node_count": len(nodes),
            "findings": [dict(f) for f in findings],
            "injection_points": [dict(i) for i in injection_points],
            "key_facts": [f["fact"] for f in facts],
            "recent_reasoning": [dict(r) for r in reasoning],
            "attack_branches": [dict(n) for n in nodes if n["node_type"] == "AttackBranch"],
        }

    def get_dag_data(self, session_id: str) -> dict:
        with _get_conn() as conn:
            nodes = conn.execute(
                "SELECT node_id, node_type, label, description, confidence, severity "
                "FROM causal_nodes WHERE session_id = ?",
                (session_id,)
            ).fetchall()
            edges = conn.execute(
                "SELECT source_id AS source, target_id AS target, label AS type "
                "FROM causal_edges WHERE session_id = ?",
                (session_id,)
            ).fetchall()
            thinking = conn.execute(
                "SELECT node_id, thought_text, confidence, entropy, mcts_score, status, created_at "
                "FROM thinking_nodes WHERE session_id = ? ORDER BY created_at",
                (session_id,)
            ).fetchall()
            reasoning = conn.execute(
                "SELECT log_id, agent, step, content, created_at FROM reasoning_log "
                "WHERE session_id = ? ORDER BY created_at DESC LIMIT 50",
                (session_id,)
            ).fetchall()
            facts = conn.execute(
                "SELECT fact FROM key_facts WHERE session_id = ? ORDER BY created_at DESC LIMIT 20",
                (session_id,)
            ).fetchall()
            db_findings = conn.execute(
                "SELECT title, severity, endpoint, cvss, evidence FROM findings "
                "WHERE session_id = ? ORDER BY created_at DESC",
                (session_id,)
            ).fetchall()

        from .dag_sanitiser import DagSanitiser
        safe_nodes = [DagSanitiser.sanitise_node(dict(n)) for n in nodes]
        safe_thinking = [DagSanitiser.sanitise_node(dict(t)) for t in thinking]

        # Generate sequential edges between thinking nodes (ordered by created_at)
        thinking_edges = []
        for i in range(1, len(safe_thinking)):
            thinking_edges.append({
                "source": safe_thinking[i - 1]["node_id"],
                "target": safe_thinking[i]["node_id"],
                "type": "leads_to"
            })

        return {
            "session_id": session_id,
            "attack_dag": {
                "nodes": safe_nodes,
                "edges": [dict(e) for e in edges],
            },
            "thinking_dag": {
                "nodes": safe_thinking,
                "edges": thinking_edges,
            },
            "reasoning_log": [dict(r) for r in reasoning],
            "key_facts": [f["fact"] for f in facts],
            "findings": [dict(f) for f in db_findings],
        }

    def add_thinking_node(self, session_id: str, thought_text: str,
                          confidence: float, entropy: float, mcts_score: float,
                          status: str = "EXPLORING") -> str:
        node_id = f"think_{uuid.uuid4().hex}"
        from .dag_sanitiser import DagSanitiser
        safe_text = DagSanitiser.sanitise_string(thought_text)
        with _get_conn() as conn:
            conn.execute(
                """INSERT INTO thinking_nodes
                   (node_id, session_id, thought_text, confidence, entropy, mcts_score, status)
                   VALUES (?,?,?,?,?,?,?)""",
                (node_id, session_id, safe_text, confidence, entropy, mcts_score, status)
            )
            conn.commit()
        # Write HAS_THOUGHT to SQLite causal_edges so the DAG query includes it
        _thought_root = self._session_roots.get(session_id) or f"session_{session_id}"
        _thought_edge_id = f"edge_{uuid.uuid4().hex}"
        with _get_conn() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO causal_edges "
                "(edge_id, session_id, source_id, target_id, label) VALUES (?,?,?,?,?)",
                (_thought_edge_id, session_id, _thought_root, node_id, "HAS_THOUGHT")
            )
            conn.commit()
        self._neo4j_create_node(session_id, node_id, "ThinkingNode", {
            "session_id": session_id, "thought_text": safe_text[:200],
            "confidence": confidence, "entropy": entropy,
            "mcts_score": mcts_score, "status": status,
        })
        # Write HAS_THOUGHT relationship from session root in Neo4j
        root_id = self._session_roots.get(session_id)
        if root_id:
            self._neo4j_create_relationship(root_id, node_id, "HAS_THOUGHT",
                                            {"confidence": confidence, "status": status})
        return node_id

    def get_all_sessions(self) -> List[dict]:
        with _get_conn() as conn:
            rows = conn.execute("SELECT * FROM sessions ORDER BY created_at DESC").fetchall()
        return [dict(r) for r in rows]

    def get_findings(self, session_id: str) -> List[dict]:
        with _get_conn() as conn:
            rows = conn.execute(
                "SELECT * FROM findings WHERE session_id = ? ORDER BY created_at DESC",
                (session_id,)
            ).fetchall()
        return [dict(r) for r in rows]

    def get_reasoning_log(self, session_id: str) -> List[dict]:
        with _get_conn() as conn:
            rows = conn.execute(
                "SELECT * FROM reasoning_log WHERE session_id = ? ORDER BY created_at",
                (session_id,)
            ).fetchall()
        return [dict(r) for r in rows]

    def create_scan_job(self, tool: str, session_id: str, command: str,
                        pid: int, job_id: str = None) -> str:
        if job_id is None:
            job_id = f"job_{uuid.uuid4().hex}"
        with _get_conn() as conn:
            conn.execute(
                "INSERT INTO scan_jobs (job_id, session_id, tool, command, pid) VALUES (?,?,?,?,?)",
                (job_id, session_id, tool, command, pid)
            )
            conn.commit()
        return job_id

    def log_intent_event(self, session_id: str, tool_name: str,
                         session_phase: str = None, agent_type: str = None,
                         parameters_summary: str = None,
                         planner_intent: str = None,
                         declared_intent_id: str = None,
                         mast_classification: str = None,
                         response_taken: str = 'log',
                         severity: str = 'low') -> int:
        with _get_conn() as conn:
            cur = conn.execute(
                """INSERT INTO agent_intent_log
                   (session_id, tool_name, session_phase, agent_type,
                    parameters_summary, planner_intent, declared_intent_id,
                    mast_classification, response_taken, severity)
                   VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (session_id, tool_name, session_phase, agent_type,
                 parameters_summary, planner_intent, declared_intent_id,
                 mast_classification, response_taken, severity)
            )
            conn.commit()
            return cur.lastrowid

    def get_intent_incidents(self, session_id: str,
                             severity: str = None) -> list:
        with _get_conn() as conn:
            if severity:
                rows = conn.execute(
                    """SELECT * FROM agent_intent_log
                       WHERE session_id=? AND severity=?
                       ORDER BY timestamp DESC""",
                    (session_id, severity)
                ).fetchall()
            else:
                rows = conn.execute(
                    """SELECT * FROM agent_intent_log
                       WHERE session_id=?
                       ORDER BY timestamp DESC""",
                    (session_id,)
                ).fetchall()
            cols = [d[0] for d in conn.execute(
                "SELECT * FROM agent_intent_log LIMIT 0"
            ).description or []]
            return [dict(zip(cols, r)) for r in rows]

    def create_declared_intent(self, intent_id: str, session_id: str,
                                phase: str, intent: str, confidence: float,
                                tools_authorised: list, scope: str,
                                rationale: str = '') -> str:
        import json
        with _get_conn() as conn:
            conn.execute(
                "UPDATE declare_intents SET active=0 WHERE session_id=?",
                (session_id,)
            )
            conn.execute(
                """INSERT INTO declare_intents
                   (id, session_id, phase, intent, confidence,
                    tools_authorised, scope, rationale)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (intent_id, session_id, phase, intent, confidence,
                 json.dumps(tools_authorised), scope, rationale)
            )
            conn.commit()
        return intent_id

    def get_active_intent(self, session_id: str) -> dict | None:
        import json
        with _get_conn() as conn:
            row = conn.execute(
                """SELECT * FROM declare_intents
                   WHERE session_id=? AND active=1
                   ORDER BY created_at DESC LIMIT 1""",
                (session_id,)
            ).fetchone()
            if not row:
                return None
            cols = [d[0] for d in conn.execute(
                "SELECT * FROM declare_intents LIMIT 0"
            ).description or []]
            d = dict(zip(cols, row))
            d['tools_authorised'] = json.loads(d['tools_authorised'])
            return d

    def get_scan_job(self, job_id: str) -> Optional[dict]:
        with _get_conn() as conn:
            row = conn.execute("SELECT * FROM scan_jobs WHERE job_id = ?", (job_id,)).fetchone()
        return dict(row) if row else None

    def update_scan_job(self, job_id: str, status: str, result: str = None):
        with _get_conn() as conn:
            if result:
                conn.execute("UPDATE scan_jobs SET status=?, result=? WHERE job_id=?",
                             (status, result, job_id))
            else:
                conn.execute("UPDATE scan_jobs SET status=? WHERE job_id=?", (status, job_id))
            conn.commit()

    def _neo4j_create_node(self, session_id: str, node_id: str, label: str, props: dict):
        driver = _get_neo4j()
        if not driver:
            return
        try:
            props["node_id"] = node_id
            cypher = f"MERGE (n:{label} {{node_id: $node_id}}) SET n += $props"
            with driver.session() as s:
                _neo4j_write_with_retry(lambda: s.run(cypher, node_id=node_id, props=props))
        except Exception as e:
            logger.debug(f"Neo4j node create failed: {e}")

    def _neo4j_create_relationship(self, from_id: str, to_id: str, rel_type: str, props: dict = None):
        """Write a typed relationship between two existing Neo4j nodes."""
        driver = _get_neo4j()
        if not driver:
            return
        try:
            cypher = (
                f"MATCH (a {{node_id: $fid}}), (b {{node_id: $tid}}) "
                f"MERGE (a)-[r:{rel_type}]->(b) SET r += $props"
            )
            _props = props or {}
            with driver.session() as s:
                _neo4j_write_with_retry(
                    lambda: s.run(cypher, fid=from_id, tid=to_id, props=_props)
                )
        except Exception as e:
            logger.debug(f"Neo4j relationship {rel_type} failed: {e}")

    def set_fingerprint(self, session_id: str, fingerprint: dict):
        self._fingerprints[session_id] = fingerprint

    def get_fingerprint(self, session_id: str) -> dict:
        return self._fingerprints.get(session_id, {})
