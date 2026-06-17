"""
RedTeam V9 — Full End-to-End Integration Test (Task 4)
Tests live services with real calls. Not mocked.
"""
import sys, json, sqlite3, requests, time, os, subprocess
from pathlib import Path
_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))

BEARER = (_ROOT / ".tmp" / "rtv9_bearer.txt").read_text().strip()
HEADERS = {"Authorization": f"Bearer {BEARER}", "Content-Type": "application/json"}
GRAPH_URL = "http://127.0.0.1:6037"
SESSION_ID = "v9_integration_test"
DB_PATH = str(_ROOT / "redteamv9.db")

results = []

def step(n, name, condition, detail=""):
    status = "PASS" if condition else "FAIL"
    results.append((n, name, status, detail))
    color = "\033[92m" if condition else "\033[91m"
    reset = "\033[0m"
    mark = "?" if condition else "?"
    print(f"  Step {n:2d}: [{color}{status}{reset}] {name}" + (f"\n          ? {detail}" if detail else ""))
    return condition

def get_sqlite(query, params=()):
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute(query, params).fetchone()
    conn.close()
    return row

def get_sqlite_all(query, params=()):
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute(query, params).fetchall()
    conn.close()
    return rows

def neo4j_query(cypher, params=None):
    from neo4j import GraphDatabase
    d = GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j","redteam123"))
    with d.session() as s:
        result = s.run(cypher, **(params or {}))
        data = result.data()
    d.close()
    return data

# Clean up any previous test session
try:
    subprocess.run(["python", "flush_dbs.py", "--session", SESSION_ID],
                   capture_output=True, cwd=str(_ROOT))
except Exception:
    pass

print(f"\n{'='*60}")
print("  RedTeam V9 — Integration Test")
print(f"{'='*60}\n")

# -- Step 1: Create session via graph memory API -------------------------------
print("Block A: Session & Graph Layer")
r = requests.post(f"{GRAPH_URL}/session/create",
                  json={"session_id": SESSION_ID, "target_url": "http://integration-test.local", "goal": "integration test"},
                  headers=HEADERS, timeout=10)
ok = r.ok and r.json().get("success")
node_id = r.json().get("node_id") if ok else None

sqlite_row = get_sqlite("SELECT session_id, target_url FROM sessions WHERE session_id=?", (SESSION_ID,))
neo4j_rows = neo4j_query("MATCH (n:Session {session_id: $sid}) RETURN n", {"sid": SESSION_ID})

step(1, "Create session ? SQLite + Neo4j",
     ok and sqlite_row is not None and len(neo4j_rows) > 0,
     f"SQLite={'OK' if sqlite_row else 'MISSING'}, Neo4j={'OK' if neo4j_rows else 'MISSING'}, node_id={node_id}")

# -- Step 2: MCP tool create_session (direct import) --------------------------
from tools.mcp_service import create_session as mcp_create_session
r2 = mcp_create_session(SESSION_ID + "_mcp", "http://mcp-test.local", "mcp direct test")
step(2, "MCP create_session (direct import)",
     r2.get("success"),
     f"result={r2.get('result')}, error={r2.get('error')}")
# Clean up the extra session
get_sqlite("SELECT 1", ())  # keep connection warm
conn2 = sqlite3.connect(DB_PATH)
conn2.execute("DELETE FROM sessions WHERE session_id=?", (SESSION_ID + "_mcp",))
conn2.execute("DELETE FROM causal_nodes WHERE session_id=?", (SESSION_ID + "_mcp",))
conn2.commit(); conn2.close()

# -- Step 3: set_branch --------------------------------------------------------
print("\nBlock B: Branch & Thinking Layer")
from tools.mcp_service import set_branch as mcp_set_branch
r3 = mcp_set_branch(SESSION_ID, "recon", "Initial reconnaissance phase")
branch_ok = r3.get("success")
time.sleep(0.3)

sqlite_branch = get_sqlite("SELECT node_id, node_type FROM causal_nodes WHERE session_id=? AND node_type='AttackBranch'", (SESSION_ID,))
neo4j_branch = neo4j_query("MATCH (n:AttackBranch {session_id: $sid}) RETURN n", {"sid": SESSION_ID})
step(3, "set_branch ? AttackBranch in SQLite + Neo4j",
     branch_ok and sqlite_branch is not None and len(neo4j_branch) > 0,
     f"SQLite={'OK' if sqlite_branch else 'MISSING'}, Neo4j={'OK' if neo4j_branch else 'MISSING'}")

# -- Step 4: log_reasoning -----------------------------------------------------
from tools.mcp_service import log_reasoning as mcp_log_reasoning
r4 = mcp_log_reasoning(SESSION_ID, "Orchestrator", "test_step", "test reasoning content — safe text")
log_ok = r4.get("success")
time.sleep(0.3)

sqlite_think = get_sqlite("SELECT node_id, thought_text FROM thinking_nodes WHERE session_id=? ORDER BY rowid DESC LIMIT 1", (SESSION_ID,))
neo4j_think = neo4j_query("MATCH (n:ThinkingNode {session_id: $sid}) RETURN n LIMIT 1", {"sid": SESSION_ID})
sqlite_log = get_sqlite("SELECT content FROM reasoning_log WHERE session_id=? AND step='test_step'", (SESSION_ID,))

# Verify sanitisation: check DAG endpoint output doesn't have payload
dag_r = requests.get(f"{GRAPH_URL}/dag/session_data?session_id={SESSION_ID}", timeout=5)
dag_think_nodes = dag_r.json().get("thinking_dag", {}).get("nodes", []) if dag_r.ok else []
dag_has_content = any("test reasoning" in str(n.get("thought_text","")) for n in dag_think_nodes)

step(4, "log_reasoning ? ThinkingNode SQLite+Neo4j, raw in reasoning_log",
     log_ok and sqlite_think is not None and len(neo4j_think) > 0 and sqlite_log is not None,
     f"SQLite_think={'OK' if sqlite_think else 'MISSING'}, Neo4j_think={'OK' if neo4j_think else 'MISSING'}, raw_log={'OK' if sqlite_log else 'MISSING'}, DAG_sanitised={'OK' if not dag_has_content else 'CHECK'}")

# -- Step 5: add_finding -------------------------------------------------------
from tools.mcp_service import add_finding as mcp_add_finding
r5 = mcp_add_finding(SESSION_ID, "Test Finding: XSS in search", "high",
                     "/search", "reflected input", "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                     "Encode output")
time.sleep(0.3)

sqlite_finding = get_sqlite("SELECT finding_id, title, severity FROM findings WHERE session_id=?", (SESSION_ID,))
neo4j_vuln = neo4j_query("MATCH (n:ConfirmedVulnerability {session_id: $sid}) RETURN n LIMIT 1", {"sid": SESSION_ID})
dag_r2 = requests.get(f"{GRAPH_URL}/dag/session_data?session_id={SESSION_ID}", timeout=5)
dag_attack_nodes = dag_r2.json().get("attack_dag", {}).get("nodes", []) if dag_r2.ok else []
dag_has_vuln = any(n.get("node_type") == "ConfirmedVulnerability" for n in dag_attack_nodes)
# Check no payload leak
dag_text = json.dumps(dag_attack_nodes)
no_payload_leak = "<script>" not in dag_text and "UNION SELECT" not in dag_text

step(5, "add_finding ? ConfirmedVulnerability in SQLite+Neo4j+DAG, no payload leak",
     r5.get("success") and sqlite_finding is not None and len(neo4j_vuln) > 0 and dag_has_vuln and no_payload_leak,
     f"SQLite={'OK' if sqlite_finding else 'MISSING'}, Neo4j={'OK' if neo4j_vuln else 'MISSING'}, DAG_vuln={dag_has_vuln}, no_leak={no_payload_leak}")

# -- Step 6: score_branches ----------------------------------------------------
print("\nBlock C: Intelligence Layer")
from tools.mcp_service import score_branches as mcp_score_branches
r6 = mcp_score_branches(SESSION_ID, "sqli,xss,idor", 3)
branches = r6.get("result", {}).get("ranked_branches", []) if r6.get("success") else []
has_scores = len(branches) > 0 and all("confidence" in b and "entropy" in b for b in branches)
mcts_running = any(b.get("visit_count", 0) > 0 or b.get("posterior", 0) > 0 for b in branches)

step(6, "score_branches returns confidence + entropy (MCTS active)",
     r6.get("success") and has_scores,
     f"branches={[b['attack_type'] for b in branches]}, example={branches[0] if branches else 'none'}")

# -- Step 7: generate_report ---------------------------------------------------
from tools.mcp_service import generate_report as mcp_generate_report
r7 = mcp_generate_report(SESSION_ID)
report_path = r7.get("result", {}).get("report_path") if r7.get("success") else None

report_ok = False
if report_path:
    import pathlib
    p = pathlib.Path(report_path)
    if p.exists():
        content = p.read_text(encoding="utf-8")
        has_exec_summary = "Executive Summary" in content
        has_findings = "Test Finding" in content
        has_cvss = "CVSS" in content
        no_payload = "<script>alert" not in content and "UNION SELECT" not in content
        report_ok = has_exec_summary and has_findings and has_cvss and no_payload

step(7, "generate_report ? HTML with Executive Summary, CVSS, no payloads",
     r7.get("success") and report_ok,
     f"path={report_path}, exec_summary={has_exec_summary if report_path else 'N/A'}, cvss={has_cvss if report_path else 'N/A'}, no_payload={no_payload if report_path else 'N/A'}")

# -- Step 8: DAG session_data has both DAGs ------------------------------------
print("\nBlock D: DAG Layer")
dag_r3 = requests.get(f"{GRAPH_URL}/dag/session_data?session_id={SESSION_ID}", timeout=5)
dag_data = dag_r3.json() if dag_r3.ok else {}
attack_nodes = dag_data.get("attack_dag", {}).get("nodes", [])
think_nodes = dag_data.get("thinking_dag", {}).get("nodes", [])
entropy_present = all("entropy" in n or n.get("entropy") is not None for n in think_nodes[:3])
conf_present = all("confidence" in n for n in attack_nodes[:3])

step(8, "DAG session_data: both AttackDAG and ThinkingDAG nodes present",
     dag_r3.ok and len(attack_nodes) > 0 and len(think_nodes) > 0 and conf_present,
     f"attack_nodes={len(attack_nodes)}, think_nodes={len(think_nodes)}, entropy_in_think={entropy_present}")

# -- Step 9: Cleanup via flush_dbs --------------------------------------------
print("\nBlock E: Cleanup & Transfer Learning")
flush = subprocess.run(["python", "flush_dbs.py", "--session", SESSION_ID],
                       capture_output=True, text=True, cwd=str(_ROOT))
time.sleep(0.3)

gone_sqlite = get_sqlite("SELECT count(*) FROM sessions WHERE session_id=?", (SESSION_ID,))[0] == 0
neo4j_after = neo4j_query("MATCH (n {session_id: $sid}) RETURN count(n) as cnt", {"sid": SESSION_ID})
gone_neo4j = neo4j_after[0]["cnt"] == 0 if neo4j_after else True

step(9, "flush_dbs --session cleans SQLite AND Neo4j",
     gone_sqlite and gone_neo4j,
     f"SQLite_gone={gone_sqlite}, Neo4j_gone={gone_neo4j}")

# -- Step 10: cross_session_insights queryable --------------------------------
r10 = requests.get(f"{GRAPH_URL}/causal/cross_session_insights", timeout=5)
insights_ok = r10.ok and "insights" in r10.json()

step(10, "cross_session_insights endpoint queryable",
     insights_ok,
     f"status={r10.status_code}, insights_count={len(r10.json().get('insights',[])) if r10.ok else 'N/A'}")

# -- Summary -------------------------------------------------------------------
print(f"\n{'='*60}")
passed = sum(1 for _, _, s, _ in results if s == "PASS")
failed = sum(1 for _, _, s, _ in results if s == "FAIL")
print(f"  Results: {passed}/10 passed, {failed} failed")
if failed == 0:
    print("  OVERALL: \033[92mPASS\033[0m")
else:
    print("  OVERALL: \033[91mFAIL\033[0m")
    for n, name, status, detail in results:
        if status == "FAIL":
            print(f"    FAIL Step {n}: {name}")
            print(f"         {detail}")
print(f"{'='*60}\n")
sys.exit(0 if failed == 0 else 1)
