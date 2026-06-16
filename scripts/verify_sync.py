"""Task 2E — verify Neo4j <-> SQLite are in sync."""
import sys, json, sqlite3, requests, time
sys.path.insert(0, "C:/users/chirayu/redteamv9")

BEARER = open("C:/Users/chirayu/redteamv9/.tmp/rtv9_bearer.txt").read().strip()
HEADERS = {"Authorization": f"Bearer {BEARER}"}
GRAPH_URL = "http://127.0.0.1:6037"
TEST_SID = "v6_schema_test"

def fail(msg):
    print(f"FAIL: {msg}")
    raise SystemExit(1)

# --- Create session via graph memory API ---
r = requests.post(f"{GRAPH_URL}/session/create",
                  json={"session_id": TEST_SID, "target_url": "http://sync-test.local", "goal": "schema sync test"},
                  headers=HEADERS, timeout=10)
if not r.ok or not r.json().get("success"):
    fail(f"session/create failed: {r.text}")
node_id = r.json()["node_id"]
print(f"Created session node_id={node_id}")

time.sleep(0.5)

# --- Verify in SQLite ---
conn = sqlite3.connect("redteamv9.db")
row = conn.execute("SELECT * FROM sessions WHERE session_id=?", (TEST_SID,)).fetchone()
node_row = conn.execute("SELECT * FROM causal_nodes WHERE session_id=?", (TEST_SID,)).fetchone()
conn.close()
if not row:
    fail("Session not found in SQLite sessions table")
if not node_row:
    fail("Session root node not found in SQLite causal_nodes")
print(f"SQLite OK: sessions row={dict(zip(['session_id','target_url','goal','status','created_at','metadata'], row))}")

# --- Verify in Neo4j ---
from neo4j import GraphDatabase
driver = GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j","redteam123"))
with driver.session() as s:
    result = s.run("MATCH (n:Session {session_id: $sid}) RETURN n", sid=TEST_SID)
    neo4j_rows = result.data()
if not neo4j_rows:
    fail(f"Session NOT found in Neo4j (node_id={node_id})")
print(f"Neo4j OK: {neo4j_rows[0]['n']}")
driver.close()

# --- Delete test session ---
r2 = requests.get(f"{GRAPH_URL}/dag/sessions", timeout=5)
print(f"Sessions before cleanup: {[s['session_id'] for s in r2.json().get('sessions',[])]}")

# Use flush via SQLite directly (flush_dbs.py --session)
import subprocess
result = subprocess.run(["python", "flush_dbs.py", "--session", TEST_SID],
                       capture_output=True, text=True, cwd="C:/users/chirayu/redteamv9")
print("Flush:", result.stdout.strip(), result.stderr.strip())

# Verify deleted
conn = sqlite3.connect("redteamv9.db")
gone = conn.execute("SELECT count(*) FROM sessions WHERE session_id=?", (TEST_SID,)).fetchone()[0]
conn.close()
if gone > 0:
    fail("Session still in SQLite after flush")

driver = GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j","redteam123"))
with driver.session() as s:
    result = s.run("MATCH (n {session_id: $sid}) RETURN count(n) as cnt", sid=TEST_SID)
    cnt = result.single()["cnt"]
driver.close()
if cnt > 0:
    fail(f"Session still has {cnt} nodes in Neo4j after flush")

print("\nNeo4j <-> SQLite sync: PASS")
