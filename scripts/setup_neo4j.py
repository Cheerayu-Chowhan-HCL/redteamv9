"""Apply Neo4j schema indexes and verify connectivity."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from neo4j import GraphDatabase

driver = GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j", "redteam123"))
driver.verify_connectivity()
print("NEO4J OK")

with driver.session() as s:
    stmts = [
        "CREATE INDEX session_idx IF NOT EXISTS FOR (n:Session) ON (n.session_id)",
        "CREATE INDEX branch_idx IF NOT EXISTS FOR (n:AttackBranch) ON (n.session_id)",
        "CREATE INDEX evidence_idx IF NOT EXISTS FOR (n:Evidence) ON (n.session_id)",
        "CREATE INDEX vuln_idx IF NOT EXISTS FOR (n:ConfirmedVulnerability) ON (n.session_id)",
        "CREATE INDEX thinking_idx IF NOT EXISTS FOR (n:ThinkingNode) ON (n.session_id)",
        "CREATE INDEX injection_idx IF NOT EXISTS FOR (n:InjectionPoint) ON (n.session_id)",
    ]
    for stmt in stmts:
        s.run(stmt)
    print("All 6 indexes applied")

    result = s.run("SHOW INDEXES WHERE name ENDS WITH '_idx'")
    rows = result.data()
    for r in rows:
        labels = r.get("labelsOrTypes", [])
        props  = r.get("properties", [])
        name   = r.get("name", "")
        print(f"  {name}: :{labels} ({props})")
    print(f"Total indexes confirmed: {len(rows)}")

driver.close()
