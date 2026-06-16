from neo4j import GraphDatabase
d = GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j","redteam123"))
with d.session() as s:
    total = s.run("MATCH (n) RETURN count(n) as c").single()["c"]
    rels  = s.run("MATCH ()-[r]->() RETURN type(r) as t, count(r) as c ORDER BY c DESC").data()
    print(f"Neo4j nodes: {total}")
    print("Relationships:")
    for r in rels:
        print(f"  {r['t']}: {r['c']}")
d.close()
