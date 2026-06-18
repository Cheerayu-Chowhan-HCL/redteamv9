# RedTeam V9 — Pre-engagement flush
# Clears all engagement data. Does NOT touch code, skills, or config.
# Run before each new corpus engagement.

Write-Host "=== RedTeam V9 Pre-Engagement Flush ===" -ForegroundColor Cyan

$flushScript = @'
import sys, sqlite3, pathlib
sys.path.insert(0, r'C:\Users\chirayu\redteamv9')
from core.graph_engine import DB_PATH

print('Flushing SQLite...')
conn = sqlite3.connect(DB_PATH)
tables = ['sessions','causal_nodes','causal_edges','key_facts',
          'reasoning_log','injection_points','findings','scan_jobs',
          'thinking_nodes','agent_intent_log','declare_intents','tool_audit_log']
for t in tables:
    try:
        conn.execute(f'DELETE FROM {t}')
        print(f'  Flushed: {t}')
    except Exception as e:
        print(f'  Skip {t}: {e}')
try:
    conn.execute('DELETE FROM sqlite_sequence')
except:
    pass
conn.commit()
conn.close()

log = pathlib.Path(r'C:\Users\chirayu\redteamv9\logs\tool_audit.jsonl')
log.write_text('')
print('  tool_audit.jsonl cleared')

try:
    from neo4j import GraphDatabase
    driver = GraphDatabase.driver('bolt://localhost:7687', auth=('neo4j','redteam123'))
    with driver.session() as s:
        r = s.run('MATCH (n) DETACH DELETE n')
        c = r.consume()
        print(f'  Neo4j: {c.counters.nodes_deleted} nodes, {c.counters.relationships_deleted} rels deleted')
    driver.close()
except Exception as e:
    print(f'  Neo4j flush skipped: {e}')

print()
print('Flush complete. Skills, tools, and config untouched.')
print('Ready for new engagement.')
'@

$flushScript | python
Write-Host ""
Write-Host "Done. Start your engagement now." -ForegroundColor Green
