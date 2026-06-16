"""Audit SQLite schema against spec."""
import sqlite3

REQUIRED = {
    "sessions":         ["session_id", "target_url", "goal", "created_at", "status"],
    "causal_nodes":     ["node_id", "session_id", "node_type", "description", "confidence", "created_at"],
    "causal_edges":     ["edge_id", "session_id", "source_id", "target_id", "label"],
    "key_facts":        ["fact_id", "session_id", "fact", "created_at"],
    "reasoning_log":    ["log_id", "session_id", "agent", "step", "content", "created_at"],
    "transfer_knowledge": ["id", "tech_stack_fingerprint", "attack_type", "success_rate", "sample_count"],
    "thinking_nodes":   ["node_id", "session_id", "thought_text", "confidence", "entropy", "mcts_score", "status", "created_at"],
    "scan_jobs":        ["job_id", "session_id", "tool", "status", "pid", "command", "result", "created_at"],
}

conn = sqlite3.connect("redteamv9.db")
cur = conn.cursor()
cur.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
existing_tables = {r[0] for r in cur.fetchall()}
print("Tables in DB:", sorted(existing_tables))

issues = []
for table, req_cols in REQUIRED.items():
    if table not in existing_tables:
        issues.append(f"MISSING TABLE: {table}")
        continue
    cur.execute(f"PRAGMA table_info({table})")
    actual_cols = {r[1] for r in cur.fetchall()}
    missing = [c for c in req_cols if c not in actual_cols]
    if missing:
        issues.append(f"Table {table} missing columns: {missing} (has: {sorted(actual_cols)})")
    else:
        print(f"  [OK] {table}: {sorted(actual_cols)}")

conn.close()
if issues:
    print("\nISSUES FOUND:")
    for i in issues:
        print(" ", i)
    raise SystemExit(1)
else:
    print("\nSQLite schema: ALL OK")
