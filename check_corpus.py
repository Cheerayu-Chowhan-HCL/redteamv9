"""Quick corpus quality snapshot — run after each engagement."""
import json, pathlib, sqlite3, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from core.graph_engine import DB_PATH

log = pathlib.Path(__file__).resolve().parent / "logs" / "tool_audit.jsonl"
lines = [l for l in log.read_text(encoding="utf-8", errors="replace").strip().split("\n") if l.strip()]
entries = []
for l in lines:
    try:
        entries.append(json.loads(l))
    except Exception:
        pass

labelled = [e for e in entries if e.get("session_phase") not in
            (None, "null", "pre_intent", "unknown_phase")]

conn = sqlite3.connect(DB_PATH)
sessions  = conn.execute("SELECT session_id FROM sessions").fetchall()
findings  = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
jobs      = conn.execute("SELECT tool, status, COUNT(*) FROM scan_jobs GROUP BY tool, status").fetchall()
conn.close()

pct = int(len(labelled) / max(len(entries), 1) * 100)
print(f"  entries={len(entries)}  labelled={len(labelled)}({pct}%)  sessions={len(sessions)}  findings={findings}")
for j in jobs:
    print(f"    scan_job: {j[0]} | {j[1]} | {j[2]}x")
if len(labelled) >= 200:
    print("  >>> READY TO TRAIN")
else:
    print(f"  >>> need {200 - len(labelled)} more labelled entries")
