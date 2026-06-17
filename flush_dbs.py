"""
flush_dbs.py — Clear RedTeam V6 databases.
Usage:
  python flush_dbs.py                    # clear everything
  python flush_dbs.py --session v6_001  # delete one session only
"""
import argparse
import sqlite3
import sys
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent / "redteamv9.db"
NEO4J_URI = "bolt://localhost:7687"
NEO4J_AUTH = ("neo4j", "redteam123")


def flush_sqlite(session_id: str = None):
    if not DB_PATH.exists():
        print(f"[SQLite] DB not found at {DB_PATH}, nothing to flush.")
        return
    tables = [
        "sessions", "causal_nodes", "causal_edges", "key_facts",
        "reasoning_log", "injection_points", "findings", "scan_jobs",
        "thinking_nodes", "transfer_knowledge"
    ]
    conn = sqlite3.connect(str(DB_PATH))
    try:
        if session_id:
            session_tables = tables[:]
            session_tables.remove("transfer_knowledge")
            for table in session_tables:
                try:
                    if table == "sessions":
                        conn.execute("DELETE FROM sessions WHERE session_id = ?", (session_id,))
                    else:
                        conn.execute(f"DELETE FROM {table} WHERE session_id = ?", (session_id,))
                except Exception as e:
                    print(f"  [SQLite] Skipping {table}: {e}")
            conn.commit()
            print(f"[SQLite] Deleted session {session_id} from {len(session_tables)} tables.")
        else:
            for table in tables:
                try:
                    conn.execute(f"DELETE FROM {table}")
                    print(f"  [SQLite] Cleared {table}")
                except Exception as e:
                    print(f"  [SQLite] Skipping {table}: {e}")
            conn.commit()
            print(f"[SQLite] All tables cleared.")
    finally:
        conn.close()


def flush_neo4j(session_id: str = None):
    try:
        from neo4j import GraphDatabase
        driver = GraphDatabase.driver(NEO4J_URI, auth=NEO4J_AUTH)
        with driver.session() as s:
            if session_id:
                s.run("MATCH (n {session_id: $sid}) DETACH DELETE n", sid=session_id)
                print(f"[Neo4j] Deleted nodes for session {session_id}")
            else:
                s.run("MATCH (n) DETACH DELETE n")
                print("[Neo4j] All nodes deleted.")
        driver.close()
    except ImportError:
        print("[Neo4j] neo4j driver not installed, skipping.")
    except Exception as e:
        print(f"[Neo4j] Failed: {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Flush RedTeam V6 databases.")
    parser.add_argument("--session", type=str, default=None,
                        help="Session ID to delete (default: delete all)")
    args = parser.parse_args()

    if args.session:
        print(f"Flushing session '{args.session}' only...")
    else:
        print("Flushing ALL data (SQLite + Neo4j)...")
        confirm = input("Type 'yes' to confirm: ").strip()
        if confirm.lower() != "yes":
            print("Aborted.")
            sys.exit(0)

    flush_sqlite(args.session)
    flush_neo4j(args.session)
    print("Done.")
