"""
Cross-session transfer learning for RedTeam V9.
Stores per-tech-stack attack success rates and loads them as Bayesian priors.
"""
import json
import logging
import sqlite3
from pathlib import Path
from typing import List, Dict

logger = logging.getLogger(__name__)

DB_PATH = Path("C:/users/chirayu/redteamv9/redteamv9.db")


def _get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def init_transfer_table():
    with _get_conn() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS transfer_knowledge (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tech_stack_fingerprint TEXT NOT NULL,
                attack_type TEXT NOT NULL,
                success_rate REAL DEFAULT 0.0,
                sample_count INTEGER DEFAULT 0,
                last_updated TEXT DEFAULT (datetime('now')),
                UNIQUE(tech_stack_fingerprint, attack_type)
            )
        """)
        conn.commit()


def fingerprint_to_key(fingerprint: dict) -> str:
    """Normalise fingerprint dict to a stable string key."""
    techs = []
    for k in ("framework", "language", "server", "cms"):
        v = fingerprint.get(k, "")
        if v:
            techs.append(f"{k}:{v.lower()}")
    return "|".join(sorted(techs)) or "unknown"


def record_outcome(fingerprint: dict, attack_type: str, success: bool):
    """After a tool execution, record outcome for future sessions."""
    key = fingerprint_to_key(fingerprint)
    reward = 1.0 if success else 0.0
    try:
        with _get_conn() as conn:
            conn.execute("""
                INSERT INTO transfer_knowledge (tech_stack_fingerprint, attack_type, success_rate, sample_count)
                VALUES (?, ?, ?, 1)
                ON CONFLICT(tech_stack_fingerprint, attack_type) DO UPDATE SET
                    success_rate = (success_rate * sample_count + ?) / (sample_count + 1),
                    sample_count = sample_count + 1,
                    last_updated = datetime('now')
            """, (key, attack_type, reward, reward))
            conn.commit()
    except Exception as e:
        logger.warning(f"transfer_learning record_outcome failed: {e}")


def get_priors_for_fingerprint(fingerprint: dict) -> List[Dict]:
    """Return matching transfer rows for a given fingerprint."""
    key = fingerprint_to_key(fingerprint)
    try:
        with _get_conn() as conn:
            rows = conn.execute("""
                SELECT attack_type, success_rate, sample_count
                FROM transfer_knowledge
                WHERE tech_stack_fingerprint = ?
                ORDER BY success_rate DESC
            """, (key,)).fetchall()
            return [dict(r) for r in rows]
    except Exception as e:
        logger.warning(f"transfer_learning get_priors failed: {e}")
        return []


def get_all_insights(tech_stack: str, attack_type: str) -> List[Dict]:
    """Read cross-session insights. Intentionally no session_id filter."""
    try:
        with _get_conn() as conn:
            query = "SELECT * FROM transfer_knowledge WHERE 1=1"
            params = []
            if tech_stack:
                query += " AND tech_stack_fingerprint LIKE ?"
                params.append(f"%{tech_stack}%")
            if attack_type:
                query += " AND attack_type = ?"
                params.append(attack_type)
            query += " ORDER BY success_rate DESC LIMIT 50"
            rows = conn.execute(query, params).fetchall()
            return [dict(r) for r in rows]
    except Exception as e:
        logger.warning(f"transfer_learning get_all_insights failed: {e}")
        return []
