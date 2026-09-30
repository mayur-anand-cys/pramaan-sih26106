"""SQLite user + audit database for PRAMAAN."""
import os
import sqlite3
import datetime
from typing import Optional, Dict, Any, List

DB_PATH = os.path.join(os.path.dirname(__file__), "users.db")


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    conn = _connect()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('analyst','citizen','admin')),
            created_at TEXT NOT NULL
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS login_audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            success INTEGER NOT NULL
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS analyses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sha256 TEXT NOT NULL,
            analyst_id INTEGER,
            risk_score REAL,
            verdict TEXT,
            notes TEXT,
            created_at TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


def get_user(username: str) -> Optional[Dict[str, Any]]:
    conn = _connect()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    conn.close()
    return dict(row) if row else None


def insert_user(username: str, password_hash: str, salt: str, role: str) -> bool:
    conn = _connect()
    cur = conn.cursor()
    try:
        cur.execute(
            "INSERT INTO users (username, password_hash, salt, role, created_at) VALUES (?,?,?,?,?)",
            (username, password_hash, salt, role, datetime.datetime.utcnow().isoformat()),
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()


def log_login(username: str, success: bool) -> None:
    conn = _connect()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO login_audit (username, timestamp, success) VALUES (?,?,?)",
        (username, datetime.datetime.utcnow().isoformat(), 1 if success else 0),
    )
    conn.commit()
    conn.close()


def get_recent_logins(limit: int = 20) -> List[Dict[str, Any]]:
    conn = _connect()
    cur = conn.cursor()
    cur.execute("SELECT * FROM login_audit ORDER BY id DESC LIMIT ?", (limit,))
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows
