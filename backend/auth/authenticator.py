"""PBKDF2-based authentication for PRAMAAN (stdlib only)."""
import hashlib
import secrets
import streamlit as st
from typing import Optional, Dict, Any

from . import db

ITERATIONS = 120_000
HASH_ALGO = "sha256"


def _hash_password(password: str, salt: str) -> str:
    dk = hashlib.pbkdf2_hmac(
        HASH_ALGO,
        password.encode("utf-8"),
        salt.encode("utf-8"),
        ITERATIONS,
    )
    return dk.hex()


def create_user(username: str, password: str, role: str = "analyst") -> bool:
    salt = secrets.token_hex(16)
    pw_hash = _hash_password(password, salt)
    return db.insert_user(username, pw_hash, salt, role)


def authenticate(username: str, password: str) -> Optional[Dict[str, Any]]:
    user = db.get_user(username)
    if not user:
        db.log_login(username, False)
        return None
    expected = _hash_password(password, user["salt"])
    if not secrets.compare_digest(expected, user["password_hash"]):
        db.log_login(username, False)
        return None
    db.log_login(username, True)
    return {
        "id": user["id"],
        "username": user["username"],
        "role": user["role"],
    }


def init_auth() -> None:
    """Initialize DB and seed demo users on first run."""
    db.init_db()
    if not db.get_user("pramaan"):
        create_user("pramaan", "admin123", "analyst")
    if not db.get_user("citizen"):
        create_user("citizen", "citizen123", "citizen")


def is_authenticated() -> bool:
    return bool(st.session_state.get("auth_user"))


def get_current_user() -> Optional[Dict[str, Any]]:
    return st.session_state.get("auth_user")


def logout() -> None:
    st.session_state.pop("auth_user", None)
