"""Role-Based Access Control (RBAC) with salted password hashing.

Users log in with a password and receive a session token. Every permission
check goes through a role, never directly through a user.
"""
import hashlib
import hmac
import os
import secrets
import time
from typing import Dict, Optional, Set, Tuple

ROLE_PERMISSIONS: Dict[str, Set[str]] = {
    "admin": {"read:telemetry", "read:stats", "manage:devices"},
    "analyst": {"read:telemetry", "read:stats"},
    "sensor": {"write:telemetry"},
    "gateway": {"write:telemetry"},
    "guest": set(),
}


def role_allows(role: Optional[str], permission: str) -> bool:
    return permission in ROLE_PERMISSIONS.get(role or "", set())


class AccessControl:
    def __init__(self, max_failed: int = 3, token_ttl: float = 3600.0,
                 iterations: int = 100_000) -> None:
        self.max_failed = max_failed
        self.token_ttl = token_ttl
        self.iterations = iterations
        self._users: Dict[str, Dict] = {}
        self._failed: Dict[str, int] = {}
        self._tokens: Dict[str, Tuple[str, float]] = {}

    def _hash(self, password: str, salt: bytes) -> bytes:
        return hashlib.pbkdf2_hmac("sha256", password.encode(), salt,
                                   self.iterations)

    def register_user(self, username: str, password: str, role: str) -> None:
        if role not in ROLE_PERMISSIONS:
            raise ValueError("unknown role: %s" % role)
        if username in self._users:
            raise ValueError("user already exists: %s" % username)
        salt = os.urandom(16)
        self._users[username] = {"salt": salt, "hash": self._hash(password, salt),
                                 "role": role}

    def is_locked(self, username: str) -> bool:
        return self._failed.get(username, 0) >= self.max_failed

    def reset_lockout(self, username: str) -> None:
        self._failed[username] = 0

    def login(self, username: str, password: str) -> Optional[str]:
        """Return a session token, or None (wrong password or locked out)."""
        if self.is_locked(username):
            return None
        user = self._users.get(username)
        if user is not None:
            candidate = self._hash(password, user["salt"])
            if hmac.compare_digest(candidate, user["hash"]):
                self._failed[username] = 0
                token = secrets.token_hex(16)
                self._tokens[token] = (username, time.time() + self.token_ttl)
                return token
        self._failed[username] = self._failed.get(username, 0) + 1
        return None

    def validate(self, token: Optional[str]) -> Optional[Tuple[str, str]]:
        """Return (username, role) for a valid token, otherwise None."""
        entry = self._tokens.get(token or "")
        if entry is None or time.time() > entry[1]:
            return None
        username = entry[0]
        return username, self._users[username]["role"]

    def is_allowed(self, token: Optional[str], permission: str) -> bool:
        info = self.validate(token)
        return info is not None and role_allows(info[1], permission)

    def logout(self, token: str) -> None:
        self._tokens.pop(token, None)
