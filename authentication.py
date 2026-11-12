"""Device authentication: registration, challenge-response, session tokens
and replay protection.

Challenge-response means the device never sends its secret key. The server
sends a random challenge and the device proves it knows the key by returning
HMAC(key, challenge). Each challenge can be used only once.
"""
import hmac
import secrets
import time
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

from security.encryption import compute_hmac, generate_key


@dataclass
class DeviceCredentials:
    device_id: str
    enc_key: bytes   # AES-256 key
    mac_key: bytes   # HMAC-SHA256 key (separate from the AES key)


def compute_challenge_response(mac_key: bytes, challenge: str) -> str:
    return compute_hmac(mac_key, ("auth:" + challenge).encode())


class Authenticator:
    """Trusted registry that issues keys, challenges and session tokens."""

    def __init__(self, token_ttl: float = 300.0,
                 challenge_ttl: float = 30.0) -> None:
        self.token_ttl = token_ttl
        self.challenge_ttl = challenge_ttl
        self._devices: Dict[str, Dict] = {}
        self._challenges: Dict[str, Tuple[str, float]] = {}
        self._tokens: Dict[str, Tuple[str, float]] = {}

    # -- registration ---------------------------------------------------
    def register_device(self, device_id: str,
                        role: str = "sensor") -> DeviceCredentials:
        if device_id in self._devices:
            raise ValueError("device already registered: %s" % device_id)
        creds = DeviceCredentials(device_id, generate_key(), generate_key())
        self._devices[device_id] = {"creds": creds, "role": role,
                                    "revoked": False}
        return creds

    def is_registered(self, device_id: str) -> bool:
        return device_id in self._devices

    def is_revoked(self, device_id: str) -> bool:
        return bool(self._devices.get(device_id, {}).get("revoked"))

    def role_of(self, device_id: str) -> Optional[str]:
        entry = self._devices.get(device_id)
        return entry["role"] if entry else None

    def get_credentials(self, device_id: str) -> Optional[DeviceCredentials]:
        """Credentials of an active device (None if unknown or revoked)."""
        entry = self._devices.get(device_id)
        if entry is None or entry["revoked"]:
            return None
        return entry["creds"]

    def revoke_device(self, device_id: str) -> None:
        """Revoke a device: it can no longer authenticate and its sessions die."""
        if device_id not in self._devices:
            raise KeyError(device_id)
        self._devices[device_id]["revoked"] = True
        self._tokens = {t: v for t, v in self._tokens.items()
                        if v[0] != device_id}

    # -- challenge-response ---------------------------------------------
    def issue_challenge(self, device_id: str) -> Optional[str]:
        if self.get_credentials(device_id) is None:
            return None
        challenge = secrets.token_hex(16)
        self._challenges[device_id] = (challenge, time.time())
        return challenge

    def verify_response(self, device_id: str, response: str) -> Optional[str]:
        """Check the response; on success return a new session token."""
        pending = self._challenges.pop(device_id, None)  # one-time use
        creds = self.get_credentials(device_id)
        if pending is None or creds is None:
            return None
        challenge, issued_at = pending
        if time.time() - issued_at > self.challenge_ttl:
            return None
        expected = compute_challenge_response(creds.mac_key, challenge)
        if not hmac.compare_digest(expected, str(response)):
            return None
        token = secrets.token_hex(16)
        self._tokens[token] = (device_id, time.time() + self.token_ttl)
        return token

    def validate_token(self, token: str, device_id: str) -> bool:
        entry = self._tokens.get(token)
        if entry is None:
            return False
        owner, expires = entry
        if owner != device_id or time.time() > expires:
            return False
        return not self.is_revoked(device_id)


class ReplayGuard:
    """Rejects messages that are too old/new or whose nonce was already used."""

    def __init__(self, window: float = 30.0) -> None:
        self.window = window
        self._seen: Dict[Tuple[str, str], float] = {}

    def check(self, device_id: str, nonce: str, timestamp: float,
              now: Optional[float] = None) -> Tuple[bool, str]:
        now = time.time() if now is None else now
        try:
            ts = float(timestamp)
        except (TypeError, ValueError):
            return False, "invalid timestamp"
        if abs(now - ts) > self.window:
            return False, "stale or future timestamp"
        # forget nonces that are old enough to be rejected by the time check
        self._seen = {k: v for k, v in self._seen.items()
                      if v >= now - self.window}
        key = (device_id, str(nonce))
        if key in self._seen:
            return False, "replay detected (nonce already used)"
        self._seen[key] = ts
        return True, "ok"
