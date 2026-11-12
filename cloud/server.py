"""Cloud server: receives data from the gateway, stores it and processes it.

Insecure mode : accepts any well-formed packet and answers any query.
Secure mode   : requires encrypted + HMAC-protected packets from the
                authenticated gateway, and role-based permissions for queries.
"""
from collections import Counter
from typing import Any, Dict, List, Optional

from common import MODE_SECURE, Result
from security.access_control import AccessControl, role_allows
from security.authentication import Authenticator, ReplayGuard
from security.encryption import (IntegrityError, decrypt_envelope,
                                 is_envelope, verify_envelope)

TEMP_RANGE = (-40.0, 85.0)
HUMIDITY_RANGE = (0.0, 100.0)
ALERT_TEMPERATURE = 35.0


class CloudServer:
    def __init__(self, mode: str, authenticator: Optional[Authenticator] = None,
                 access_control: Optional[AccessControl] = None,
                 replay_window: float = 30.0) -> None:
        self.mode = mode
        self.authenticator = authenticator
        self.access_control = access_control
        self.replay_guard = ReplayGuard(replay_window)
        self.records: List[Dict[str, Any]] = []
        self.alerts: List[str] = []
        self.rejections: Counter = Counter()

    @property
    def secure(self) -> bool:
        return self.mode == MODE_SECURE

    # -- device authentication (used by the gateway in secure mode) --------
    def begin_auth(self, device_id: str) -> Optional[str]:
        return self.authenticator.issue_challenge(device_id) if self.secure else None

    def complete_auth(self, device_id: str, response: str) -> Optional[str]:
        return (self.authenticator.verify_response(device_id, response)
                if self.secure else None)

    # -- ingestion ----------------------------------------------------------
    def ingest(self, packet: Any) -> Result:
        result = self._ingest_secure(packet) if self.secure else self._store(packet)
        if not result.accepted:
            self.rejections[result.reason] += 1
        return result

    def _ingest_secure(self, packet: Any) -> Result:
        if not is_envelope(packet):
            return Result(False, "unencrypted packet rejected")
        sender = packet.get("device_id")
        creds = self.authenticator.get_credentials(sender)
        if creds is None:
            return Result(False, "unknown or revoked sender")
        if not role_allows(self.authenticator.role_of(sender), "write:telemetry"):
            return Result(False, "sender role may not write telemetry")
        if not verify_envelope(creds.mac_key, packet):
            return Result(False, "HMAC verification failed")
        if not self.authenticator.validate_token(packet.get("token"), sender):
            return Result(False, "invalid session token")
        fresh, why = self.replay_guard.check(sender, packet["nonce"],
                                             packet["timestamp"])
        if not fresh:
            return Result(False, why)
        try:
            payload = decrypt_envelope(creds.enc_key, packet)
        except IntegrityError as exc:
            return Result(False, str(exc))
        return self._store(payload)

    def _store(self, payload: Any) -> Result:
        """Validate the sensor payload, store it and run basic processing."""
        if not isinstance(payload, dict):
            return Result(False, "malformed payload")
        try:
            record = {"device_id": str(payload["device_id"]),
                      "timestamp": float(payload["timestamp"]),
                      "temperature": float(payload["temperature"]),
                      "humidity": float(payload["humidity"])}
        except (KeyError, TypeError, ValueError):
            return Result(False, "malformed payload")
        if not TEMP_RANGE[0] <= record["temperature"] <= TEMP_RANGE[1]:
            return Result(False, "temperature out of range")
        if not HUMIDITY_RANGE[0] <= record["humidity"] <= HUMIDITY_RANGE[1]:
            return Result(False, "humidity out of range")
        self.records.append(record)
        if record["temperature"] > ALERT_TEMPERATURE:
            self.alerts.append("HIGH TEMPERATURE %.1f C from %s"
                               % (record["temperature"], record["device_id"]))
        return Result(True, "stored")

    # -- queries -------------------------------------------------------------
    def _authorize(self, token: Optional[str], permission: str) -> Optional[Result]:
        """Return a denial Result, or None if the request may proceed."""
        if not self.secure:
            return None  # insecure mode: no access control at all
        if self.access_control.validate(token) is None:
            return Result(False, "authentication required (invalid or missing token)")
        if not self.access_control.is_allowed(token, permission):
            return Result(False, "forbidden: role lacks '%s'" % permission)
        return None

    def query_data(self, token: Optional[str] = None,
                   device_id: Optional[str] = None) -> Result:
        denied = self._authorize(token, "read:telemetry")
        if denied:
            self.rejections[denied.reason] += 1
            return denied
        rows = [dict(r) for r in self.records
                if device_id is None or r["device_id"] == device_id]
        return Result(True, "ok", rows)

    def get_stats(self, token: Optional[str] = None) -> Result:
        denied = self._authorize(token, "read:stats")
        if denied:
            self.rejections[denied.reason] += 1
            return denied
        per_device: Dict[str, Dict[str, float]] = {}
        for device_id in sorted({r["device_id"] for r in self.records}):
            temps = [r["temperature"] for r in self.records
                     if r["device_id"] == device_id]
            per_device[device_id] = {
                "count": len(temps),
                "avg_temperature": round(sum(temps) / len(temps), 2),
                "min_temperature": min(temps),
                "max_temperature": max(temps)}
        return Result(True, "ok", {"total_records": len(self.records),
                                   "alerts": len(self.alerts),
                                   "devices": per_device})
