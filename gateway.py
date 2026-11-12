"""IoT gateway and the simulated network between the components.

The Network records every packet that crosses a link. This is what an
attacker "sniffing the wire" can see: plaintext in insecure mode and
encrypted envelopes in secure mode.
"""
import copy
from collections import Counter
from typing import Any, Callable, Dict, List, Optional

from common import (LINK_GATEWAY_CLOUD, LINK_SENSOR_GATEWAY, MODE_SECURE,
                    Result)
from security.authentication import (Authenticator, DeviceCredentials,
                                     ReplayGuard, compute_challenge_response)
from security.access_control import role_allows
from security.encryption import (IntegrityError, decrypt_envelope,
                                 is_envelope, seal_message, verify_envelope)

GATEWAY_ID = "GATEWAY"


class Network:
    """Delivers packets between components and keeps a copy of each one."""

    def __init__(self) -> None:
        self.captured: Dict[str, List[Any]] = {LINK_SENSOR_GATEWAY: [],
                                               LINK_GATEWAY_CLOUD: []}

    def deliver(self, link: str, packet: Any,
                handler: Callable[[Any], Result]) -> Result:
        self.captured.setdefault(link, []).append(copy.deepcopy(packet))
        return handler(packet)


class Gateway:
    def __init__(self, mode: str, cloud: Any, network: Network,
                 authenticator: Optional[Authenticator] = None,
                 credentials: Optional[DeviceCredentials] = None,
                 replay_window: float = 30.0) -> None:
        self.mode = mode
        self.cloud = cloud
        self.network = network
        self.authenticator = authenticator
        self.credentials = credentials
        self.cloud_token: Optional[str] = None
        self.replay_guard = ReplayGuard(replay_window)
        self.stats = Counter()
        self.rejections: Counter = Counter()

    @property
    def secure(self) -> bool:
        return self.mode == MODE_SECURE

    # -- sensor authentication ------------------------------------------------
    def begin_auth(self, device_id: str) -> Optional[str]:
        return self.authenticator.issue_challenge(device_id) if self.secure else None

    def complete_auth(self, device_id: str, response: str) -> Optional[str]:
        return (self.authenticator.verify_response(device_id, response)
                if self.secure else None)

    # -- receiving data ---------------------------------------------------------
    def receive(self, packet: Any) -> Result:
        self.stats["received"] += 1
        result = self._receive_secure(packet) if self.secure else self._forward(packet)
        if result.accepted:
            self.stats["accepted"] += 1
        else:
            self.stats["rejected"] += 1
            self.rejections[result.reason] += 1
        return result

    def _receive_secure(self, packet: Any) -> Result:
        if not is_envelope(packet):
            return Result(False, "unencrypted packet rejected")
        sender = packet.get("device_id")
        creds = self.authenticator.get_credentials(sender)
        if creds is None:
            return Result(False, "unknown or revoked device")
        if not role_allows(self.authenticator.role_of(sender), "write:telemetry"):
            return Result(False, "device role may not write telemetry")
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
        if payload.get("device_id") != sender:
            return Result(False, "payload device does not match sender")
        return self._forward(payload)

    # -- forwarding to the cloud -------------------------------------------------
    def _authenticate_to_cloud(self) -> bool:
        challenge = self.cloud.begin_auth(GATEWAY_ID)
        if challenge is None:
            return False
        response = compute_challenge_response(self.credentials.mac_key, challenge)
        self.cloud_token = self.cloud.complete_auth(GATEWAY_ID, response)
        return self.cloud_token is not None

    def _forward(self, payload: Any) -> Result:
        if not self.secure:
            return self.network.deliver(LINK_GATEWAY_CLOUD, payload,
                                        self.cloud.ingest)
        if self.cloud_token is None and not self._authenticate_to_cloud():
            return Result(False, "gateway authentication to cloud failed")
        envelope = seal_message(self.credentials.enc_key, self.credentials.mac_key,
                                GATEWAY_ID, payload, self.cloud_token)
        result = self.network.deliver(LINK_GATEWAY_CLOUD, envelope,
                                      self.cloud.ingest)
        if not result.accepted and "session" in result.reason:
            self.cloud_token = None
        return result
