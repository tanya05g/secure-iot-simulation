"""Virtual temperature + humidity sensors (no real hardware)."""
import random
import time
from typing import Any, Dict, Optional

from common import (LINK_SENSOR_GATEWAY, MODE_INSECURE, MODE_SECURE, Result)
from security.authentication import DeviceCredentials, compute_challenge_response
from security.encryption import seal_message


class TemperatureHumiditySensor:
    def __init__(self, device_id: str, mode: str = MODE_INSECURE,
                 credentials: Optional[DeviceCredentials] = None,
                 seed: Optional[int] = None) -> None:
        if mode == MODE_SECURE and credentials is None:
            raise ValueError("secure mode needs device credentials")
        self.device_id = device_id
        self.mode = mode
        self.credentials = credentials
        self.token: Optional[str] = None
        self.rng = random.Random(seed)
        self._temperature = 24.0 + self.rng.uniform(-2, 2)
        self._humidity = 50.0 + self.rng.uniform(-5, 5)
        self.last_payload: Dict[str, Any] = {}

    def read(self) -> Dict[str, Any]:
        """Generate one realistic reading (slow random walk, kept in range)."""
        self._temperature += self.rng.gauss(0, 0.2) + (24.0 - self._temperature) * 0.05
        self._humidity += self.rng.gauss(0, 0.5) + (50.0 - self._humidity) * 0.05
        self._humidity = min(100.0, max(0.0, self._humidity))
        self.last_payload = {"device_id": self.device_id,
                             "timestamp": time.time(),
                             "temperature": round(self._temperature, 2),
                             "humidity": round(self._humidity, 1)}
        return self.last_payload

    def authenticate(self, gateway: Any) -> bool:
        """Challenge-response login; the secret key is never transmitted."""
        challenge = gateway.begin_auth(self.device_id)
        if challenge is None:
            return False
        response = compute_challenge_response(self.credentials.mac_key, challenge)
        self.token = gateway.complete_auth(self.device_id, response)
        return self.token is not None

    def send(self, network: Any, gateway: Any) -> Result:
        """Take a reading and send it to the gateway over the network."""
        payload = self.read()
        if self.mode == MODE_INSECURE:
            return network.deliver(LINK_SENSOR_GATEWAY, payload, gateway.receive)
        if self.token is None and not self.authenticate(gateway):
            return Result(False, "device authentication failed")
        envelope = seal_message(self.credentials.enc_key, self.credentials.mac_key,
                                self.device_id, payload, self.token)
        result = network.deliver(LINK_SENSOR_GATEWAY, envelope, gateway.receive)
        if not result.accepted and "session" in result.reason:
            self.token = None  # session expired: log in again next time
        return result
