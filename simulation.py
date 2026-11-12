"""Builds a complete system (sensors + gateway + cloud) in either mode and
runs legitimate traffic through it."""
import time
from dataclasses import dataclass, field
from typing import Dict, List

from cloud.server import CloudServer
from common import MODE_INSECURE, MODE_SECURE, MODES, Result
from devices.gateway import GATEWAY_ID, Gateway, Network
from devices.sensors import TemperatureHumiditySensor
from security.access_control import AccessControl
from security.authentication import Authenticator

# Demo accounts for the simulation only (not real secrets).
DEMO_USERS = {"admin": ("admin-demo-pass", "admin"),
              "analyst": ("analyst-demo-pass", "analyst"),
              "guest": ("guest-demo-pass", "guest")}
SENSOR_IDS = ["TEMP_HUM_01", "TEMP_HUM_02", "TEMP_HUM_03"]


@dataclass
class System:
    mode: str
    network: Network
    cloud: CloudServer
    gateway: Gateway
    sensors: List[TemperatureHumiditySensor]
    authenticator: Authenticator
    access_control: AccessControl
    demo_users: Dict[str, tuple] = field(default_factory=lambda: dict(DEMO_USERS))


def build_system(mode: str, sensor_ids=None, seed: int = 1,
                 fast_hashing: bool = False) -> System:
    """Create all components. `fast_hashing` lowers PBKDF2 cost for unit tests."""
    if mode not in MODES:
        raise ValueError("mode must be one of %s" % (MODES,))
    sensor_ids = sensor_ids or SENSOR_IDS
    authenticator = Authenticator()
    access = AccessControl(iterations=1000 if fast_hashing else 100_000)
    for name, (password, role) in DEMO_USERS.items():
        access.register_user(name, password, role)

    network = Network()
    cloud = CloudServer(mode, authenticator, access)
    gateway_creds = None
    sensors = []
    if mode == MODE_SECURE:
        gateway_creds = authenticator.register_device(GATEWAY_ID, role="gateway")
    gateway = Gateway(mode, cloud, network, authenticator, gateway_creds)
    for i, sensor_id in enumerate(sensor_ids):
        creds = (authenticator.register_device(sensor_id, role="sensor")
                 if mode == MODE_SECURE else None)
        sensors.append(TemperatureHumiditySensor(sensor_id, mode, creds,
                                                 seed=seed + i))
    return System(mode, network, cloud, gateway, sensors, authenticator, access)


def run_traffic(system: System, duration: float, interval: float = 0.5,
                verbose: bool = True) -> Dict[str, int]:
    """Send legitimate sensor readings for `duration` seconds."""
    stats = {"sent": 0, "accepted": 0, "rejected": 0}
    start = time.time()
    while True:
        for sensor in system.sensors:
            result = sensor.send(system.network, system.gateway)
            stats["sent"] += 1
            stats["accepted" if result.accepted else "rejected"] += 1
            if verbose:
                p = sensor.last_payload
                print("  [t=%4.1fs] %-12s %5.2f C  %5.1f %%  -> %s (%s)" % (
                    time.time() - start, sensor.device_id, p["temperature"],
                    p["humidity"], "ACCEPTED" if result.accepted else "REJECTED",
                    result.reason))
        if time.time() - start + interval >= duration:
            break
        time.sleep(interval)
    return stats


def legitimate_user_query(system: System) -> Result:
    """An authorised analyst reads the data (proves secure mode still works)."""
    token = None
    if system.mode == MODE_SECURE:
        password = DEMO_USERS["analyst"][0]
        token = system.access_control.login("analyst", password)
    return system.cloud.query_data(token)
