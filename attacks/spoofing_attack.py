"""Data spoofing attack: the attacker pretends to be a real sensor and injects
false readings (a fake 55+ C temperature with very low humidity).

The attacker first sniffs the wire to learn the packet format. Against
plaintext traffic it forges plain packets. Against encrypted traffic it tries
every trick available to someone WITHOUT the sensors' secret keys.

Success = the fake reading ended up stored in the cloud.
"""
import copy
import secrets
import time

from common import AttackResult, LINK_SENSOR_GATEWAY
from security.encryption import generate_key, is_envelope, seal_message

NAME = "Data Spoofing"


def _fake_payload(victim: str, temperature: float) -> dict:
    return {"device_id": victim, "timestamp": time.time(),
            "temperature": temperature, "humidity": 5.0}


def _tampered_copy(packet: dict) -> dict:
    forged = copy.deepcopy(packet)
    first = forged["ciphertext"][0]
    forged["ciphertext"] = ("A" if first != "A" else "B") + forged["ciphertext"][1:]
    return forged


def run(system, attempts: int = 10) -> AttackResult:
    result = AttackResult(NAME, system.mode)
    sniffed = list(system.network.captured.get(LINK_SENSOR_GATEWAY, []))
    encrypted_traffic = any(is_envelope(p) for p in sniffed)
    victims = [s.device_id for s in system.sensors]

    for i in range(attempts):
        victim = victims[i % len(victims)]
        fake_temp = 55.0 + i
        payload = _fake_payload(victim, fake_temp)

        if not encrypted_traffic:
            technique = "forged plaintext packet"
            packet = payload
        else:
            kind = i % 4
            if kind == 0:
                technique = "forged plaintext packet"
                packet = payload
            elif kind == 1:
                technique = "forged envelope with attacker's own keys"
                packet = seal_message(generate_key(), generate_key(), victim,
                                      payload, secrets.token_hex(16))
            elif kind == 2:
                technique = "tampered captured ciphertext"
                packet = _tampered_copy(sniffed[i % len(sniffed)])
            else:
                technique = "fake authentication, then forged envelope"
                system.gateway.begin_auth(victim)
                system.gateway.complete_auth(victim, "0" * 64)  # wrong answer
                packet = seal_message(generate_key(), generate_key(), victim,
                                      payload, "")

        before = len(system.cloud.records)
        response = system.gateway.receive(packet)
        stored = (len(system.cloud.records) > before and
                  system.cloud.records[-1]["temperature"] == fake_temp and
                  system.cloud.records[-1]["device_id"] == victim)
        result.record(technique, stored, response.reason)
    return result
