"""Replay attack: the attacker records genuine packets from the wire and
sends them again later.

Success = the replayed packet was accepted and created a NEW record in the
cloud database (measured by counting records before and after).
"""
import copy

from common import AttackResult, LINK_GATEWAY_CLOUD, LINK_SENSOR_GATEWAY

NAME = "Replay Attack"


def run(system, attempts: int = 10) -> AttackResult:
    result = AttackResult(NAME, system.mode)
    targets = [(LINK_SENSOR_GATEWAY, system.gateway.receive),
               (LINK_GATEWAY_CLOUD, system.cloud.ingest)]
    # Snapshot what the attacker has sniffed so far.
    sniffed = {link: list(system.network.captured.get(link, []))
               for link, _ in targets}

    for i in range(attempts):
        link, handler = targets[i % 2]
        packets = sniffed[link]
        technique = "replay on %s" % link
        if not packets:
            result.record(technique, False, "no packet captured on this link")
            continue
        packet = copy.deepcopy(packets[(i // 2) % len(packets)])
        before = len(system.cloud.records)
        response = handler(packet)
        stored_again = len(system.cloud.records) > before
        result.record(technique, stored_again, response.reason)
    return result
