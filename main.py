"""Secure IoT Simulation: Attack and Defence Using Cryptography and Access Control

    python main.py --mode insecure --duration 5
    python main.py --mode secure   --duration 5
    python main.py --mode compare  --duration 5     (runs both + report)
"""
import argparse
import time
from typing import Any, Dict

from attacks import replay_attack, spoofing_attack, unauthorized_access
from common import MODE_INSECURE, MODE_SECURE
from reports import comparison
from simulation import build_system, legitimate_user_query, run_traffic

ATTACKS = [replay_attack, spoofing_attack, unauthorized_access]


def run_mode(mode: str, duration: float, interval: float, attempts: int) -> Dict[str, Any]:
    banner = "=" * 70
    print(banner)
    print(" MODE: %s" % mode.upper())
    print(banner)
    system = build_system(mode)

    print("\n[1] Legitimate sensor traffic (%d sensors -> gateway -> cloud)" % len(system.sensors))
    traffic = run_traffic(system, duration, interval)
    print("    sent=%d accepted=%d rejected=%d | cloud records=%d" % (
        traffic["sent"], traffic["accepted"], traffic["rejected"], len(system.cloud.records)))

    query = legitimate_user_query(system)
    query_ok = query.accepted and bool(query.data)
    print("    authorised analyst query: %s" % ("OK (%d rows)" % len(query.data) if query_ok
                                                  else "FAILED - " + query.reason))

    print("\n[2] Running attacks (%d attempts each)" % attempts)
    attack_results = []
    for module in ATTACKS:
        res = module.run(system, attempts)
        attack_results.append(res)
        print("    %-20s success %5.1f%%  (%d succeeded, %d blocked)" % (
            res.name, res.success_rate, res.successes, res.blocked))

    print("\n[3] Result")
    for res in attack_results:
        status = "SUCCEEDED" if res.successes else "FAILED (blocked)"
        print("    %-20s -> attack %s" % (res.name, status))
    print("    cloud records after attacks: %d (legitimate: %d)" % (
        len(system.cloud.records), traffic["accepted"]))
    if system.cloud.alerts:
        print("    cloud alerts raised: %d, e.g. %s" % (len(system.cloud.alerts),
                                                        system.cloud.alerts[-1]))

    return {"mode": mode, "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "legitimate": {"sent": traffic["sent"], "accepted": traffic["accepted"],
                           "rejected": traffic["rejected"], "analyst_query_ok": query_ok},
            "attacks": [r.to_dict() for r in attack_results]}


def main() -> int:
    parser = argparse.ArgumentParser(description="Secure IoT attack/defence simulation")
    parser.add_argument("--mode", choices=[MODE_INSECURE, MODE_SECURE, "compare"],
                        default=MODE_INSECURE)
    parser.add_argument("--duration", type=float, default=5.0,
                        help="seconds of legitimate sensor traffic (default 5)")
    parser.add_argument("--interval", type=float, default=0.5,
                        help="seconds between sensor readings (default 0.5)")
    parser.add_argument("--attempts", type=int, default=10,
                        help="attempts per attack (default 10)")
    args = parser.parse_args()

    modes = [MODE_INSECURE, MODE_SECURE] if args.mode == "compare" else [args.mode]
    for mode in modes:
        data = run_mode(mode, args.duration, args.interval, args.attempts)
        path = comparison.save_results(mode, data)
        print("\n    results saved to %s\n" % path)

    insecure, secure = comparison.load_results(MODE_INSECURE), comparison.load_results(MODE_SECURE)
    if insecure and secure:
        print(comparison.render_text(insecure, secure))
        paths = comparison.save_report(insecure, secure)
        print("Report files: %s, %s" % (paths["text"], paths["csv"]))
    else:
        other = MODE_SECURE if modes == [MODE_INSECURE] else MODE_INSECURE
        print("Run `python main.py --mode %s` too, to generate the comparison report." % other)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
