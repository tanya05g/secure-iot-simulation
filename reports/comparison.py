"""Comparison report: insecure vs secure attack success rates.

Each `python main.py --mode ...` run saves its results as JSON in
reports/output/. When both files exist, this module builds the report.
It can also be run on its own:   python -m reports.comparison
"""
import csv
import json
import os
from collections import Counter
from typing import Any, Dict, List, Optional

OUTPUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "output")


def results_path(mode: str, out_dir: str = OUTPUT_DIR) -> str:
    return os.path.join(out_dir, "results_%s.json" % mode)


def save_results(mode: str, data: Dict[str, Any], out_dir: str = OUTPUT_DIR) -> str:
    os.makedirs(out_dir, exist_ok=True)
    path = results_path(mode, out_dir)
    with open(path, "w") as handle:
        json.dump(data, handle, indent=2)
    return path


def load_results(mode: str, out_dir: str = OUTPUT_DIR) -> Optional[Dict[str, Any]]:
    path = results_path(mode, out_dir)
    if not os.path.exists(path):
        return None
    with open(path) as handle:
        return json.load(handle)


def _verdict(insecure_rate: float, secure_rate: float) -> str:
    if insecure_rate == 0:
        return "n/a (attack failed in baseline)"
    if secure_rate == 0:
        return "PREVENTED"
    if secure_rate < insecure_rate:
        return "REDUCED"
    return "STILL VULNERABLE"


def build_rows(insecure: Dict[str, Any], secure: Dict[str, Any]) -> List[Dict[str, Any]]:
    secure_by_name = {a["name"]: a for a in secure["attacks"]}
    rows = []
    for a in insecure["attacks"]:
        s = secure_by_name[a["name"]]
        rows.append({
            "attack": a["name"],
            "attempts": a["attempts"],
            "insecure_successes": a["successes"],
            "insecure_rate": a["success_rate"],
            "secure_successes": s["successes"],
            "secure_rate": s["success_rate"],
            "verdict": _verdict(a["success_rate"], s["success_rate"]),
        })
    return rows


def _overall(rows: List[Dict[str, Any]]) -> Dict[str, float]:
    attempts = sum(r["attempts"] for r in rows)
    ins = sum(r["insecure_successes"] for r in rows)
    sec = sum(r["secure_successes"] for r in rows)
    pct = lambda n: round(100.0 * n / attempts, 1) if attempts else 0.0
    return {"attempts": attempts, "insecure_successes": ins,
            "insecure_rate": pct(ins), "secure_successes": sec,
            "secure_rate": pct(sec)}


def render_text(insecure: Dict[str, Any], secure: Dict[str, Any]) -> str:
    rows = build_rows(insecure, secure)
    total = _overall(rows)
    line = "=" * 86
    out = [line, "ATTACK SUCCESS RATE COMPARISON: INSECURE vs SECURE MODE", line,
           "%-22s %8s  %-18s %-18s %s" % ("Attack", "Attempts", "Insecure success",
                                         "Secure success", "Verdict"),
           "-" * 86]
    for r in rows:
        out.append("%-22s %8d  %-18s %-18s %s" % (
            r["attack"], r["attempts"],
            "%5.1f%% (%d/%d)" % (r["insecure_rate"], r["insecure_successes"], r["attempts"]),
            "%5.1f%% (%d/%d)" % (r["secure_rate"], r["secure_successes"], r["attempts"]),
            r["verdict"]))
    out.append("-" * 86)
    out.append("%-22s %8d  %-18s %-18s" % (
        "OVERALL", total["attempts"],
        "%5.1f%% (%d/%d)" % (total["insecure_rate"], total["insecure_successes"], total["attempts"]),
        "%5.1f%% (%d/%d)" % (total["secure_rate"], total["secure_successes"], total["attempts"])))
    out.append("")
    out.append("Why attacks were blocked in secure mode:")
    for a in secure["attacks"]:
        reasons = Counter(d["reason"] for d in a["details"] if not d["success"])
        out.append("  %s:" % a["name"])
        for reason, count in reasons.most_common():
            out.append("    - %s  (x%d)" % (reason, count))
    out.append("")
    leg_i, leg_s = insecure["legitimate"], secure["legitimate"]
    out.append("Legitimate traffic still works in secure mode:")
    out.append("  sensor readings accepted: insecure %d/%d, secure %d/%d" % (
        leg_i["accepted"], leg_i["sent"], leg_s["accepted"], leg_s["sent"]))
    out.append("  authorised analyst query: insecure %s, secure %s" % (
        "OK" if leg_i["analyst_query_ok"] else "FAILED",
        "OK" if leg_s["analyst_query_ok"] else "FAILED"))
    out.append(line)
    return "\n".join(out)


def save_report(insecure: Dict[str, Any], secure: Dict[str, Any],
                out_dir: str = OUTPUT_DIR) -> Dict[str, str]:
    """Write comparison.txt and comparison.csv; return their paths."""
    os.makedirs(out_dir, exist_ok=True)
    txt_path = os.path.join(out_dir, "comparison.txt")
    csv_path = os.path.join(out_dir, "comparison.csv")
    with open(txt_path, "w") as handle:
        handle.write(render_text(insecure, secure) + "\n")
    rows = build_rows(insecure, secure)
    with open(csv_path, "w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    return {"text": txt_path, "csv": csv_path}


def main() -> int:
    insecure, secure = load_results("insecure"), load_results("secure")
    if insecure is None or secure is None:
        print("Results missing. Run both:\n"
              "  python main.py --mode insecure --duration 5\n"
              "  python main.py --mode secure --duration 5")
        return 1
    print(render_text(insecure, secure))
    paths = save_report(insecure, secure)
    print("Saved: %s and %s" % (paths["text"], paths["csv"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
