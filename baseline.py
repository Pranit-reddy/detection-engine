"""Measure false positives: run the rules over BENIGN logs.

matrix.py answers "how many attacks do the rules catch?".  This answers the
other half: "how often do the rules fire on normal, harmless activity?"
Every alert on a benign log is a false positive, so fewer is better.

Usage:
    python baseline.py <benign_dir> [--show N] [--json out.json]

<benign_dir> should contain .evtx files from a clean machine, ideally with
Sysmon installed.  See the README ("Measuring false positives") for a public
source of such logs.

Reading the output:
    ALERTS    events that matched the rule
    FILES     benign files in which the rule fired at least once
    PER 10K   alerts per 10,000 events scanned, so results can be compared
              across baselines of different sizes
Alerts are NOT automatically wrong detections: a human should look at the
`--show` samples and decide whether each is a real false positive.
"""
import argparse
import glob
import json
import os
import sys
from collections import defaultdict

from engine import evaluate, load_rules
from parse import parse_file

SAMPLE_FIELDS = ("EventID", "Provider", "Image", "ParentImage", "SourceImage", "TargetImage", "CommandLine")


def summarize(per_file, rules):
    """Combine per-file results into per-rule totals.

    per_file: list of {"file": str, "events": int, "hits": {rule_id: [event, ...]}}
    Returns a dict with overall counts and one row per rule.
    """
    total_events = sum(f["events"] for f in per_file)
    rows = []
    for rule in rules:
        rid = rule["id"]
        alerts = sum(len(f["hits"].get(rid, [])) for f in per_file)
        files = sum(1 for f in per_file if f["hits"].get(rid))
        rows.append({
            "rule": rid,
            "confidence": rule.get("confidence", "normal"),
            "alerts": alerts,
            "files": files,
            "per_10k": (10000 * alerts / total_events) if total_events else 0.0,
        })
    return {
        "files": len(per_file),
        "events": total_events,
        "total_alerts": sum(r["alerts"] for r in rows),
        "silent_rules": sum(1 for r in rows if r["alerts"] == 0),
        "rules": rows,
    }


def sample_alerts(per_file, rule_id, limit):
    """Return up to `limit` compact descriptions of events that fired a rule."""
    out = []
    for f in per_file:
        for event in f["hits"].get(rule_id, []):
            out.append({"file": f["file"],
                        **{k: event[k] for k in SAMPLE_FIELDS if event.get(k)}})
            if len(out) >= limit:
                return out
    return out


def scan(paths, rules):
    per_file, failed = [], []
    for i, path in enumerate(paths, 1):
        print(f"\r  scanning {i}/{len(paths)}  {os.path.basename(path)[:40]:<40}",
              end="", flush=True, file=sys.stderr)
        try:
            events = parse_file(path)
        except Exception as exc:  # report, don't hide, files we could not read
            failed.append((path, str(exc)))
            continue
        hits = {rid: m for rid, m in evaluate(events, rules).items() if m}
        per_file.append({"file": os.path.basename(path), "events": len(events), "hits": hits})
    print(file=sys.stderr)
    return per_file, failed


def print_report(summary, per_file, show):
    print(f"\nBASELINE: {summary['files']} benign files, {summary['events']:,} events scanned\n")
    print(f"{'RULE':<36} {'ALERTS':>8} {'FILES':>6} {'PER 10K':>9}")
    print("-" * 62)
    for row in sorted(summary["rules"], key=lambda r: (-r["alerts"], r["rule"])):
        flag = " (low)" if row["confidence"] == "low" else ""
        print(f"{row['rule'] + flag:<36} {row['alerts']:>8} {row['files']:>6} {row['per_10k']:>9.2f}")
    print("-" * 62)
    print(f"{'TOTAL ALERTS':<36} {summary['total_alerts']:>8}")
    print(f"Rules that never fired on benign data: {summary['silent_rules']} of {len(summary['rules'])}")

    if show:
        print(f"\nSAMPLE ALERTS (up to {show} per rule) - review these by hand:")
        for row in summary["rules"]:
            if row["alerts"]:
                print(f"\n  {row['rule']}")
                for s in sample_alerts(per_file, row["rule"], show):
                    detail = "  |  ".join(f"{k}={str(v)[:90]}" for k, v in s.items() if k != "file")
                    print(f"    [{s['file']}] {detail}")


def main():
    parser = argparse.ArgumentParser(description="Run the rules over benign logs to count false positives.")
    parser.add_argument("benign_dir")
    parser.add_argument("--show", type=int, default=0, help="print up to N sample alerts per rule")
    parser.add_argument("--json", help="also write the summary to this file")
    args = parser.parse_args()

    paths = sorted(glob.glob(os.path.join(args.benign_dir, "**", "*.evtx"), recursive=True))
    if not paths:
        sys.exit(f"No .evtx files found under {args.benign_dir}")

    rules = load_rules()
    per_file, failed = scan(paths, rules)
    summary = summarize(per_file, rules)
    print_report(summary, per_file, args.show)

    if failed:
        print(f"\nWARNING: {len(failed)} file(s) could not be parsed and were NOT scanned:")
        for path, err in failed:
            print(f"  {path}: {err}")
    if args.json:
        with open(args.json, "w") as f:
            json.dump({**summary, "failed": [p for p, _ in failed]}, f, indent=2)


if __name__ == "__main__":
    main()
