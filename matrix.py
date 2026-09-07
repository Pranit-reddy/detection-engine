import sys
import os
import glob
import json
from collections import defaultdict
from parse import parse_file
from engine import load_rules, evaluate


def scan(sample_root, rules):
    results = []
    paths = sorted(glob.glob(f"{sample_root}/**/*.evtx", recursive=True))
    for i, path in enumerate(paths, 1):
        rel = os.path.relpath(path, sample_root)
        tactic = rel.split(os.sep)[0] if os.sep in rel else "Uncategorized"
        print(f"\r  scanning {i}/{len(paths)}", end="", flush=True, file=sys.stderr)
        try:
            events = parse_file(path)
        except Exception:
            continue
        hits = evaluate(events, rules)
        results.append({
            "file": os.path.basename(path),
            "tactic": tactic,
            "events": len(events),
            "fired": [rid for rid, matched in hits.items() if matched],
        })
    print()
    return results


def report(results, rules):
    by_tactic = defaultdict(lambda: {"total": 0, "detected": 0})
    per_rule = defaultdict(int)

    for r in results:
        by_tactic[r["tactic"]]["total"] += 1
        if r["fired"]:
            by_tactic[r["tactic"]]["detected"] += 1
        for rid in r["fired"]:
            per_rule[rid] += 1

    print(f"\n{'TACTIC':<28} {'FILES':>6} {'CAUGHT':>7} {'COVERAGE':>9}")
    print("-" * 54)
    for tactic in sorted(by_tactic):
        stats = by_tactic[tactic]
        pct = 100 * stats["detected"] / stats["total"]
        print(f"{tactic:<28} {stats['total']:>6} {stats['detected']:>7} {pct:>8.0f}%")

    total = len(results)
    caught = sum(1 for r in results if r["fired"])
    print("-" * 54)
    print(f"{'OVERALL':<28} {total:>6} {caught:>7} {100*caught/total:>8.0f}%")

    low_conf = {r["id"] for r in rules if r.get("confidence") == "low"}
    hollow = sum(1 for r in results if r["fired"] and set(r["fired"]) <= low_conf)
    print(f"\n{'HEADLINE COVERAGE':<34} {100*caught/total:>6.0f}%")
    print(f"{'SUBSTANTIVE COVERAGE':<34} {100*(caught-hollow)/total:>6.0f}%")
    print(f"{'(files carried by low-confidence only)':<34} {hollow:>6}")

    print(f"\n{'RULE':<40} {'FILES HIT':>9}")
    print("-" * 51)
    for rule in rules:
        flag = " (low conf)" if rule.get("confidence") == "low" else ""
        print(f"{rule['id'] + flag:<40} {per_rule[rule['id']]:>9}")
    
    


if __name__ == "__main__":
    root = sys.argv[1] if len(sys.argv) > 1 else "samples"
    rules = load_rules()
    results = scan(root, rules)
    with open("results.json", "w") as f:
        json.dump(results, f, indent=2)
    report(results, rules)