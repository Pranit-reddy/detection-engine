"""Measure false positives: run the rules over BENIGN logs.

matrix.py answers "how many attacks do the rules catch?".  This answers the
other half: "how often do the rules fire on normal, harmless activity?"
Every alert on a benign log is a candidate false positive, so fewer is better.

Usage:
    python baseline.py <benign_dir> [--show N] [--json out.json] [--workers K]

<benign_dir> should contain .evtx files from a clean machine, ideally with
Sysmon installed.  See the README ("Measuring false positives") for a public
source of such logs.

Real baselines are big (one Sysmon log can hold over a million events), so this
script streams: it never keeps a whole log in memory, only a count, a few sample
events and (for threshold rules) the set of distinct values per rule.  Large
files are split into chunk ranges and parsed by several processes at once.
The results are the same as running engine.evaluate() on the whole file.

Reading the output:
    ALERTS    events that matched the rule (0 if a threshold rule did not reach
              its threshold in that file, exactly as engine.py behaves)
    FILES     benign files in which the rule fired at least once
    PER 10K   alerts per 10,000 events scanned, so baselines of different sizes
              can be compared
An alert is NOT automatically a wrong detection: look at the --show samples and
decide by hand whether each is a real false positive.
"""
import argparse
import glob
import json
import os
import sys
import time
from multiprocessing import Pool

from engine import load_rules, rule_matches, threshold_key
from parse import count_chunks, iter_events

SAMPLE_FIELDS = ("EventID", "Provider", "Image", "ParentImage", "SourceImage",
                 "TargetImage", "CommandLine")
SAMPLES_KEPT = 25          # per rule, per file: enough to review by hand
CHUNKS_PER_TASK = 400      # ~25 MB of log per work item


# --- scanning one slice of one file -----------------------------------------

def compact(event):
    """Keep only the fields a human needs to judge an alert."""
    return {k: event[k] for k in SAMPLE_FIELDS if event.get(k)}


def scan_slice(task):
    """Worker: stream one chunk range of one file through every rule.

    Returns (path, start, events, {rule_id: {"count", "samples", "keys"}}).
    "keys" is the set of distinct values a threshold rule counts.
    """
    path, start, stop = task
    rules = load_rules()
    state = {r["id"]: {"count": 0, "samples": [], "keys": set()} for r in rules}
    events = 0
    for event in iter_events(path, (start, stop)):
        events += 1
        for rule in rules:
            if rule_matches(event, rule):
                s = state[rule["id"]]
                s["count"] += 1
                if len(s["samples"]) < SAMPLES_KEPT:
                    s["samples"].append(compact(event))
                th = rule.get("threshold")
                if th and event.get(th["distinct_field"]):
                    s["keys"].add(threshold_key(event, th["distinct_field"]))
    return path, start, events, state


def make_tasks(paths):
    tasks = []
    for path in paths:
        try:
            chunks = count_chunks(path)
        except Exception as exc:
            print(f"\nWARNING: cannot open {path}: {exc}", file=sys.stderr)
            continue
        for start in range(0, max(chunks, 1), CHUNKS_PER_TASK):
            tasks.append((path, start, min(start + CHUNKS_PER_TASK, chunks)))
    return tasks


def finalize_file(path, parts, rules):
    """Merge a file's slices and apply each rule's threshold, as engine.py would."""
    parts = sorted(parts, key=lambda p: p[0])            # restore chunk order
    hits, events = {}, 0
    for rule in rules:
        rid = rule["id"]
        count, samples, keys = 0, [], set()
        for _, ev, state in parts:
            count += state[rid]["count"]
            keys |= state[rid]["keys"]
            samples.extend(state[rid]["samples"])
        th = rule.get("threshold")
        if th and len(keys) < int(th["min_count"]):
            count, samples = 0, []                        # threshold not reached
        if count:
            hits[rid] = {"count": count, "samples": samples[:SAMPLES_KEPT]}
    events = sum(ev for _, ev, _ in parts)
    return {"file": os.path.basename(path), "events": events, "hits": hits}


def scan(paths, rules, workers):
    tasks = make_tasks(paths)
    if not tasks:
        return [], []
    total_chunks = sum(t[2] - t[1] for t in tasks)
    by_file, done_chunks, started = {}, 0, time.time()
    with Pool(workers) as pool:
        for path, start, events, state in pool.imap_unordered(scan_slice, tasks):
            by_file.setdefault(path, []).append((start, events, state))
            done_chunks += next(t[2] - t[1] for t in tasks if t[0] == path and t[1] == start)
            pct = 100 * done_chunks / total_chunks
            print(f"\r  {pct:5.1f}%  {done_chunks}/{total_chunks} chunks  "
                  f"{(time.time() - started) / 60:5.1f} min elapsed", end="",
                  flush=True, file=sys.stderr)
    print(file=sys.stderr)
    per_file = [finalize_file(p, parts, rules) for p, parts in sorted(by_file.items())]
    return per_file, [p for p in paths if p not in by_file]


# --- summary and report -----------------------------------------------------

def summarize(per_file, rules):
    """Combine per-file results into per-rule totals.

    per_file: list of {"file", "events", "hits": {rule_id: {"count", "samples"}}}
    """
    total_events = sum(f["events"] for f in per_file)
    rows = []
    for rule in rules:
        rid = rule["id"]
        alerts = sum(f["hits"].get(rid, {}).get("count", 0) for f in per_file)
        files = sum(1 for f in per_file if f["hits"].get(rid, {}).get("count"))
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
        for sample in f["hits"].get(rule_id, {}).get("samples", []):
            out.append({"file": f["file"], **sample})
            if len(out) >= limit:
                return out
    return out


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
    parser.add_argument("--workers", type=int, default=os.cpu_count() or 1,
                        help="parallel processes (default: all CPU cores)")
    args = parser.parse_args()

    paths = sorted(glob.glob(os.path.join(args.benign_dir, "**", "*.evtx"), recursive=True))
    if not paths:
        sys.exit(f"No .evtx files found under {args.benign_dir}")

    rules = load_rules()
    per_file, failed = scan(paths, rules, args.workers)
    summary = summarize(per_file, rules)
    print_report(summary, per_file, args.show)

    if failed:
        print(f"\nWARNING: {len(failed)} file(s) could not be opened and were NOT scanned:")
        for path in failed:
            print(f"  {path}")
    if args.json:
        with open(args.json, "w") as f:
            json.dump({**summary, "not_scanned": failed}, f, indent=2)


if __name__ == "__main__":
    main()
