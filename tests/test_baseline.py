"""Tests for baseline.py.

Most use tiny hand-made inputs to check the arithmetic and bookkeeping; they say
nothing about how the real rules perform on real benign logs.

The last group is an integration test that needs real .evtx files.  It runs only
when EVTX_SAMPLES points at a folder of them (e.g. the EVTX-ATTACK-SAMPLES
clone), and is skipped otherwise:

    EVTX_SAMPLES=samples python -m pytest -q
"""
import glob
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from baseline import finalize_file, sample_alerts, scan_slice, summarize  # noqa: E402
from engine import evaluate, load_rules  # noqa: E402
from parse import count_chunks, iter_events, parse_file  # noqa: E402

RULES = [
    {"id": "noisy", "confidence": "low"},
    {"id": "quiet"},
    {"id": "sometimes"},
]


def per_file():
    return [
        {"file": "a.evtx", "events": 6000,
         "hits": {"noisy": {"count": 3, "samples": [{"Image": "x.exe"}] * 3},
                  "sometimes": {"count": 1, "samples": [{"Image": "y.exe"}]}}},
        {"file": "b.evtx", "events": 4000,
         "hits": {"noisy": {"count": 2, "samples": [{"Image": "z.exe"}] * 2}}},
        {"file": "c.evtx", "events": 0, "hits": {}},
    ]


def row(summary, rule_id):
    return next(r for r in summary["rules"] if r["rule"] == rule_id)


def test_totals():
    s = summarize(per_file(), RULES)
    assert s["files"] == 3
    assert s["events"] == 10000
    assert s["total_alerts"] == 6


def test_alert_and_file_counts_per_rule():
    s = summarize(per_file(), RULES)
    assert (row(s, "noisy")["alerts"], row(s, "noisy")["files"]) == (5, 2)
    assert (row(s, "sometimes")["alerts"], row(s, "sometimes")["files"]) == (1, 1)
    assert (row(s, "quiet")["alerts"], row(s, "quiet")["files"]) == (0, 0)


def test_rate_per_10k_events():
    s = summarize(per_file(), RULES)
    assert row(s, "noisy")["per_10k"] == 5.0      # 5 alerts in 10,000 events
    assert row(s, "sometimes")["per_10k"] == 1.0


def test_silent_rules_counted():
    assert summarize(per_file(), RULES)["silent_rules"] == 1


def test_confidence_is_carried_through():
    s = summarize(per_file(), RULES)
    assert row(s, "noisy")["confidence"] == "low"
    assert row(s, "quiet")["confidence"] == "normal"


def test_empty_baseline_does_not_divide_by_zero():
    s = summarize([], RULES)
    assert s["events"] == 0
    assert all(r["per_10k"] == 0.0 for r in s["rules"])


def test_sample_alerts_respects_limit_and_keeps_file_name():
    out = sample_alerts(per_file(), "noisy", 4)
    assert len(out) == 4
    assert out[0]["file"] == "a.evtx"
    assert out[-1]["file"] == "b.evtx"


def test_sample_alerts_for_unknown_rule_is_empty():
    assert sample_alerts(per_file(), "nope", 5) == []


# --- merging slices of one file and applying thresholds ---------------------

def slice_state(count, keys=(), samples=()):
    return {"count": count, "samples": list(samples), "keys": set(keys)}


def test_finalize_adds_up_slices():
    rules = [{"id": "r"}]
    parts = [(0, 100, {"r": slice_state(2, samples=[{"Image": "a"}])}),
             (400, 50, {"r": slice_state(3, samples=[{"Image": "b"}])})]
    out = finalize_file("/x/f.evtx", parts, rules)
    assert out["events"] == 150
    assert out["hits"]["r"]["count"] == 5
    assert out["file"] == "f.evtx"


def test_finalize_restores_chunk_order_for_samples():
    rules = [{"id": "r"}]
    parts = [(400, 1, {"r": slice_state(1, samples=[{"Image": "second"}])}),
             (0, 1, {"r": slice_state(1, samples=[{"Image": "first"}])})]
    samples = finalize_file("f.evtx", parts, rules)["hits"]["r"]["samples"]
    assert [s["Image"] for s in samples] == ["first", "second"]


def test_threshold_is_judged_across_slices_not_per_slice():
    """Two distinct values in different slices must add up to the threshold."""
    rules = [{"id": "r", "threshold": {"distinct_field": "Image", "min_count": 2}}]
    parts = [(0, 1, {"r": slice_state(1, keys={"a.exe"})}),
             (400, 1, {"r": slice_state(1, keys={"b.exe"})})]
    assert finalize_file("f.evtx", parts, rules)["hits"]["r"]["count"] == 2


def test_threshold_not_reached_means_no_alerts():
    rules = [{"id": "r", "threshold": {"distinct_field": "Image", "min_count": 3}}]
    parts = [(0, 1, {"r": slice_state(9, keys={"a.exe", "b.exe"}, samples=[{"Image": "a"}])})]
    assert "r" not in finalize_file("f.evtx", parts, rules)["hits"]


# --- integration: streaming scan == original evaluate() ---------------------

SAMPLES = os.environ.get("EVTX_SAMPLES")
needs_samples = pytest.mark.skipif(
    not SAMPLES or not os.path.isdir(SAMPLES or ""),
    reason="set EVTX_SAMPLES to a folder of .evtx files to run this test")


def some_files(n=12):
    files = sorted(glob.glob(os.path.join(SAMPLES, "**", "*.evtx"), recursive=True))
    return files[:: max(1, len(files) // n)][:n]


@needs_samples
def test_streaming_scan_matches_evaluate_on_real_files():
    rules = load_rules()
    for path in some_files():
        expected = {rid: len(m) for rid, m in evaluate(parse_file(path), rules).items() if m}
        chunks = count_chunks(path)
        _, _, events, state = scan_slice((path, 0, chunks))
        got = finalize_file(path, [(0, events, state)], rules)
        assert events == len(parse_file(path)), path
        assert {rid: h["count"] for rid, h in got["hits"].items()} == expected, path


@needs_samples
def test_splitting_a_file_into_chunk_ranges_loses_nothing():
    for path in some_files(6):
        chunks = count_chunks(path)
        whole = list(iter_events(path))
        pieces = []
        for start in range(0, chunks, 1):          # one chunk at a time: worst case
            pieces.extend(iter_events(path, (start, start + 1)))
        assert pieces == whole, path
