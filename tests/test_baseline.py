"""Tests for the false-positive summary logic in baseline.py.

These use tiny hand-made inputs to check the arithmetic and bookkeeping.
They say nothing about how the real rules perform on real benign logs.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from baseline import sample_alerts, summarize  # noqa: E402

RULES = [
    {"id": "noisy", "confidence": "low"},
    {"id": "quiet"},
    {"id": "sometimes"},
]


def per_file():
    return [
        {"file": "a.evtx", "events": 6000,
         "hits": {"noisy": [{"Image": "x.exe"}] * 3, "sometimes": [{"Image": "y.exe"}]}},
        {"file": "b.evtx", "events": 4000,
         "hits": {"noisy": [{"Image": "z.exe"}] * 2}},
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
