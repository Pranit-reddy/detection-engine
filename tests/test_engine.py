"""Unit tests for the matching engine.

These tests use hand-built event dictionaries, so they need no .evtx files
and run in well under a second.  Run them with:  python -m pytest -q
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import (  # noqa: E402
    apply_threshold,
    evaluate,
    field_matches,
    load_rules,
    rule_matches,
)

RULES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "rules")
SYSMON = "Microsoft-Windows-Sysmon/Operational"


def rule_by_id(rule_id):
    return next(r for r in load_rules(RULES_DIR) if r["id"] == rule_id)


# --- field_matches: the seven operators -------------------------------------

def test_equals_is_exact():
    assert field_matches("1", {"equals": "1"})
    assert not field_matches("10", {"equals": "1"})


def test_equals_any():
    assert field_matches("104", {"equals_any": ["104", "1102"]})
    assert not field_matches("4624", {"equals_any": ["104", "1102"]})


def test_contains_any_is_case_insensitive_substring():
    cond = {"contains_any": ["powershell.exe"]}
    assert field_matches(r"C:\Windows\System32\WindowsPowerShell\v1.0\PowerShell.EXE", cond)
    assert not field_matches(r"C:\Windows\System32\cmd.exe", cond)


def test_contains_all_requires_every_item():
    cond = {"contains_all": ["-enc", "-nop"]}
    assert field_matches("powershell -nop -enc AAAA", cond)
    assert not field_matches("powershell -enc AAAA", cond)


def test_not_contains_excludes():
    cond = {"not_contains": ["msmpeng.exe"]}
    assert field_matches(r"C:\tools\evil.exe", cond)
    assert not field_matches(r"C:\ProgramData\Defender\MsMpEng.exe", cond)


def test_bitmask_any_matches_when_any_bit_set():
    cond = {"bitmask_any": ["0x10"]}
    assert field_matches("0x1410", cond)      # read bit set
    assert field_matches("0x1FFFFF", cond)    # PROCESS_ALL_ACCESS
    assert not field_matches("0x1000", cond)  # query-only, no read bit


def test_bitmask_none_matches_only_when_no_bit_set():
    cond = {"bitmask_none": ["0x10", "0x20", "0x08"]}
    assert field_matches("0x1000", cond)
    assert not field_matches("0x1410", cond)


@pytest.mark.parametrize("operator", ["bitmask_any", "bitmask_none"])
@pytest.mark.parametrize("bad_value", [None, "", "not-hex"])
def test_bitmask_with_non_hex_value_never_matches(operator, bad_value):
    assert not field_matches(bad_value, {operator: ["0x10"]})


def test_missing_field_is_treated_as_empty_string():
    assert not field_matches(None, {"contains_any": ["x"]})
    assert field_matches(None, {"not_contains": ["x"]})


def test_unknown_operator_raises():
    with pytest.raises(ValueError):
        field_matches("a", {"starts_with": "a"})


def test_multiple_operators_in_one_condition_are_anded():
    cond = {"contains_any": ["cmd"], "not_contains": ["safe"]}
    assert field_matches("cmd.exe", cond)
    assert not field_matches("cmd-safe.exe", cond)


# --- rule_matches: log source scoping and AND across fields -----------------

def make_rule(**overrides):
    rule = {
        "id": "t",
        "logsource": {"channel": SYSMON},
        "detection": {"EventID": {"equals": "1"}, "Image": {"contains_any": ["cmd.exe"]}},
    }
    rule.update(overrides)
    return rule


def test_all_fields_must_match():
    rule = make_rule()
    assert rule_matches({"Channel": SYSMON, "EventID": "1", "Image": "cmd.exe"}, rule)
    assert not rule_matches({"Channel": SYSMON, "EventID": "1", "Image": "calc.exe"}, rule)
    assert not rule_matches({"Channel": SYSMON, "EventID": "3", "Image": "cmd.exe"}, rule)


def test_channel_scoping_blocks_same_event_id_elsewhere():
    rule = make_rule()
    other = {"Channel": "Security", "EventID": "1", "Image": "cmd.exe"}
    assert not rule_matches(other, rule)


def test_provider_scoping():
    rule = make_rule(logsource={"provider": "Microsoft-Windows-Eventlog"},
                     detection={"EventID": {"equals_any": ["104", "1102"]}})
    assert rule_matches({"Provider": "Microsoft-Windows-Eventlog", "EventID": "1102"}, rule)
    assert not rule_matches({"Provider": "Some-Other-Provider", "EventID": "1102"}, rule)


def test_rule_without_logsource_matches_any_channel():
    rule = make_rule()
    del rule["logsource"]
    assert rule_matches({"Channel": "Anything", "EventID": "1", "Image": "cmd.exe"}, rule)


# --- apply_threshold: second-stage aggregation ------------------------------

def threshold_rule(n=3):
    return {"threshold": {"distinct_field": "Image", "min_count": n}}


def events_for(*images):
    return [{"Image": i} for i in images]


def test_threshold_not_met_returns_nothing():
    matches = events_for(r"C:\Windows\System32\whoami.exe", r"C:\Windows\System32\nltest.exe")
    assert apply_threshold(matches, threshold_rule(3)) == []


def test_threshold_met_returns_all_matches():
    matches = events_for(r"C:\a\whoami.exe", r"C:\a\nltest.exe", r"C:\a\systeminfo.exe")
    assert apply_threshold(matches, threshold_rule(3)) == matches


def test_threshold_counts_distinct_binaries_not_repeats():
    matches = events_for(*([r"C:\a\whoami.exe"] * 10))
    assert apply_threshold(matches, threshold_rule(3)) == []


def test_threshold_ignores_path_and_case():
    matches = events_for(r"C:\a\whoami.exe", r"D:\other\WHOAMI.EXE", r"C:\a\nltest.exe")
    assert apply_threshold(matches, threshold_rule(3)) == []


def test_rule_without_threshold_passes_matches_through():
    matches = events_for("a", "b")
    assert apply_threshold(matches, {}) == matches


# --- evaluate ---------------------------------------------------------------

def test_evaluate_returns_one_entry_per_rule():
    rules = [make_rule(id="a"), make_rule(id="b", detection={"EventID": {"equals": "99"}})]
    events = [{"Channel": SYSMON, "EventID": "1", "Image": "cmd.exe"}]
    results = evaluate(events, rules)
    assert set(results) == {"a", "b"}
    assert len(results["a"]) == 1
    assert results["b"] == []


# --- regression tests for the findings documented in the README -------------

def sysmon_access(source, granted, target=r"C:\Windows\System32\lsass.exe"):
    return {"Channel": SYSMON, "EventID": "10", "SourceImage": source,
            "TargetImage": target, "GrantedAccess": granted}


def test_finding_2_lsass_rule_needs_read_rights():
    rule = rule_by_id("lsass_process_access")
    assert rule_matches(sysmon_access(r"C:\tools\dump.exe", "0x1410"), rule)
    assert rule_matches(sysmon_access(r"C:\tools\dump.exe", "0x1FFFFF"), rule)
    assert not rule_matches(sysmon_access(r"C:\tools\dump.exe", "0x1000"), rule)


def test_finding_2_query_only_handles_go_to_the_low_confidence_rule():
    rule = rule_by_id("lsass_query_only_access")
    assert rule.get("confidence") == "low"
    assert rule_matches(sysmon_access(r"C:\tools\ppldump.exe", "0x1000"), rule)
    assert not rule_matches(sysmon_access(r"C:\tools\ppldump.exe", "0x1410"), rule)


def test_finding_3_known_limitation_allowlisted_process_is_invisible():
    """Documents a KNOWN WEAKNESS, not desired behaviour.

    services.exe is allowlisted, so full-access LSASS handles from it are
    ignored -- which is exactly how the PPLdump KnownDlls-hijack sample hid
    its strongest event.  If this test ever fails, the rule was changed and
    the README's finding 3 should be revisited.
    """
    rule = rule_by_id("lsass_process_access")
    event = sysmon_access(r"C:\Windows\System32\services.exe", "0x1FFFFF")
    assert not rule_matches(event, rule)


def test_finding_4_recon_needs_three_distinct_utilities():
    rule = rule_by_id("discovery_recon_burst")

    def proc(image):
        return {"Channel": SYSMON, "EventID": "1", "Image": image}

    one = evaluate([proc(r"C:\Windows\System32\whoami.exe")], [rule])
    three = evaluate([proc(r"C:\Windows\System32\whoami.exe"),
                      proc(r"C:\Windows\System32\nltest.exe"),
                      proc(r"C:\Windows\System32\systeminfo.exe")], [rule])
    assert one["discovery_recon_burst"] == []
    assert len(three["discovery_recon_burst"]) == 3


def test_finding_1_log_clearing_rule_is_marked_low_confidence():
    assert rule_by_id("event_log_cleared").get("confidence") == "low"


# --- every rule file is well-formed -----------------------------------------

KNOWN_OPERATORS = {"equals", "equals_any", "contains_any", "contains_all",
                   "not_contains", "bitmask_any", "bitmask_none"}
ALL_RULES = load_rules(RULES_DIR)


def test_expected_number_of_rules_loaded():
    assert len(ALL_RULES) == 27


def test_rule_ids_are_unique():
    ids = [r["id"] for r in ALL_RULES]
    assert len(ids) == len(set(ids))


@pytest.mark.parametrize("rule", ALL_RULES, ids=lambda r: r["id"])
def test_rule_is_well_formed(rule):
    for key in ("id", "title", "attack", "detection"):
        assert key in rule, f"missing '{key}'"
    assert os.path.basename(rule["_path"]) == rule["id"] + ".yml", "file name should match id"
    assert rule["attack"].startswith("T"), "attack should be an ATT&CK technique id"
    assert rule.get("confidence", "normal") in ("low", "normal")
    for field, condition in rule["detection"].items():
        unknown = set(condition) - KNOWN_OPERATORS
        assert not unknown, f"{field}: unknown operator(s) {unknown}"
    if "threshold" in rule:
        assert {"distinct_field", "min_count"} <= set(rule["threshold"])
