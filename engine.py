import sys
import glob
import yaml
from parse import parse_file


def load_rules(directory="rules"):
    rules = []
    for path in sorted(glob.glob(f"{directory}/*.yml")):
        with open(path) as f:
            rule = yaml.safe_load(f)
            rule["_path"] = path
            rules.append(rule)
    return rules


def field_matches(value, condition):
    """Check one field's value against one field's condition block."""
    value = "" if value is None else str(value)
    lowered = value.lower()

    for operator, expected in condition.items():
        if operator == "equals":
            if value != str(expected):
                return False
        elif operator == "equals_any":
            if value not in [str(item) for item in expected]:
                return False
        elif operator == "contains_any":
            if not any(str(item).lower() in lowered for item in expected):
                return False
        elif operator == "contains_all":
            if not all(str(item).lower() in lowered for item in expected):
                return False
        elif operator == "not_contains":
            if any(str(item).lower() in lowered for item in expected):
                return False
        elif operator == "bitmask_any":
            try:
                actual = int(value, 16)
            except (TypeError, ValueError):
                return False
            if not any(actual & int(str(bit), 16) for bit in expected):
                return False
        elif operator == "bitmask_none":
            try:
                actual = int(value, 16)
            except (TypeError, ValueError):
                return False
            if any(actual & int(str(bit), 16) for bit in expected):
                return False
        else:
            raise ValueError(f"Unknown operator: {operator}")
    return True


def rule_matches(event, rule):
    source = rule.get("logsource", {})
    if "channel" in source:
        if source["channel"].lower() not in (event.get("Channel") or "").lower():
            return False
    if "provider" in source:
        if source["provider"].lower() not in (event.get("Provider") or "").lower():
            return False
    for field, condition in rule["detection"].items():
        if not field_matches(event.get(field), condition):
            return False
    return True


def threshold_key(event, field):
    """How a value is normalised when counting distinct values for a threshold:
    lower-cased, with any directory path removed (so C:\\a\\Whoami.exe and
    D:\\b\\whoami.exe count as one binary)."""
    return str(event.get(field)).lower().split("\\")[-1]


def apply_threshold(matches, rule):
    """Second stage: require N distinct values of a field across matches."""
    threshold = rule.get("threshold")
    if not threshold:
        return matches
    field = threshold["distinct_field"]
    needed = int(threshold["min_count"])
    seen = {threshold_key(e, field) for e in matches if e.get(field)}
    return matches if len(seen) >= needed else []


def evaluate(events, rules):
    return {
        rule["id"]: apply_threshold(
            [e for e in events if rule_matches(e, rule)], rule
        )
        for rule in rules
    }


if __name__ == "__main__":
    rules = load_rules()
    events = parse_file(sys.argv[1])
    results = evaluate(events, rules)

    print(f"Parsed {len(events)} events against {len(rules)} rules\n")
    for rule in rules:
        hits = results[rule["id"]]
        status = f"ALERT ({len(hits)})" if hits else "clear"
        print(f"[{status:>10}] {rule['title']}  [{rule['attack']}]")
        for hit in hits[:2]:
            src = hit.get("ParentImage") or hit.get("SourceImage") or "?"
            dst = hit.get("Image") or hit.get("TargetImage") or "?"
            print(f"             {src}\n          -> {dst}")