import sys
from parse import parse_file

BROWSERS = ("iexplore.exe", "chrome.exe", "firefox.exe", "msedge.exe", "outlook.exe")
SHELLS = ("cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe")


def browser_spawns_shell(event):
    if event.get("EventID") != "1":
        return False
    parent = (event.get("ParentImage") or "").lower()
    child = (event.get("Image") or "").lower()
    return any(b in parent for b in BROWSERS) and any(s in child for s in SHELLS)


def unbacked_call_trace(event):
    if event.get("EventID") != "10":
        return False
    return "UNKNOWN(" in (event.get("CallTrace") or "")


RULES = {
    "Browser or Office spawned a shell": browser_spawns_shell,
    "Process access from unbacked memory": unbacked_call_trace,
}

if __name__ == "__main__":
    events = parse_file(sys.argv[1])
    print(f"Parsed {len(events)} events\n")
    for name, rule in RULES.items():
        hits = [e for e in events if rule(e)]
        status = f"ALERT ({len(hits)})" if hits else "clear"
        print(f"[{status:>10}] {name}")
        for hit in hits[:2]:
            print(f"             {hit.get('ParentImage') or hit.get('SourceImage')}")
            print(f"          -> {hit.get('Image') or hit.get('TargetImage')}")