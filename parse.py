import sys
import json
import xml.etree.ElementTree as ET
import Evtx.Evtx as evtx


def flatten(record_xml):
    """Turn one event's XML into a flat dictionary."""
    root = ET.fromstring(record_xml)
    event = {}

    system = root.find("{*}System")
    if system is not None:
        for tag in ("EventID", "Channel", "Computer"):
            node = system.find("{*}" + tag)
            if node is not None:
                event[tag] = node.text

        created = system.find("{*}TimeCreated")
        if created is not None:
            event["TimeCreated"] = created.get("SystemTime")

        provider = system.find("{*}Provider")
        if provider is not None:
            event["Provider"] = provider.get("Name")

    data = root.find("{*}EventData")
    if data is not None:
        for item in data.findall("{*}Data"):
            name = item.get("Name")
            if name:
                event[name] = item.text

    return event


def parse_file(path):
    """Parse every event in an .evtx file into a list of dictionaries."""
    events = []
    with evtx.Evtx(path) as log:
        for record in log.records():
            try:
                events.append(flatten(record.xml()))
            except ET.ParseError:
                continue
    return events


if __name__ == "__main__":
    events = parse_file(sys.argv[1])
    print(f"Parsed {len(events)} events\n")
    for event in events[:3]:
        print(json.dumps(event, indent=2))
        hits = [
        e for e in events
        if "encodedcommand" in (e.get("CommandLine") or "").lower()
    ]
    print(f"\n>>> {len(hits)} events matched 'EncodedCommand'")
    for hit in hits[:2]:
        print(hit.get("CommandLine"))