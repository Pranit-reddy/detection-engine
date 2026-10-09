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


def iter_events(path, chunk_range=None):
    """Yield one flat dictionary per event, without holding the file in memory.

    An .evtx file is a sequence of independent 64 KB chunks.  chunk_range=(start,
    stop) restricts parsing to chunks start..stop-1, which lets very large logs
    be split across processes.  Yielding every range in order gives exactly the
    same events, in the same order, as parsing the whole file.
    """
    with evtx.Evtx(path) as log:
        for index, chunk in enumerate(log.chunks()):
            if chunk_range is not None:
                if index < chunk_range[0]:
                    continue
                if index >= chunk_range[1]:
                    break
            for record in chunk.records():
                try:
                    yield flatten(record.xml())
                except ET.ParseError:
                    continue


def count_chunks(path):
    """Number of 64 KB chunks in an .evtx file (used to split work)."""
    with evtx.Evtx(path) as log:
        return sum(1 for _ in log.chunks())


def parse_file(path):
    """Parse every event in an .evtx file into a list of dictionaries."""
    return list(iter_events(path))


if __name__ == "__main__":
    events = parse_file(sys.argv[1])
    print(f"Parsed {len(events)} events\n")
    for event in events[:3]:
        print(json.dumps(event, indent=2))