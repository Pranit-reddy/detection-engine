"""Print the raw XML of the first few events in an .evtx file.

Useful for seeing which fields exist before writing a rule.
Usage: python peek.py <file.evtx> [count]
"""
import sys
import Evtx.Evtx as evtx


def peek(path, count=3):
    with evtx.Evtx(path) as log:
        for i, record in enumerate(log.records()):
            if i >= count:
                break
            print(record.xml())


if __name__ == "__main__":
    peek(sys.argv[1], int(sys.argv[2]) if len(sys.argv) > 2 else 3)
