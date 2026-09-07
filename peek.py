import sys
import Evtx.Evtx as evtx

with evtx.Evtx(sys.argv[1]) as log:
    for i, record in enumerate(log.records()):
        print(record.xml())
        if i >= 2:
            break