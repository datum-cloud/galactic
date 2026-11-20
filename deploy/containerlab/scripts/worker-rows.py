"""Print egress_route_table entries outside the given VRF tables.

Reads `bpftool -j map dump` output on stdin, formatted or raw, and prints one
line per entry whose table is not in argv[1], a "|"-separated list of table
IDs, as verify-worker.sh snapshots it. argv[2], when given, lists the tables
a VRF on the node holds; an entry of any other table is garbage the router's
GC sweeps, and is printed as stale_egress_row instead. The raw layout is
struct egress_route_key and egress_route_value, packed and little endian, as
worker-fabric.sh decodes it.
"""

import json
import struct
import sys

skip = {int(t) for t in sys.argv[1].split("|") if t} if len(sys.argv) > 1 else set()
live = {int(t) for t in sys.argv[2].split("|") if t} if len(sys.argv) > 2 else None


def raw(field):
    return bytes(int(b, 16) for b in field)


try:
    entries = json.load(sys.stdin)
except ValueError:
    print("egress_route_table unreadable")
    sys.exit(0)
out = []
for e in entries:
    f = e.get("formatted")
    if f:
        table, key, value = f["key"]["table_id"], f["key"], f["value"]
        line = json.dumps(key, sort_keys=True) + " " + json.dumps(value, sort_keys=True)
    else:
        kb, vb = raw(e["key"]), raw(e["value"])
        table = struct.unpack_from("<I", kb, 4)[0]
        line = kb.hex() + " " + vb.hex()
    if live is not None and table not in live:
        out.append("stale_egress_row " + line)
        continue
    if table in skip:
        continue
    out.append("egress_route_table " + line)
print("\n".join(sorted(out)))
