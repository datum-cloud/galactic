"""Print egress_route_table entries outside the given VRF tables.

Reads `bpftool -j map dump` output on stdin, formatted or raw, and prints one
line per entry whose table is not in argv[1], a "|"-separated list of table
IDs, as verify-worker.sh snapshots it. The raw layout is struct
egress_route_key and egress_route_value, packed and little endian, as
worker-fabric.sh decodes it.
"""

import json
import struct
import sys

skip = {int(t) for t in sys.argv[1].split("|") if t} if len(sys.argv) > 1 else set()


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
    if table in skip:
        continue
    out.append("egress_route_table " + line)
print("\n".join(sorted(out)))
