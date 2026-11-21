#!/usr/bin/env python3
# Copyright 2026 Datum Cloud, Inc.
#
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Count the Envoy socket checks' requests and replies in pcap files.

Usage: envoy-pcap.py --gateway ADDR --nonces FILE PCAP...

FILE holds one "<nonce>\\t<key>" line per request. A packet carrying a nonce
counts for the nonce's key, as a request when its innermost IPv6 source is
the gateway and as a reply when its innermost IPv6 destination is, so a
packet inside SRv6 or IPv6-in-IPv6 counts by the addresses it carries. Each
also counts under req_srv6 or rep_srv6 when its outer header is
encapsulated. Prints one JSON object, summed over every file:

    {"<key>": {"req": N, "rep": N, "req_srv6": N, "rep_srv6": N}, ...}

Every key in FILE appears, at zero when nothing carried it. The pcap reading
is handoff-pcap.py's.
"""

import argparse
import importlib.util
import ipaddress
import json
import os
import sys

# Loading handoff-pcap.py must not leave bytecode beside the lab scripts.
sys.dont_write_bytecode = True
_spec = importlib.util.spec_from_file_location(
    "handoff_pcap", os.path.join(os.path.dirname(os.path.abspath(__file__)), "handoff-pcap.py"))
hp = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(hp)


def innermost(frame, off):
    """Offset of the innermost IPv6 header under the one at off."""
    for _ in range(4):
        nexthdr, pos = frame[off + 6], off + 40
        inner = None
        for _ in range(8):
            if nexthdr == 41:
                inner = pos
                break
            if nexthdr not in hp.EXT_HEADERS or len(frame) < pos + 2:
                break
            length = 8 if nexthdr == 44 else (frame[pos + 1] + 1) * 8
            nexthdr = frame[pos]
            pos += length
        if inner is None or len(frame) < inner + 40 or frame[inner] >> 4 != 6:
            return off
        off = inner
    return off


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--gateway", required=True)
    ap.add_argument("--nonces", required=True)
    ap.add_argument("files", nargs="*")
    args = ap.parse_args()
    gw = ipaddress.IPv6Address(args.gateway).packed

    keys = {}
    with open(args.nonces) as f:
        for line in f:
            parts = line.rstrip("\n").split("\t")
            if len(parts) == 2 and parts[0]:
                keys[parts[0].encode()] = parts[1]
    out = {k: {"req": 0, "rep": 0, "req_srv6": 0, "rep_srv6": 0} for k in keys.values()}

    for path in args.files:
        for linktype, frame in hp.records(path):
            off = hp.ipv6_offset(linktype, frame)
            if off is None:
                continue
            hit = [k for n, k in keys.items() if n in frame]
            if not hit:
                continue
            encap = hp.encapsulated(frame, off)
            inner = innermost(frame, off)
            src, dst = frame[inner + 8 : inner + 24], frame[inner + 24 : inner + 40]
            for k in hit:
                if src == gw:
                    out[k]["req"] += 1
                    out[k]["req_srv6"] += int(encap)
                elif dst == gw:
                    out[k]["rep"] += 1
                    out[k]["rep_srv6"] += int(encap)
    json.dump(out, sys.stdout, sort_keys=True)
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
