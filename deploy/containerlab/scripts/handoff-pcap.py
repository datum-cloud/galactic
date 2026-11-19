#!/usr/bin/env python3
# Copyright 2026 Datum Cloud, Inc.
#
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Count the packets in pcap files that carry a probe nonce.

Usage: handoff-pcap.py [--nonce TEXT] [--src ADDR] [--dst ADDR]
                        [--proto tcp|udp] [--dport PORT] [--srv6] FILE...

A packet counts when its frame contains the nonce bytes anywhere, including
inside an encapsulation, and its outer IPv6 source and destination match
--src and --dst when given. --proto and --dport match the transport header
that directly follows the outer IPv6 header, for a packet with no payload to
carry a nonce, such as a TCP SYN to a denied port. --srv6 counts only packets that carry an IPv6
Routing Header of type 4 (an SRv6 Segment Routing Header) or that are IPv6
in IPv6, the forms the uSID datapath encapsulates in. The sum over every
file is printed. A missing or empty file counts as zero, and a truncated
one counts up to its last whole record.
"""

import argparse
import ipaddress
import struct
import sys

ETH_P_IPV6 = 0x86DD
VLAN_TYPES = (0x8100, 0x88A8)
LINKTYPE_ETHERNET = 1
LINKTYPE_LINUX_SLL = 113
LINKTYPE_LINUX_SLL2 = 276
LINKTYPE_RAW = 101
EXT_HEADERS = (0, 43, 44, 51, 60)


def records(path):
    try:
        with open(path, "rb") as f:
            data = f.read()
    except FileNotFoundError:
        return
    if len(data) < 24:
        return
    magic = data[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        order = "<"
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        order = ">"
    else:
        raise ValueError(f"{path}: not a pcap file")
    linktype = struct.unpack(order + "I", data[20:24])[0] & 0x0FFFFFFF
    off = 24
    while off + 16 <= len(data):
        incl = struct.unpack(order + "I", data[off + 8 : off + 12])[0]
        off += 16
        if off + incl > len(data):
            return
        yield linktype, data[off : off + incl]
        off += incl


def ipv6_offset(linktype, frame):
    """Offset of the outer IPv6 header, or None."""
    if linktype == LINKTYPE_ETHERNET:
        off, ethertype = 14, None
        if len(frame) < 14:
            return None
        ethertype = struct.unpack(">H", frame[12:14])[0]
        while ethertype in VLAN_TYPES and len(frame) >= off + 4:
            ethertype = struct.unpack(">H", frame[off + 2 : off + 4])[0]
            off += 4
    elif linktype == LINKTYPE_LINUX_SLL:
        off = 16
        ethertype = struct.unpack(">H", frame[14:16])[0] if len(frame) >= 16 else None
    elif linktype == LINKTYPE_LINUX_SLL2:
        off = 20
        ethertype = struct.unpack(">H", frame[0:2])[0] if len(frame) >= 20 else None
    elif linktype == LINKTYPE_RAW:
        off, ethertype = 0, ETH_P_IPV6
    else:
        return None
    if ethertype != ETH_P_IPV6 or len(frame) < off + 40 or frame[off] >> 4 != 6:
        return None
    return off


def encapsulated(frame, off):
    """True for an SRv6 Routing Header (type 4) or IPv6-in-IPv6 chain."""
    nexthdr = frame[off + 6]
    pos = off + 40
    for _ in range(8):
        if nexthdr == 41:
            return True
        if nexthdr == 43 and len(frame) >= pos + 4 and frame[pos + 2] == 4:
            return True
        if nexthdr not in EXT_HEADERS or len(frame) < pos + 2:
            return False
        length = 8 if nexthdr == 44 else (frame[pos + 1] + 1) * 8
        nexthdr = frame[pos]
        pos += length
    return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--nonce", default="")
    ap.add_argument("--proto", choices=("tcp", "udp"))
    ap.add_argument("--dport", type=int)
    ap.add_argument("--src")
    ap.add_argument("--dst")
    ap.add_argument("--srv6", action="store_true")
    ap.add_argument("files", nargs="*")
    args = ap.parse_args()
    nonce = args.nonce.encode()
    src = ipaddress.IPv6Address(args.src).packed if args.src else None
    dst = ipaddress.IPv6Address(args.dst).packed if args.dst else None

    total = 0
    for path in args.files:
        for linktype, frame in records(path):
            if nonce not in frame:
                continue
            off = ipv6_offset(linktype, frame)
            if off is None:
                if src or dst or args.srv6 or args.proto or args.dport is not None:
                    continue
                total += 1
                continue
            if src and frame[off + 8 : off + 24] != src:
                continue
            if dst and frame[off + 24 : off + 40] != dst:
                continue
            if args.srv6 and not encapsulated(frame, off):
                continue
            if args.proto or args.dport is not None:
                nexthdr = frame[off + 6]
                if args.proto and nexthdr != {"tcp": 6, "udp": 17}[args.proto]:
                    continue
                if nexthdr not in (6, 17) or len(frame) < off + 44:
                    continue
                if args.dport is not None and struct.unpack(">H", frame[off + 42 : off + 44])[0] != args.dport:
                    continue
            total += 1
    print(total)


if __name__ == "__main__":
    sys.exit(main())
