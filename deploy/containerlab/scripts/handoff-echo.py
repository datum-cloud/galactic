#!/usr/bin/env python3
# Copyright 2026 Datum Cloud, Inc.
#
# SPDX-License-Identifier: AGPL-3.0-or-later
"""A UDP echo server for the Local handoff checks.

Usage: handoff-echo.py ADDRESS PORT REPLY

Answers each datagram's first line, cut to 200 bytes so a large request
gets a small answer, with "<line> REPLY", from ADDRESS, so a listener bound
to a VIP answers from the VIP. An empty datagram, which socat
sends at the end of its input, gets no answer.
"""

import socket
import sys


def main():
    addr, port, reply = sys.argv[1], int(sys.argv[2]), sys.argv[3].encode()
    s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((addr, port))
    while True:
        data, peer = s.recvfrom(65535)
        if not data:
            continue
        try:
            s.sendto(data.split(b"\n", 1)[0][:200] + b" " + reply + b"\n", peer)
        except OSError:
            # The rig changes routes between cells; a late datagram whose
            # answer has no route must not end the server.
            continue


if __name__ == "__main__":
    sys.exit(main())
