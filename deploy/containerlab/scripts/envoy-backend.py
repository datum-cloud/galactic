#!/usr/bin/env python3
# Copyright 2026 Datum Cloud, Inc.
#
# SPDX-License-Identifier: AGPL-3.0-or-later
"""An HTTP/1.1 keep-alive backend for the Envoy socket checks.

Usage: envoy-backend.py SITE VPC NODE [PORT]

Listens on [::]:PORT (8080) and answers every GET with a JSON object:

    {"site": SITE, "vpc": VPC, "node": NODE, "nonce": <X-Nonce>,
     "peer": {"address": <client address>, "port": <client port>},
     "local": {"address": <own address>, "port": <own port>}}

SITE is "local" or "remote", as the Envoy route names the backend. The nonce
is echoed so a capture can find the reply as well as the request. Each
request is logged to stdout with its nonce and the connection it came on, so
a pooled connection shows as one peer port carrying several nonces.
"""

import json
import socket
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Server(ThreadingHTTPServer):
    address_family = socket.AF_INET6
    daemon_threads = True
    allow_reuse_address = True


def handler(site, vpc, node):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        # An idle pooled connection closes after this, so a stopped run
        # leaves nothing open for long.
        timeout = 300

        def do_GET(self):
            peer = self.client_address
            local = self.connection.getsockname()
            nonce = self.headers.get("X-Nonce", "")
            body = json.dumps({
                "site": site,
                "vpc": vpc,
                "node": node,
                "nonce": nonce,
                "peer": {"address": peer[0], "port": peer[1]},
                "local": {"address": local[0], "port": local[1]},
            }).encode() + b"\n"
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            print(f"nonce={nonce} peer=[{peer[0]}]:{peer[1]} path={self.path}", flush=True)

        def log_message(self, fmt, *args):
            pass

    return Handler


def main():
    if len(sys.argv) < 4:
        print(__doc__, file=sys.stderr)
        return 2
    site, vpc, node = sys.argv[1], sys.argv[2], sys.argv[3]
    port = int(sys.argv[4]) if len(sys.argv) > 4 else 8080
    srv = Server(("::", port), handler(site, vpc, node))
    print(f"listening on [::]:{port} site={site} vpc={vpc} node={node}", flush=True)
    srv.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
