#!/usr/bin/env python3
"""Check the same consumer address and source tuple in different VPCs."""
import json
import os
import socket
import sys

transport, expected, payload = sys.argv[1:4]
timeout = float(sys.argv[4]) if len(sys.argv) > 4 else 2
frontend = os.environ.get("PSC_FRONTEND", "fd70:ffff::10")
port = int(os.environ.get("PSC_PORT", "8443"))


def receive_exact(conn, length):
    data = b""
    while len(data) < length:
        chunk = conn.recv(length - len(data))
        if not chunk:
            raise OSError("service frame truncated")
        data += chunk
    return data


kind = socket.SOCK_DGRAM if transport == "udp" else socket.SOCK_STREAM
with socket.socket(socket.AF_INET6, kind) as client:
    client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    client.settimeout(timeout)
    client.bind(("fd00:c::2", 40530))
    try:
        request = payload.encode()
        if transport == "tcp":
            client.connect((frontend, port))
            client.sendall(len(request).to_bytes(2, "big") + request)
            response = receive_exact(client, int.from_bytes(receive_exact(client, 2), "big"))
            peer = client.getpeername()[0]
        else:
            client.sendto(request, (frontend, port))
            response, address = client.recvfrom(65535)
            peer = address[0]
    except OSError as error:
        print(json.dumps({"transport": transport, "timeout": True, "error": str(error)}))
        sys.exit(3)
result = json.loads(response)
result.update({"transport": transport, "peer": peer, "timeout": False})
print(json.dumps(result))
if peer != frontend or result["destination"] != expected or result["payload"] != payload:
    raise RuntimeError("response reached the wrong consumer or producer")
