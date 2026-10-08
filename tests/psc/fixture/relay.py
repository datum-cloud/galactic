#!/usr/bin/env python3
"""Persistent fixture relay; network authorization stays in Galactic's TC path."""
import json
import os
import time
import socket
import sys
import threading

mode, transport, listen_address, listen_port, target, target_port, source = sys.argv[1:]
socket_type = socket.SOCK_DGRAM if transport == "udp" else socket.SOCK_STREAM


def receive_frame(conn):
    header = receive_exact(conn, 2)
    return receive_exact(conn, int.from_bytes(header, "big"))


def receive_exact(conn, length):
    data = b""
    while len(data) < length:
        chunk = conn.recv(length - len(data))
        if not chunk:
            raise OSError("connection closed before service frame completed")
        data += chunk
    return data


def exchange(query):
    if mode == "root":
        return json.dumps({"destination": target, "payload": query.decode()}).encode()
    with socket.socket(socket.AF_INET6, socket_type) as upstream:
        upstream.settimeout(3)
        if transport == "tcp":
            upstream.connect((target, int(target_port)))
            upstream.sendall(len(query).to_bytes(2, "big") + query)
            return receive_frame(upstream)
        upstream.sendto(query, (target, int(target_port)))
        response, _ = upstream.recvfrom(65535)
        return response


def save_trace(trace):
    path = os.path.join(os.path.dirname(__file__), "psc-delay-trace.json")
    temp = path + f".{os.getpid()}.{threading.get_ident()}"
    with open(temp, "w", encoding="utf-8") as trace_file:
        json.dump(trace, trace_file)
    os.replace(temp, path)


def delay_response(received_at):
    if mode != "producer":
        return
    directive = os.path.join(os.path.dirname(__file__), "psc-delay.json")
    claim = directive + f".{os.getpid()}.{threading.get_ident()}"
    try:
        os.rename(directive, claim)
    except FileNotFoundError:
        return
    try:
        with open(claim, encoding="utf-8") as source_file:
            directive = json.load(source_file)
            seconds = directive["seconds"]
    finally:
        os.unlink(claim)
    trace = {"token": directive["token"], "destination": listen_address, "transport": transport,
             "requestReceivedAt": received_at, "upstreamResponseAt": time.time(), "seconds": seconds}
    save_trace(trace)
    print(f"DELAY producer {transport} {seconds}s after upstream response token={trace['token']}", flush=True)
    time.sleep(seconds)
    trace["replyAttemptAt"] = time.time()
    save_trace(trace)
    print(f"DELAY_REPLY producer {transport} token={trace['token']} time={trace['replyAttemptAt']}", flush=True)


def serve_tcp(conn):
    with conn:
        conn.settimeout(4)
        try:
            while True:
                query = receive_frame(conn)
                received_at = time.time()
                response = exchange(query)
                delay_response(received_at)
                conn.sendall(len(response).to_bytes(2, "big") + response)
        except (OSError, socket.timeout) as error:
            print(f"{mode} TCP: {error}", flush=True)


def serve_udp(listener, query, peer, received_at):
    try:
        response = exchange(query)
        delay_response(received_at)
        listener.sendto(response, peer)
    except (OSError, socket.timeout) as error:
        print(f"{mode} UDP: {error}", flush=True)


with socket.socket(socket.AF_INET6, socket_type) as listener:
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((listen_address, int(listen_port)))
    if transport == "tcp":
        listener.listen(32)
    print(f"READY {mode} {transport} {listen_address}:{listen_port}", flush=True)
    while True:
        if transport == "tcp":
            conn, _ = listener.accept()
            threading.Thread(target=serve_tcp, args=(conn,), daemon=True).start()
        else:
            query, peer = listener.recvfrom(65535)
            threading.Thread(target=serve_udp, args=(listener, query, peer, time.time()), daemon=True).start()
