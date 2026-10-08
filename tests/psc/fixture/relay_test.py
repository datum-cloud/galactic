"""Check the generic producer protocol without a DNS service."""
import json
import pathlib
import socket
import subprocess
import unittest


class ProducerProtocolTest(unittest.TestCase):
    def test_udp_and_tcp_destinations(self):
        for transport in ("udp", "tcp"):
            with self.subTest(transport=transport):
                kind = socket.SOCK_DGRAM if transport == "udp" else socket.SOCK_STREAM
                with socket.socket(socket.AF_INET6, kind) as reservation:
                    reservation.bind(("::1", 0))
                    port = reservation.getsockname()[1]
                process = subprocess.Popen(
                    ["python3", str(pathlib.Path(__file__).with_name("relay.py")),
                     "root", transport, "::1", str(port), "fd70:100::10", "8443", "-"],
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                try:
                    self.assertTrue(process.stdout.readline().startswith("READY"))
                    payload = b"consumer-a request"
                    with socket.socket(socket.AF_INET6, kind) as client:
                        client.settimeout(3)
                        if transport == "tcp":
                            client.connect(("::1", port))
                            client.sendall(len(payload).to_bytes(2, "big") + payload)
                            length = int.from_bytes(client.recv(2), "big")
                            response = b""
                            while len(response) < length:
                                response += client.recv(length - len(response))
                        else:
                            client.sendto(payload, ("::1", port))
                            response, _ = client.recvfrom(65535)
                    self.assertEqual(json.loads(response), {
                        "destination": "fd70:100::10", "payload": payload.decode()})
                finally:
                    process.terminate()
                    process.wait(timeout=3)
                    process.stdout.close()


if __name__ == "__main__":
    unittest.main()
