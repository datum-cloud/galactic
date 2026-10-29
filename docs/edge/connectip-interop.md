# CONNECT-IP interoperability over HTTP/3 and HTTP/2

This is the protocol feasibility proof for CONNECT-IP ([RFC 9484](https://www.rfc-editor.org/rfc/rfc9484)). It shows that an independent client can exchange 1280-byte inner IPv6 packets in both directions over HTTP/3 and over HTTP/2, and that HTTP/2 works with UDP/443 blocked. It also records the server and client stacks chosen for that proof and what they lack. The proof first ran against a test-only HTTP/2 prototype (#973); since #981 it runs against the production listener, `connectip.Server.ServeTLS`.

The proof uses a test admission authority and a controlled packet backend. It is not Galactic Edge provider conformance ([provider contract](provider-contract.md)) or platform qualification. Nothing here grants foundation authority or programs host networking.

## Run it

From the repository root, on a linux/amd64 host with `sudo`, `nft` and `ip`:

```sh
task test:connectip-interop
```

The task downloads Xray-core v26.10.21 (`Xray-linux-64.zip`) and checks it against the SHA-256 pinned in `Taskfile.yaml`. It then builds `tests/connectipinterop` with the race detector and runs it as root. `bin/connectip-interop/` receives:

- `results.json`, with every check's outcome and measurements;
- `servers.log`, from the server;
- `xray-<check>.log`, one per client run.

Without `CONNECTIP_INTEROP_XRAY` or root, every fixture-backed test skips. Only the capsule codec's unit tests still run.

The fixture builds three network namespaces and removes them on exit:

```text
client netns ── veth ── server netns   connectip.Server: HTTP/3 on UDP/443
  (Xray)                  │                              HTTP/2 on TCP/443
                          │ connectip.TUNBackend
                          └── TUN device ── VPC netns (UDP and TCP echo)
```

Each Xray process forwards a local TCP and UDP port to the echo server through its MASQUE outbound. Xray's own IP stack runs with a 1280-byte MTU, so each 1232-byte UDP payload becomes exactly one 1280-byte IPv6 packet inside the tunnel. A recording wrapper around the TUN backend counts every packet by size and direction. nftables counters in the server namespace count outer UDP/443 and TCP/443 packets, and the blocked-UDP check adds a counted drop rule. The server's TLS configuration records the ALPN protocol of every handshake, and the test admission counts the requests that reach it through the TCP listener.

## Selections

| Role                                | Selection                                                                                      | Why                                                                                                                                                                                                                                           |
| ----------------------------------- | ---------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| HTTP/3 server                       | `internal/edge/connectip` on `quic-go/connect-ip-go` v0.6.0 and `quic-go` v0.63.0              | The existing server, unchanged.                                                                                                                                                                                                               |
| HTTP/2 server                       | `internal/edge/connectip` (`ServeTLS`): `net/http` Extended CONNECT plus its own capsule codec | `connect-ip-go` only speaks HTTP/3: its `Conn` wraps an HTTP/3 stream, and its proxy needs `http3.HTTPStreamer`. HTTP/2 support upstream is an open request ([quic-go/connect-ip-go#41](https://github.com/quic-go/connect-ip-go/issues/41)). |
| Independent client, both transports | Xray-core v26.10.21 MASQUE outbound (`alpn` `h3` or `h2`)                                      | A released client that speaks CONNECT-IP over HTTP/3 and over HTTP/2. HTTP/2 arrived in [XTLS/Xray-core#6810](https://github.com/XTLS/Xray-core/pull/6810).                                                                                   |
| Negative-path client                | Raw clients in the harness (`quic-go` `RequestStream`; `x/net/http2` framer)                   | Malformed capsules, two requests on one connection and per-request cancellation need control no released client offers.                                                                                                                       |

Xray's CONNECT-IP layer is a fork of `connect-ip-go`. Over HTTP/3 it therefore shares code lineage with the server's library, so a protocol misreading common to both would go unnoticed there. Over HTTP/2 the server side is Galactic's own capsule codec, so the two ends are independent.

### Candidates that failed

google/quiche `masque_client` at `c607d240fb0125f41f4e8e6206a847d6bd1dbe3c` shares no code with `connect-ip-go`. As released, it cannot carry packets to these servers:

- **URL mode.** The client tunnels its own QUIC connection. `MaxPacketSizeForEncapsulatedConnections` sizes those QUIC packets to the outer datagram payload. In CONNECT-IP mode the client then prepends 48 bytes of IPv6 and UDP header, so no tunnelled packet fits in a datagram. The server accepts the request, but the client's inner handshake times out.
- **TUN mode.** `CreateTunInterface` supports IPv4 only. The servers assign IPv6 /96 prefixes only.
- **HTTP/2.** `masque_tcp_client` sends ordinary requests over HTTP/2 and has no CONNECT-IP mode.

Xray replaced quiche as the selected client. quiche still confirms the HTTP/3 server independently once the sizing is corrected. `tests/connectipinterop/quiche/Dockerfile` builds both binaries: the released one, and one whose size subtracts those 48 bytes. To run each one with `TestQuicheMasqueClientInterop`:

```sh
docker build -t connectip-quiche tests/connectipinterop/quiche
go test -c -o bin/connectip.test ./internal/edge/connectip/
for client in masque_client masque_client_patched; do
  sudo env CONNECTIP_QUICHE_CLIENT="docker run --rm --network host --entrypoint /usr/local/bin/$client connectip-quiche --dns_on_client --v=1 --stderrthreshold=0" \
    bin/connectip.test -test.run TestQuicheMasqueClientInterop -test.v -test.count=1
done
```

`--dns_on_client` makes the client send the literal target address rather than a placeholder address that the proxy would resolve. `--v=1 --stderrthreshold=0` makes it write its log, which carries the response body the test looks for, to the output the test reads.

| Binary                  | Recorded 2026-10-27                                                                                                                                                                                                  |
| ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `masque_client`         | Failed: the request was accepted, no tunnelled packet reached the server, and the inner handshake ended with `QUIC_NETWORK_IDLE_TIMEOUT`.                                                                            |
| `masque_client_patched` | Passed: the client adopted the assigned /96 and completed an HTTP/3 request to a server inside the VPC namespace. Its first packet, sent from `::` before `ADDRESS_ASSIGN` arrived, was dropped by the source check. |

## What each check proves

| Check                        | Proof                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| ---------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Round trip                   | Xray sends 20 UDP echoes, then a 256 KiB TCP echo, all byte-exact. During the UDP phase alone, the backend must see at least 20 packets of exactly 1280 bytes each way, and none larger, so each datagram crossed as one unfragmented packet. One backend session opens. ALPN is `h3` or `h2` as configured. Outer packets appear only on that transport's port. Only the HTTP/2 run's request reaches admission through the TCP listener.                                                                                                                                                   |
| Untrusted server certificate | Xray trusts an unrelated CA. No echo comes back, no backend session opens, and Xray reports `certificate signed by unknown authority`.                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| HTTP/2 with UDP/443 blocked  | With the drop rule in place, an HTTP/3 client gets no echo or session, and the drop counter rises. Then a separate HTTP/2 client completes 20 echoes of 1280-byte packets each way over TCP/443, with no UDP/443 packet dropped during its run. No automatic fallback is involved.                                                                                                                                                                                                                                                                                                           |
| Malformed input              | Two requests share one connection. One receives an oversized capsule, a malformed `ADDRESS_REQUEST`, a capsule cut off by FIN, or a datagram that is not IP or carries a spoofed source or a destination outside the advertised routes. The other must still complete a 1280-byte round trip. After the input, nothing from an ended request may reach the backend. A request that stays open sends one probe after the input, and only that probe may reach the backend. A packet with hop limit 1 must reach the backend, because RFC 9484 decrements the hop limit on encapsulation only. |
| Cancel one request           | Two requests share one connection and one is cancelled (QUIC stream reset, or HTTP/2 `RST_STREAM`). The cancelled request's backend session closes, and the other keeps forwarding.                                                                                                                                                                                                                                                                                                                                                                                                          |

On connection setup, each raw client also requires the server's SETTINGS to enable Extended CONNECT: `SETTINGS_ENABLE_CONNECT_PROTOCOL` on HTTP/2, plus HTTP Datagrams on HTTP/3.

Malformed capsules don't behave the same way on both servers:

- **Malformed address capsule, or a capsule cut off by FIN:** both servers end the request.
- **Oversized DATAGRAM capsule:** both servers keep the request open and discard the capsule as it arrives, so nothing is buffered. The client sends the whole 1 MiB value, because over HTTP/2 the request's later packets follow it on the same stream.
- **A datagram that is not IP or carries a spoofed source or a destination outside the routes:** both servers drop it without ending the request.
- **Hop limit 1 from the client:** both servers forward it unchanged.

## Recorded runs

### Production HTTP/2 listener

Recorded 2026-10-28 with `task test:connectip-interop` on the #981 branch, on the same host, Go and Xray versions as the run below. All 33 tests passed under the race detector, against one `connectip.Server` serving both transports. The HTTP/3 column of the table below still holds. These HTTP/2 results differ from the prototype's or add to them:

| Check               | HTTP/2                                                                                      |
| ------------------- | ------------------------------------------------------------------------------------------- |
| Negotiated protocol | ALPN `h2`; request admitted through the TCP listener; 364 outer TCP/443 packets, no UDP/443 |
| UDP/443 blocked     | 20 of 20 echoes, 1280 bytes each way; 35 TCP/443 packets; 0 UDP/443 dropped: passed         |
| Oversized capsule   | Request stays open, nothing buffered; only the probe reached the VPC: passed                |

### Prototype

Recorded 2026-10-27 with `task test:connectip-interop`, on base commit `1a9d0f16` with this suite applied. The host ran Fedora 44, Linux 7.1.3, Go 1.26.5 and Xray 26.10.21 (built with Go 1.27.3). Five consecutive runs, the last on the published code, each passed all 33 tests under the race detector and removed every fixture namespace. The table shows the last run.

| Check                                                  | HTTP/3                                                                       | HTTP/2                                                                              |
| ------------------------------------------------------ | ---------------------------------------------------------------------------- | ----------------------------------------------------------------------------------- |
| Negotiated protocol                                    | ALPN `h3` over QUIC; 368 outer UDP/443 packets, no TCP/443                   | ALPN `h2`; request seen as `HTTP/2.0`; 225 outer TCP/443 packets, no UDP/443        |
| 1280-byte inner packets in the UDP phase, VPC / client | 20 / 20; none larger                                                         | 20 / 20; none larger                                                                |
| UDP and TCP echo                                       | 20 of 20 datagrams, 256 KiB stream: passed                                   | 20 of 20 datagrams, 256 KiB stream: passed                                          |
| Untrusted certificate                                  | Rejected by the client; no session: passed                                   | Rejected by the client; no session: passed                                          |
| UDP/443 blocked                                        | 10 packets dropped; no echo; no session (expected failure)                   | 20 of 20 echoes, 1280 bytes each way; 36 TCP/443 packets; 0 UDP/443 dropped: passed |
| Oversized capsule                                      | Request stays open, nothing buffered; only the probe reached the VPC: passed | Request and its backend session end; nothing reached the VPC: passed                |
| Malformed `ADDRESS_REQUEST`                            | Request ends; nothing reached the VPC: passed                                | Request ends; nothing reached the VPC: passed                                       |
| Capsule truncated by FIN                               | Request ends; nothing reached the VPC: passed                                | Request ends; nothing reached the VPC: passed                                       |
| Non-IP, spoofed source, destination outside the routes | Dropped; only the probe reached the VPC: passed                              | Dropped; only the probe reached the VPC: passed                                     |
| Hop limit 1                                            | Forwarded with the probe: passed                                             | Forwarded with the probe: passed                                                    |
| Sibling request on the same connection                 | 1280-byte round trip after every input: passed                               | 1280-byte round trip after every input: passed                                      |
| Cancel one request                                     | Its backend session closes; sibling forwards: passed                         | Its backend session closes; sibling forwards: passed                                |

The thresholds were set before the first run: at least 20 packets of exactly 1280 bytes each way, and none larger. The outer packet counts vary between runs, because the TCP echo's segmentation varies.

## Shared boundary

Both servers admit a request through `connectip.Admission`. They hold the returned `Lease` for the request's lifetime and end the request when `Lease.Done` closes. They exchange packets through one `connectip.PacketBackend` session opened per request. The transport handles only framing:

- HTTP/3 carries packets in QUIC datagrams.
- HTTP/2 carries them in DATAGRAM capsules on the request stream.

The production adapters behind these interfaces come from #975–#979:

- foundation-backed admission and the instance lease;
- attachment-bound packet backends with independent forwarding fences;
- route publication.

The harness's admission and recording TUN backend stand in for them, and prove nothing about foundation behavior.

## From prototype to production listener

The prototype left six items for the production listener. #981 closed them in `internal/edge/connectip`:

1. **One shared request path.** `Server.ServeHTTP` parses each transport's request, then runs one path for both: limits, `Admission`, grant checks, the backend session and `packetPolicy`.
2. **Packet checks equal to HTTP/3's.** Both transports apply `packetPolicy` in both directions, including to the Packet Too Big the HTTP/2 tunnel returns for a packet over 1500 bytes. IPv4 is refused on both, as #979 decided.
3. **An explicit Extended CONNECT opt-in.** `net/http` offers `SETTINGS_ENABLE_CONNECT_PROTOCOL` only when `GODEBUG` contains `http2xconnect=1` at process start (golang/go#71128). The masque-provider image sets it, and `ServeTLS` returns `ErrExtendedConnectDisabled` without it.
4. **Bounded resources on TCP.** `Config.Limits` covers TCP connections in total and per source, HTTP/2 streams, headers and the TLS handshake. Admission and session caps are shared with HTTP/3. One DATAGRAM capsule of at most 1508 bytes is held per request, and a write that cannot finish in 5 seconds ends its request; unit tests cover a client that stops reading.
5. **Protocol details.** Routes are sorted and checked for overlap as over HTTP/3. `Capsule-Protocol` accepts structured-field parameters.
6. **Reconnect behavior.** A connector that reconnects over HTTP/2 is admitted again through the same adapter, which [replaces](masque-provider.md#replacing-a-connectors-request) its HTTP/3 request without dual ownership.

[MASQUE connector service](masque-service.md#http2-fallback) documents the listener's behavior.

## Carried from #991

The table records the prototype's findings. Since then, `connectip.Server` has applied `Config.Limits` before admission on both transports and has sent the HTTP/3 MTU probe only after admission (#991, #981).

| Finding                                  | Status in this proof                                                                                                                                                                                                                                                                                                                                                                  |
| ---------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| No limit ahead of admission              | Open on both transports. The prototype adds none; #980/#981 own it.                                                                                                                                                                                                                                                                                                                   |
| MTU probe before admission               | HTTP/3 only. A TCP stream has no datagram size to probe, so the prototype sends nothing before admission.                                                                                                                                                                                                                                                                             |
| A full TUN ends unrelated sessions       | Unchanged. Both transports use the same `TUNBackend`, so #979 must fix it once for both.                                                                                                                                                                                                                                                                                              |
| Routes not checked against other tenants | Unchanged. Route authority belongs to the admission adapter (#977/#978).                                                                                                                                                                                                                                                                                                              |
| Backend not fenced by lease state        | Unchanged. #976 owns it, and cancelling the protocol worker is not a fence on either transport.                                                                                                                                                                                                                                                                                       |
| Packet checks in both directions         | Toward the VPC, both transports drop non-IP datagrams, spoofed sources and destinations outside the advertised routes, and forward a hop limit of 1 unchanged, as the malformed-input checks prove. The HTTP/2 prototype drops IPv4. Checks toward the client, beyond the TUN backend's /96 demultiplexing, and the HTTP/3 server's IPv4 behavior were not exercised; #979 owns them. |
