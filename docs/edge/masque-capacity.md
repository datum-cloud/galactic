# MASQUE capacity

The [MASQUE contract](../designs/masque/contract.md#resource-budgets-and-benchmark-contract) sets initial capacity targets for the CONNECT-IP service and asks for measured results per transport. This page describes the load harness, records the first run, and lists what still needs the target environment. Issue [#984](https://github.com/datum-cloud/galactic/issues/984) tracks the qualification.

## The harness

`task test:connectip-load` runs `TestLoad` in `internal/edge/connectip`. The test is skipped unless `CONNECTIP_LOAD` is set, so `task test:unit` and CI never run it. One full run takes about 15 minutes and loads every CPU.

The harness runs the production `connectip.Server` with its default limits on loopback, with HTTP/3 on UDP and HTTP/2 on TLS. Clients run in the same process:

- Each connector dials from its own loopback source address, so the 8-per-source cap applies as it would to separate hosts.
- Connectors alternate between two tenants whose gVPCs hand out the same /96 values. Every packet carries its connector's number, and a packet delivered to the wrong connector fails the run.
- A reflecting backend stands in for the gVPC. It returns each client packet to the session that sent it, through a queue with the TUN backend's limits of 128 packets and 256 KiB.
- Each connector keeps at most 32 packets unanswered and writes off a window that stays unanswered for 200 ms.

Goodput counts inner IP bytes in both directions. CPU time and memory are the whole test process, clients included.

Environment variables adjust a run:

| Variable                    | Default         | Meaning                                                         |
| --------------------------- | --------------- | --------------------------------------------------------------- |
| `CONNECTIP_LOAD_DURATION`   | `10s`           | Measured time of each run                                       |
| `CONNECTIP_LOAD_WARMUP`     | `2s`            | Traffic before measuring starts                                 |
| `CONNECTIP_LOAD_RUNS`       | `3`             | Runs of each scenario (the test alone defaults to 1)            |
| `CONNECTIP_LOAD_CONNECTORS` | `1,8,32`        | Connector counts for the throughput scenario                    |
| `CONNECTIP_LOAD_REPORT`     | set by the task | Markdown report path; a JSON file with every run goes beside it |

The task writes `bin/connectip-load/report.md` and `report.json`.

## Scenarios

- **Throughput:** 1, 8 and 32 connectors per transport, with 1280-byte and 64-byte packets.
- **Overload:** 32 connectors carry traffic while 256 clients, twice the connection cap, keep opening requests. Each flood request waits 2 s in admission, as with a slow authority, and holds its session for 1 s once admitted. One flooder in eight shares a single source address. Halfway through, four connectors' leases are revoked. The run fails if a connector receives nothing, or if a revoked session lasts over 10 s.
- **Slow reader:** one client stops reading while 8 connectors carry traffic, and the gVPC side keeps sending to it. The run fails if its session lasts over 10 s, or if another connector stops receiving.
- **Churn:** 10 new requests a second, each from a new source address, beside 8 connectors.
- **Impaired (HTTP/3 only):** 8 connectors whose sockets drop 1% of datagrams each way and delay what they send by 50 ms.

After every scenario the harness closes all clients. It then waits up to 40 s for zero sessions, zero backend sessions, zero QUIC connections, and goroutines back within 8 of the count before the run. The 40 s covers the 30 s QUIC idle timeout, which is how the server learns that a client vanished without closing.

## Results: loopback, 2026-10-28

Host: Intel Core i7-10710U, 12 CPUs, Linux 7.1, Go 1.26.5. Server code at `f7008a48` ([#1210](https://github.com/datum-cloud/galactic/pull/1210)); later #1210 commits change only tests and comments. Warm-up 2 s, measured 10 s, 3 runs of each scenario, every run passed. The tables give the median of the three runs, except peak RSS, which is the largest.

These numbers come from one host with clients and server sharing its CPUs. They show how the server behaves under load and that it holds its limits. They do not show capacity on an edge node.

### Throughput

No throughput run lost a packet or dropped one from a session queue. Every run recovered.

| Transport | Connectors | Packet | Goodput Mbit/s | Packets/s each way | RTT p50 ms | RTT p99 ms | CPU cores | Peak RSS MiB |
| --------- | ---------- | ------ | -------------- | ------------------ | ---------- | ---------- | --------- | ------------ |
| HTTP/3    | 1          | 1280 B | 1951           | 95,292             | 0.30       | 0.61       | 4.7       | 37           |
| HTTP/3    | 8          | 1280 B | 2290           | 111,848            | 2.18       | 5.89       | 7.7       | 48           |
| HTTP/3    | 32         | 1280 B | 2403           | 117,380            | 7.94       | 23.55      | 7.7       | 82           |
| HTTP/3    | 1          | 64 B   | 132            | 129,628            | 0.22       | 0.54       | 4.7       | 34           |
| HTTP/3    | 8          | 64 B   | 142            | 138,985            | 1.60       | 4.86       | 6.4       | 46           |
| HTTP/3    | 32         | 64 B   | 147            | 144,121            | 6.40       | 19.46      | 6.6       | 76           |
| HTTP/2    | 1          | 1280 B | 911            | 44,506             | 0.67       | 1.22       | 3.0       | 38           |
| HTTP/2    | 8          | 1280 B | 2881           | 140,682            | 1.60       | 3.71       | 9.8       | 45           |
| HTTP/2    | 32         | 1280 B | 2971           | 145,076            | 6.40       | 19.46      | 9.8       | 65           |
| HTTP/2    | 1          | 64 B   | 51             | 50,186             | 0.61       | 0.80       | 2.9       | 37           |
| HTTP/2    | 8          | 64 B   | 183            | 178,960            | 1.34       | 2.69       | 9.8       | 43           |
| HTTP/2    | 32         | 64 B   | 182            | 178,498            | 5.38       | 13.82      | 9.8       | 59           |

### Disturbances

| Scenario    | Transport | What the harness checked                                                                 | Result in all 3 runs                                                                                 |
| ----------- | --------- | ---------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| Overload    | HTTP/3    | 32 connectors kept receiving; 4 revoked leases ended their sessions; resources recovered | No connector starved; revoked sessions ended in 1.0 to 1.1 ms; about 18,000 requests refused per run |
| Overload    | HTTP/2    | Same                                                                                     | No connector starved; revoked sessions ended in 2.0 to 3.9 ms; about 20,000 requests refused per run |
| Slow reader | HTTP/3    | The stalled client's session ends within 10 s; 8 other connectors keep receiving         | Ended after 6.8 to 8.0 s; no connector starved                                                       |
| Slow reader | HTTP/2    | Same                                                                                     | Ended after 5.5 s; no connector starved                                                              |
| Churn       | HTTP/3    | 10 new requests a second beside 8 connectors; resources recovered                        | 95 or 96 of 96 accepted; one 503 in two runs                                                         |
| Churn       | HTTP/2    | Same                                                                                     | 96 of 96 accepted in one run; one handshake timeout in each of the other two                         |
| Impaired    | HTTP/3    | 8 connectors with 1% loss each way and 50 ms added delay                                 | 16 Mbit/s, RTT p50 102 ms, p99 311 ms, 1.9 to 2.0% loss                                              |

The overload runs admitted 64 flood requests each, which held free session slots for 1 s at a time. The rest were refused before admission: with 503 for too many sessions or admissions, or by closing the QUIC connection for too many connections from one source. Over HTTP/2, some TCP connections were reset when accepted because the connection cap was full.

### Against the contract targets

| Contract target                                         | Loopback result                                                     | Status                                                              |
| ------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- |
| HTTP/3 goodput at least 250 Mbit/s per pod              | 2403 Mbit/s at 32 connectors                                        | Exceeded on loopback; unproven on edge nodes                        |
| HTTP/2 goodput at least 100 Mbit/s per pod              | 2971 Mbit/s at 32 connectors                                        | Exceeded on loopback; unproven on edge nodes                        |
| Provider RSS at most 1 GiB                              | 136 MiB peak, client included                                       | Within target                                                       |
| Average CPU at most 3.2 cores                           | 7.7 to 9.8 cores at saturation, client included                     | Not comparable: the harness offers as much load as the host absorbs |
| 5 s blocked-delivery timeout                            | 5.5 s on HTTP/2, 6.8 to 8.0 s on HTTP/3                             | Missed on both; see Findings                                        |
| Overload rejects bounded work                           | Refused with 503 or a closed connection; queues held at 128 packets | Met                                                                 |
| Expiry under load                                       | Revoked sessions ended within 4 ms under a flood                    | Met                                                                 |
| Recovery after clients leave                            | Every run recovered                                                 | Met                                                                 |
| Less than 1% UDP loss, p99 at most 10 ms above baseline | Not measured: no untunneled baseline on loopback                    | Open                                                                |

## Findings

- The first blocked-delivery watchdog let a stalled HTTP/3 client hold its session for 13.3 s. A QUIC connection to a client that stopped reading still sends two datagrams per probe timeout, so no single write blocked for 5 s. [#1210](https://github.com/datum-cloud/galactic/pull/1210) now ends a session after slow writes keep recurring for 5 s. The probe timeouts start below the 1.25 s that counts as slow, so the HTTP/3 session ends after 6.8 to 8.0 s rather than 5.
- Neither transport meets the 5 s target exactly. The watchdog checks every 1.25 s, so a session blocked for 5 s ends within 6.25 s; HTTP/2 measured 5.5 s. The harness fails a run only past 10 s, so it shows the timeout is bounded, not that 5 s is met. Meeting 5 s exactly would mean checking more often, or treating the target as 5 s plus one check interval; that choice belongs to the target review #984 asks for.
- The harness reaches the contract's 32 connectors per pod with headroom on both transports. Latency grows with the connector count because each connector keeps 32 packets in flight: the p99 is 23.6 ms at 32 connectors over HTTP/3.

## Still open

Closing #984 needs the run the contract specifies. That means two physical edge nodes and a separate load host at 10 Gbit/s, with real gVPC workloads behind the TUN device, a 2-minute warm-up, a 10-minute measurement, and an untunneled baseline for the added-RTT and loss targets. This harness does not cover:

- the TUN device, attachments, EdgeRoutes and map occupancy;
- grant authority and lease-renewal API budgets;
- HTTP/2 under loss or added delay, which needs network emulation;
- CPU per pod with the client on another host.

Any change to a target needs review before #984 closes.
