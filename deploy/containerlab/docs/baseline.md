# Dedicated-placement baseline

This page describes a fixture and a set of scripted packet observations of
today's remote paths. The fixture is two VPCs with identical guest addresses
on two physical workers. Services run on dedicated edge nodes, and workloads
run on compute nodes. Later work on the Galactic Worker reuses this fixture
and compares its results against the reference recorded here.

The fixture has no TAP-backed guest. The tenant TAP capture point belongs to
[#1444](https://github.com/datum-cloud/galactic/issues/1444).

## Fixture

`ns80` (`resources/tenants/ns80/`) holds two VPCs with the same guest address
at each site:

| VPC  | Attachment | dfw-worker guest      | sjc-worker guest      | Kind                   |
| ---- | ---------- | --------------------- | --------------------- | ---------------------- |
| `80` | `vpc-a`    | `fd20:80:ff01::1:0:0` | `fd20:80:ff02::1:0:0` | veth (`galactic-veth`) |
| `81` | `vpc-b`    | `fd20:80:ff01::1:0:0` | `fd20:80:ff02::1:0:0` | veth (`galactic-veth`) |

- **Two physical workers.** `dfw-worker` and `sjc-worker` are each their site's
  only compute node. They have distinct SRv6 locators and reach each other over
  the routed underlay through their sites' edge nodes and the transit routers.
  Gateway and NAT run only on the edge nodes (`dfw-worker2`, `dfw-worker3`,
  `sjc-worker2`), so this is dedicated placement.
- **Identical addressing.** The guests take fixed addresses through IPAM's
  `addresses` path, so the overlap does not depend on allocation order. Each
  guest's gateway lies outside its `/96` and is reached on-link, as on every
  `addresses` attachment.
- **Public client and egress peer.** `remote-host` behind `tr4` serves HTTP
  on `[2001:db8:1:40::2]:80` and `11.1.40.2:80`. It is the client for gateway
  ingress and the peer for NAT egress.
- **Policy.** Every `ns80` attachment is bound to the `private-nat` set
  (`resources/tenants/policies/README.md`).

`task deploy` deploys `ns80` as part of `deploy:scenarios`. `task deploy:ns80`
redeploys it alone, and `task verify:ns80` (part of `task verify`) checks
placement, the overlapping addresses and cross-site reachability.

## Running the observations

```bash
cd deploy/containerlab
task deploy             # from a destroyed lab: build images, deploy everything
task baseline:twice     # pins, two observation runs, compare with the reference
task verify             # the lab's full verification still passes
```

`task baseline:twice` writes to `bin/baseline/<UTC timestamp>/` at the
repository root, or to the directory given after `--`. It fails if a pinned
version disagrees, if any check fails in either run, if the two runs'
`results.json` files differ, or if run 1 differs from
`baseline/reference-results.json`. `task baseline:observe -- DIR` runs one
observation and `task baseline:versions -- FILE` records versions alone.

Each run directory holds:

| File               | Contents                                                                               |
| ------------------ | -------------------------------------------------------------------------------------- |
| `results.json`     | One row per check: scenario, check, expected, observed, result. Stable values only.    |
| `volatile.tsv`     | Per-run values: source ports, the isolation nonce, translated tuples, shard addresses. |
| `pcap/<scenario>/` | One pcap per capture point and interface, with tcpdump's log beside it.                |
| `logs/`            | Probe output and the gateway checks' full logs.                                        |

`results.json` never holds a port, nonce, timestamp or MAC address. Those
values change on every run, and only stable values let two runs compare equal.

## Scenarios

Each scenario runs in its own capture window, in both directions.

| Scenario       | Traffic                                                                                   | Expected                                                                                            |
| -------------- | ----------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| `cross-node-a` | 5 ICMPv6 echoes dfw → sjc, then 5 sjc → dfw, in VPC 80                                    | 5 replies each way, every request seen at every expected point                                      |
| `cross-node-b` | The same in VPC 81                                                                        | The same                                                                                            |
| `nat66`        | Both dfw guests fetch `http://[2001:db8:1:40::2]/` at once from one identical source port | Both get 200, the peer sees 2 distinct translated tuples from shard addresses only                  |
| `nat64`        | The same to `http://[2001:db8:64::b01:2802]/`, under the shards' NAT64 prefix             | The same over IPv4                                                                                  |
| `gateway-ipv6` | `verify-gateway-ingress.sh --node dfw-worker2`: TCP and UDP to `2001:db8:6060:1::1`       | Answered flows in both protocols; requests and DSR replies seen at the public side and the backends |
| `gateway-ipv4` | `verify-gateway-ingress-ipv4.sh --node dfw-worker2`: TCP and UDP to `198.51.100.1`        | The same; backends see the client as `64:ff9b::b01:2802`                                            |
| `isolation`    | 5 UDP datagrams from each VPC's sjc guest to `[fd20:80:ff01::1:0:0]`                      | Each VPC's dfw guest and host veth see its own 5 and none of the other VPC's                        |

The gateway scenarios reuse the lab's ingress checks against `ns60`'s
backends on `dfw-worker`, and pin the VIP to `dfw-worker2` on `tr1` for the
duration of the check.

The IPv4 check captures on `remote-host` itself and stops every tcpdump
there, so `gateway-ipv4` has no `remote-host` capture point. The check's own
client-side assertions stand in for it.

### Intermittent TCP loss in the gateway checks

Both lab ingress checks lose a TCP flow now and then, with or without these
captures: in three back-to-back runs of `verify-gateway-ingress-ipv4.sh --node
dfw-worker2` with no capture running, one answered 6 of 8 TCP flows. The
captures show that the lost flow is delivered. The request reaches the
backend over the gateway, and the backend acknowledges it. Then the `ns60`
responder (`socat ... fork SYSTEM:`) closes without writing a reply, 1 to
2 ms after the client's FIN, and that close returns to the client over the
DSR path. UDP flows are never lost.

So each gateway scenario's exact flow counts and the check's exit status go
to `volatile.tsv`, and `results.json` records only whether each protocol had
answered flows.

## Capture points

| Point           | Where                                                                                                                   |
| --------------- | ----------------------------------------------------------------------------------------------------------------------- |
| Public RX/TX    | `tr1`'s members facing both dfw edge nodes (`eth1`, `eth6`, `eth5`, `eth7`), and `remote-host` `eth1`                   |
| Veth peers      | Each guest's `eth0` (an `ns80` guest, or an `ns60` backend for gateway ingress) and its host veth `G<vpc><attachment>H` |
| Remote underlay | `tr2`'s members facing `sjc-worker2` (`eth1`, `eth5`), `tr1`'s dfw edge members, and both compute workers' bond members |

A point that names several interfaces sums them. The bond member a flow
uses, and the dfw edge node it crosses, are chosen by hashes that can differ
between runs. The link the flow crosses does not change.

Some points cannot see one direction, because of how today's datapath
delivers packets. Those checks are recorded as observations without an
expectation, and are still compared between runs:

- **Edge nodes.** The edge nodes forward NAT and gateway traffic in XDP,
  which tcpdump on those nodes never sees (#565). Public-side captures are
  therefore taken on the transit router's end of each edge uplink.
- **Host veths, inbound.** A host veth carries its guest's outbound packets.
  Inbound packets reach the guest through `bpf_redirect_peer` in
  `usid_ingress` (`internal/plumbing/ebpf/prog/usid.c`), straight into the
  guest's side of the pair, so tcpdump on the host side never sees them. The
  guest's own `eth0` is the evidence for inbound delivery, including for
  the isolation control.
- **Compute bond members.** These captures are recorded without an
  expectation.

## Pinned versions

`baseline/pins.yaml` pins the host tools (containerlab, kind, task), the
Kind node version, FRR, the `remote-host` base image and the guest image
digest. `scripts/baseline-versions.sh` checks each pin against its source:
the host tool, the lab's Dockerfiles, the `ns80` manifests and the running
lab. It then records the host and node kernels, Docker, the Galactic
revision and every lab image ID in `versions.yaml`. Change a pin only
together with the reference results.

## Updating the reference

After a deliberate change to the fixture or to an expectation, rerun with
`BASELINE_WRITE_REFERENCE=1 task baseline:twice`. The reference is replaced
only when both runs pass and agree. Commit the new
`baseline/reference-results.json` with the change that caused it.
