# Qualification plan

Status: proposed. The NIC and the numeric limits (D16, D18) were confirmed on
2026-11-18. [#1444](https://github.com/datum-cloud/galactic/issues/1444)
proves the handoffs on this platform, and
[#1442](https://github.com/datum-cloud/galactic/issues/1442) runs the
comparison and reports against the limits.

## Platform

| Item             | Value                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| ---------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Kernel           | 6.8 or later, the minimum the interface traffic policy preflight already enforces. Each run records the exact kernel release.                                                                                                                                                                                                                                                                                                                                                                      |
| Lab              | The two-worker Containerlab topology from [#1432](https://github.com/datum-cloud/galactic/issues/1432) (`deploy/containerlab`), reserved through the shared lab procedure. Kind nodes share the lab host's kernel.                                                                                                                                                                                                                                                                                 |
| NIC (D16)        | Broadcom NetXtreme-C/E (`bnxt_en` driver), which runs generic XDP under the [selection rule](../operations/xdp-attach-mode.md). A `bnxt_en` NIC anywhere on a host selects generic mode for every interface on it, so native XDP is qualified on a different host without one: the lab's veth devices, and a NIC whose driver supports native XDP when such a host is available. Each run records the NIC model and driver; a hardware combination not run is listed as outstanding in the report. |
| XDP attach modes | Native and generic, as `internal/plumbing/ebpf/xdpmode` selects them. Both modes are qualified.                                                                                                                                                                                                                                                                                                                                                                                                    |
| Device types     | A plain interface, a bond member and a VLAN device, in each mode.                                                                                                                                                                                                                                                                                                                                                                                                                                  |

A combination of mode and device type that fails is recorded here as
unsupported, and Worker reports it as `HookUnsupported` in its capabilities.

## Handoffs #1444 proves

| Handoff                                                                                                 | Capability                          | Consumer                                                                    |
| ------------------------------------------------------------------------------------------------------- | ----------------------------------- | --------------------------------------------------------------------------- |
| Public receive `XDP_PASS` into the tenant-side TC program                                               | `local.tap`                         | Gateway, [#1438](https://github.com/datum-cloud/galactic/issues/1438)       |
| TC on one end of the NAT internal veth pair, XDP on its peer, and the reverse TC receive                | `local.veth_pair`                   | NAT, [#1437](https://github.com/datum-cloud/galactic/issues/1437)           |
| Envoy pod delivery to a VRF-bound upstream socket (`SO_BINDTODEVICE`) through a pod-to-host routed link | `local.routed_link`, `local.socket` | Envoy sidecar, [#1439](https://github.com/datum-cloud/galactic/issues/1439) |

Each proof covers both directions, a packet that policy denies, and the
absence of local encapsulation on the physical wire.

## Workload

- NAT66 and NAT64, NLB and ALB (Envoy) run at the same time, against two VPCs
  that use the same guest addresses.
- Destinations include pods and TAP-backed Unikraft guests, on the local and
  the remote worker.
- Throughput uses 1280-byte inner IPv6 packets. A separate run uses 64-byte
  packets for packet rate. Traffic is split 50/50 by bytes between TCP and UDP,
  evenly in both directions.
- `iperf3` measures throughput and loss; `netperf` `TCP_RR` measures
  request-response latency.

## Comparison method

This method follows the one the MASQUE contract uses (D17).

1. Deploy the main base (`11323a9`) and the branch head on the same host and
   topology, with artifacts pinned by `v0.0.0-<short-sha>`.
2. For each workload, warm up for 2 minutes, then measure for 10 minutes.
   Run each workload three times.
3. Compare the median of the three branch runs with the median of the three
   base runs. Report all runs, not only the medians.
4. Record the kernel, CPU model, NIC and driver, XDP mode, MTUs, and image
   digests with each result.

## Limits

The limits were confirmed on 2026-11-18 (D18). Throughput and latency are judged
against the base on the same host, because absolute numbers depend on the
hardware.

| Measure                                                       | Limit                      |
| ------------------------------------------------------------- | -------------------------- |
| Throughput, per service path and packet size                  | At least 95% of the base   |
| Added p99 latency                                             | At most 10% above the base |
| Packets delivered to an unauthorized VPC                      | 0                          |
| Worker reconcile time, claim change to `Programmed=True`      | p99 under 1 s              |
| Re-convergence after a Worker restart, to every claim `Ready` | Under 5 s                  |
| Worker resident memory                                        | Under 256 MiB              |
| Claims one caller holds (`ClaimLimit`, `--claim-limit`)       | 1024                       |

CPU per packet, drops and guest contention are measured and reported against
the base without a limit, as the MASQUE benchmark does, because they depend on
the host hardware.
