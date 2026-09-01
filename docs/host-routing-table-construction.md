# How the Host Routing Table Is Constructed

There is no single "install the routing table" step in Galactic — the
node's kernel routing state is assembled by three independent binaries, each
reacting to a different trigger, writing into a different table (or, for one
path, into something that deliberately is **not** a kernel table at all):

| Source                                     | Trigger                                    | Table                                                 | Mechanism                                                                                     |
| ------------------------------------------- | ------------------------------------------- | ------------------------------------------------------ | ----------------------------------------------------------------------------------------------- |
| `fabric-router` (FRR `zebra`)               | eBGP underlay session with the fabric switch | Kernel **main** table (`RT_TABLE_MAIN`)                | `zebra` installs learned eBGP routes via netlink; also brings up `lo`/interface addressing     |
| `galactic-cni` (`galactic-veth`/`-tap`, `hostgw`, `galactic-route`) | Pod/VM CNI `ADD`                | Per-VPC **VRF** table (one routing table ID per VPC)   | `vrf.Add` creates the table; `hostgw.ConfigureHostGateway` and, optionally, `galactic-route` install routes into it via netlink |
| `galactic-router` (`internal/runtime/gobgp`) | Remote EVPN Type 5 best-path change          | **Either** kernel main table **or** `egress_route_table` (pinned eBPF map, not a kernel table) | `processEVPNPath` picks the destination based on whether the path carries a Route Target        |

See [ARCHITECTURE-CNI.md](agents/ARCHITECTURE-CNI.md),
[ARCHITECTURE-ROUTER.md](agents/ARCHITECTURE-ROUTER.md), and
[docs/architecture/](architecture/) (including the
[galactic-cni](architecture/components/galactic-cni-components.png),
[galactic-router](architecture/components/galactic-router-components.png), and
[fabric-router](architecture/components/fabric-router-components.png)
component diagrams) for the surrounding architecture; this document is the
one place all three pieces come together into a single mechanism.

---

## Sequence

```mermaid
sequenceDiagram
    autonumber
    participant Switch as Physical Fabric Switch
    participant FRR as fabric-router (zebra + bgpd)
    participant Kernel as Kernel routing tables (main + per-VPC VRF)
    participant Runtime as CNI Runtime
    participant CNI as galactic-veth/-tap + hostgw + galactic-route
    participant K8s
    participant GoBGP as galactic-router (GoBGP + monitor.go)
    participant EgressMap as egress_route_table (pinned eBPF map)
    participant Peer as iBGP peer / Route Reflector

    rect rgb(235, 245, 255)
    Note over Switch,Kernel: Phase 1 — node boot: underlay reachability (main table)
    FRR->>Switch: establish eBGP session (port 179, per this node's frr.conf.<nodename>)
    Switch-->>FRR: exchange underlay routes
    FRR->>FRR: bgpd redistributes learned routes to zebra
    FRR->>Kernel: zebra installs underlay routes into RT_TABLE_MAIN; brings up lo/interface addressing
    end
    Note over GoBGP,Kernel: galactic-router's own outbound iBGP dial (port 1790) rides this<br/>reachability — it cannot connect to its peer/RR until this phase converges

    rect rgb(235, 255, 240)
    Note over Runtime,K8s: Phase 2 — pod/VM attach: per-VPC VRF table
    Runtime->>CNI: ADD (galactic-veth or galactic-tap)
    CNI->>Kernel: vrf.Add(vpc) — FlushTable(reused ID), create VRF interface + table ID (idempotent)
    CNI->>Kernel: create veth pair / tap device, enslave host side to the VRF
    CNI->>Kernel: hostgw.ConfigureHostGateway — AddrAdd(gateway) on this attachment's<br/>own host iface, RouteAdd(pod subnet) into the VRF table, NeighSet (veth only)
    opt attachment has terminations
        Runtime->>CNI: ADD (galactic-route, chained next)
        CNI->>Kernel: route.Add(vpc, network, via, dev) — into the same VRF table
    end
    Runtime->>CNI: ADD (galactic-bgp, chained last)
    CNI->>K8s: CreateOrUpdate BGPVRFInstance (RD/RT), BGPAdvertisement
    end
    Note over CNI,Kernel: See docs/cni/cni-cmd-sequence.md for the full CNI ADD/DEL chain —<br/>this phase only covers the routes it installs, not IPAM/NAD/eBPF registration

    rect rgb(255, 245, 235)
    Note over K8s,Kernel: Phase 3 — EVPN convergence: tenant path vs. RT-less anycast path
    K8s->>GoBGP: BGPVRFInstance reconciled
    GoBGP->>GoBGP: applyVRFs — register this VRF's Route Target in rtIndex;<br/>probeEgressRouteWrite verifies the pinned eBPF map is writable
    GoBGP->>GoBGP: applyEVPN — originate local EVPN Type 5 path<br/>(Prefix-SID attribute = this attachment's uSID)
    GoBGP->>Peer: advertise path (iBGP, rides Phase 1's underlay reachability)
    Peer-->>GoBGP: (on every node importing this VPC's RT) receive + reflect best path
    GoBGP->>GoBGP: watchEVPNRIB fires OnBestPath -> processEVPNPath
    GoBGP->>GoBGP: matchTableID(attrs) — has a Route Target community?
    alt path carries a Route Target (tenant VRF prefix)
        GoBGP->>GoBGP: look up this VRF's kernel table ID via rtIndex
        GoBGP->>EgressMap: RouteEgressAdd(prefix, uSID gateway, tableID)
        Note over EgressMap: NOT a kernel route — the TC-BPF uSID datapath's own<br/>bpf_fib_lookup() consults this map per-packet instead.<br/>Replaces a pre-cutover netlink.SEG6Encap route (CVE-2026-31668)
    else path carries no Route Target (e.g. NetworkGateway anycast VIP)
        GoBGP->>Kernel: resolveNextHop(gateway) via netlink.RouteGet<br/>(itself resolved through Phase 1's underlay route)
        GoBGP->>Kernel: RouteMainAdd(prefix, gw, RT_TABLE_MAIN) — netlink.RouteReplace,<br/>a genuine kernel route, ordinary recursive forwarding (no SEG6 encap)
    end
    end
    Note over GoBGP,Kernel: Withdrawal is symmetric: path.Withdrawal fires<br/>RouteEgressDel / RouteMainDel from the same watchEVPNRIB goroutine
```

---

## Notes

- **Three tables, not one.** `RT_TABLE_MAIN` carries underlay reachability
  (`fabric-router`) and RT-less anycast VIP routes (`galactic-router`'s
  `RouteMainAdd`); each VPC gets its own VRF table, populated by
  `galactic-cni` (pod-subnet + termination routes); the TC-BPF uSID
  datapath's `egress_route_table` is a **pinned eBPF map**, not a kernel
  routing table at all — the ingress/egress datapath (`internal/plumbing/ebpf/prog/usid.c`)
  reads it directly via `bpf_fib_lookup()`-style logic, bypassing the kernel
  FIB entirely for tenant SRv6 traffic.
- **Tenant VRF prefixes deliberately stopped being kernel routes.**
  `internal/runtime/gobgp/monitor.go`'s `processEVPNPath` used to install a
  `netlink.SEG6Encap` route for every remote EVPN Type 5 path; that mechanism
  is confirmed broken under this codebase's per-tenant-VRF architecture
  (CVE-2026-31668 — the kernel's seg6 lwtunnel `dst_cache` is reused across
  differing routing contexts). `RouteEgressAdd`/`RouteEgressDel`
  (`internal/plumbing/srv6/egress.go`) now write the pinned eBPF map instead;
  only the RT-less anycast path (`RouteMainAdd`/`RouteMainDel`) still touches
  the kernel FIB, because it needs ordinary recursive forwarding, not SEG6
  encapsulation.
- **A strict dependency order, not three independent processes.**
  `galactic-router`'s outbound iBGP dial (Phase 3) cannot reach its peer/route
  reflector until `fabric-router`'s eBGP underlay session has converged
  (Phase 1) — and `RouteMainAdd`'s own `resolveNextHop` call
  (`netlink.RouteGet`) depends on that same underlay route existing in the
  kernel to resolve a real next hop for an anycast VIP path. Phase 2 (a pod
  attach) can happen independently of Phase 1/3 timing-wise, but the
  `BGPAdvertisement`/`BGPVRFInstance` CRDs it writes only take effect once
  `galactic-router` reconciles them (Phase 3).
- **Route lifecycle doesn't end at install.** `galactic-cni`'s own `cmdDel`
  never removes the VRF, its routes, or the eBPF map entries it depends on —
  `galactic-router`'s GC controller (`internal/gc`) reclaims the kernel VRF
  (`vrf.FlushTable` + `netlink.LinkDel`) and stale `egress_route_table`
  entries asynchronously, once no live container still references them. See
  [ARCHITECTURE-CNI.md#known-constraints](agents/ARCHITECTURE-CNI.md#known-constraints)
  and [docs/cni/gc-cmd-sequence.md](cni/gc-cmd-sequence.md).
- **This is a superset view, not a replacement, of the existing sequence
  docs.** [docs/cni/cni-cmd-sequence.md](cni/cni-cmd-sequence.md) covers the
  full CNI ADD/DEL chain (IPAM, NAD annotation, eBPF map registration, etc.),
  and [docs/agent-startup.md](agent-startup.md) covers `galactic-router`'s
  full startup sequence — this document isolates only the routing-table
  side of both, plus `fabric-router`'s half, which neither of those covers.
