# CNI attach chain architecture

This page describes the component boundaries and invariants. Use [configuration](configuration.md) for settings and [the documentation index](../README.md) for deployment and development guides.

## Overview

When a pod or VM is attached to a VPC, a chain of CNI plugins creates the
required kernel state (VRF, veth pair or tap device, host-side routes) and
writes a `BGPAdvertisement` CRD. `galactic-router` (see
[ARCHITECTURE-ROUTER.md](../router/architecture.md)) watches that CRD and
injects the EVPN path into the node-local GoBGP server. `galactic-bgp` also
publishes a per-pod `discoveryv1.EndpointSlice` (when the attachment has an
IPv6 address to carry) — the mechanism the HTTP-ingress extension server
discovers VPC backends through; see
the EndpointSlice publication path in `internal/cnibgp`
and [docs/cni/conflist-reference.md](../cni/conflist-reference.md)'s
"EndpointSlice publish" section.

The CNI attach side is a **chain of small binaries**, not one monolithic
plugin: a master plugin (`galactic-veth` for containers, `galactic-tap` for
VM workloads) creates the VRF and host-side interface; an optional
`galactic-route` installs static termination routes; `galactic-bgp` publishes
the BGP/SRv6/eBPF state. IPAM is delegated to a separate `galactic-ipam`
binary via the standard CNI IPAM delegation protocol, not chained. None of
these five binaries are ever installed by hand: `galactic-cni`, a sixth
binary that is never itself a CNI plugin (no NAD ever names it in a `"type"`
field), stages the other five (plus `host-device`) onto the
host from its own `init`/`run` DaemonSet containers. All six ship in the
same `ghcr.io/datum-cloud/galactic-cni` image.

VPC and VPCAttachment CRDs are defined in `api/cloud/v1alpha1` and
reconciled through the NSO cell manager. `galactic-controller --role=cell`
projects BGP programming status; see [controller ownership](../controller/README.md#responsibilities). The CNI receives their
pre-populated identifiers and acts on them.

### SRv6 SID encoding


Each attachment endpoint is assigned a /128 USID (Unique Local SID, RFC 8986
Section 3.2). There is no companion-operator-injected `srv6_sid` NAD/config
field: `galactic-bgp` (`internal/cnibgp/bgp.go`'s `registerEBPFDatapath`,
which calls `internal/plumbing/ebpf/attachreg`'s `RegisterDatapath`)
derives the uSID `Block` from the node's `BGPRouter.spec.srv6Locator` via
`uformat.Block`, and registers `locator_table`/`function_table`/`vrf_table`
entries keyed on that `Block` plus this attachment's `Argument` (its
`BGPVRFInstance`'s VRFID) in the eBPF uSID datapath's pinned maps
(`internal/plumbing/ebpf/usidmap`) — no kernel seg6local route is installed
per attachment anymore; the TC-BPF program (`internal/plumbing/ebpf/prog/usid.c`)
is the only ingress/decap path (see Known Constraints below for the cutover
history). If the router lacks either `srv6Locator` or `nodeID`, eBPF
registration is skipped entirely for that attachment (`registerEBPFDatapath`
returns `registered=false`, not an error).

CNI ADD initially writes an attachment's rows and this node's own
`locator_table`, `function_table` and `node_src_addr_table` rows, and the
first writer of its `public_uplink_table` row, so a map recreated empty by a
layout change or a lost pin would otherwise stay empty until every workload
re-attaches.
`galactic-cni run` rebuilds every missing row
(`internal/gc/datapath_repair.go`'s `RepairAttachmentDatapath`, through the
same `attachreg` helpers ADD uses), always off the daemon's main loop: once
right after the datapath loads, retried while a pass fails or finds
attachments whose `BGPRouter` or `BGPVRFInstance` has not appeared yet (the
latter for up to ten minutes), and again on every eBPF GC tick. It finds
attachments by their host interface name and VRF master, takes the routing
table and egress kind from the kernel, the guest prefixes from the pod-subnet
routes out that interface and from the attachment's `BGPAdvertisement`, the
gateways from its own addresses, and the Block and Argument from the
`BGPRouter` and `BGPVRFInstance`. The advertisement is needed because the
master plugin routes a family's guest prefix only when that family has a
gateway, while ADD registers it either way (#806). It only writes a
row that is missing, and never one under the ingress sidecar's Block. The
sidecar return path's tables are excluded by their reserved table ID range,
since the sidecar's own `vrf_table` rows that also mark them may be among the
rows lost. A VPC's shared `vrf_table` and `vpc_attribution_table` rows are
rebuilt from its lowest-ifindex attachment, while ADD leaves whichever
attachment registered last, so those two may differ from before the loss;
delivery reads the per-interface `ifindex_egress_kind_table` row, which is
exact. Once no egress shard resolves, a pass skips the remaining VRFs' shard
routes rather than wait out each one's neighbor solicitation.

The ingress sidecar (`galactic-vrf`) writes rows into the same maps from its
pod's network namespace, each in a key range no host writer reaches: `vrf_table`
under `uformat.BlockIngressSidecar`, `ifindex_vrf_table` at or above
`ifindexvrfmap.SidecarIfindexBase`, and `egress_route_table` for tables at or
above `vrf.SidecarTableIDBase`. It leaves them in place when it exits, so a
restarted container keeps serving, and the host's GC and repair passes never
touch them. Two things remove a deleted pod's rows
(`internal/plumbing/ebpf/sidecarmap`, #773). A new sidecar removes, at startup,
every sidecar row its own VRFs do not account for. The installer's sidecar
return sweep (`internal/installer/sidecarreap.go`) treats a sidecar gateway
advertisement whose recorded host-side interface no longer exists, or is no
longer a veth, as the advertisement of a deleted pod, and deletes it. When every
sidecar advertisement on the node is in that state on two sweeps in a row, it
first removes every sidecar row from the maps. The second sweep covers a
replacement pod that has written its rows but not yet republished its
advertisements. A node whose sidecar publishes no advertisements gives the
installer no evidence, so it keeps that node's rows. Either path can still take
a live sidecar's rows for a deleted pod's: the startup prune when two sidecar
pods overlap on a node, and the installer when a replacement pod fails to
publish for two sweeps. So every sidecar reads its own `vrf_table` and
`ifindex_vrf_table` rows back on each sweep and reapplies its VRFs and routes
when any are missing, the same reapply a datapath reload triggers.
A sidecar also retries a failed gateway publication on each sweep, at most
four VPCs a sweep, so a publish that failed once does not wait for the VPC's
next EndpointSlice change.
While any VRF is installed, each sweep also reads `node_src_addr_table` and
restores this node's source address when it is unset or wrong, since only a
new VRF otherwise writes it.
A restarted sidecar container finds the routes its pod already installed by
their redirect routes in the pod's own main table, which no other pod can
write, and reads each one's SID from `egress_route_table`. An entry in that
map with no redirect route in the pod may belong to an overlapping sibling
pod, so the sidecar logs it and leaves it in place.

`galactic-router`'s own reconciler independently derives the *same* SID value
from the same inputs (`srv6.ComputeSID`, `internal/plumbing/srv6/usid.go`,
called from `internal/reconcile/reconcile.go`) for the BGP control-plane
side — see [ARCHITECTURE-ROUTER.md](../router/architecture.md) for that half.
The CNI side and the router side compute the same bit layout via separate
code paths (`uformat` is the single source of truth both build on), by
design — see `internal/plumbing/ebpf/doc.go`.

All nodes in the same VPC derive the same BGP Route Target by truncating the
48-bit hex VPC identifier to its low 32 bits (`uint32(v)`), formatted as
`ASN:NN`, enabling automatic cross-node path import without explicit RT
configuration. The RT is also used as the `BGPVRFInstance`'s Route
Distinguisher and import/export Route Target.

---

## Data flow

The [ADD and DEL sequences](cni-cmd-sequence.md) describe attachment; the [GC sequences](gc-cmd-sequence.md) describe the independent router and installer cleanup loops. The installer owns BPF program loading and the chain registers per-attachment state.


## Key Design Decisions

- **USID per endpoint, computed independently on both the CNI and BGP-control-plane sides.** Each (VPC, VPCAttachment) pair is assigned a unique /128 USID from the owning `BGPRouter`'s `srv6Locator` + `nodeID` plus this attachment's VRFID — there is no config-supplied SID field. `galactic-bgp` registers the eBPF uSID datapath's map entries for it (`internal/cnibgp/bgp.go`'s `registerEBPFDatapath`); `galactic-router` independently derives the same value for the BGP Prefix-SID path attribute (see [ARCHITECTURE-ROUTER.md](../router/architecture.md)). See [SRv6 SID encoding](#srv6-sid-encoding) above. VPC identity is not encoded in the SID itself — VPC scoping comes from the BGPVRFInstance's route target instead.
- **Base62 interface names.** Kernel interface names use the format `G{9-char-vpc-base62}{3-char-att-base62}{suffix}` (suffix: `V` = VRF, `H` = host veth/tap, `G` = guest veth pre-move), fitting in the 15-character kernel limit. The hex form is used for BGP route targets; base62 for kernel interfaces.
- **VRF/route-target model via BGPVRFInstance.** `galactic-bgp` creates a `BGPVRFInstance` (RouteDistinguisher + import/export Route Targets, all set to the derived RT) before the `BGPAdvertisement`; `galactic-router`'s GoBGP runtime applies VRFs before originating EVPN paths.
- **Every VRF table ends in an unreachable default, per family.** `vrf.Add` installs `unreachable default` for IPv4 and IPv6 at metric `4278198272` (`vrf.UnreachableDefaultMetric`, the value the kernel's VRF documentation recommends), on every call, not only when it creates the VRF. Without it, a lookup that misses in the VRF's table falls through the rules after the l3mdev rule to the main table, and the host routes a tenant packet the eBPF datapath didn't claim out its own default interface with the tenant's source address. The high metric means any real default in the table, such as the ingress sidecar's, still wins. Route sweepers must leave it alone: `hostgw` only removes unicast routes on the attachment's own device, and the installer's sidecar-return prune only touches tables from `0xF000` up. Each has a test pinning that.
- **TCP MSS is clamped in the datapath, not by the tenant or the fabric MTU.** A tenant packet crosses the fabric inside a 40-byte outer IPv6 header with no SRH, so a tenant interface at the uplink's own MTU advertises an MSS the path cannot carry, and nothing on the path fragments or reports an oversized segment. `clamp_tcp_mss` in `usid.c` lowers the MSS of every SYN and SYN-ACK at three points: `usid_egress` just before it encapsulates, `usid_egress`'s DSR reply redirect (the client's segments reach the backend encapsulated by the gateway), and `usid_ingress` just after it decapsulates (the only place a SYN-ACK returning through an egress shard can be clamped, since the shard does not). The limits are per tenant family, 1400 for IPv6 and 1420 for IPv4 at a 1500-byte fabric, and the IPv6 value also covers NAT64. `galactic-cni run` sizes them from the smallest uplink MTU (`internal/plumbing/ebpf/mssclamp`) into `mss_clamp_table`, overridable with `GALACTIC_CNI_TCP_MSS_CLAMP` (see [docs/cni/environment-variables.md](../cni/environment-variables.md#galactic_cni_tcp_mss_clamp)). The map and its counters (`mss_clamp_stats`, sized with spare slots) are new maps rather than new fields or `drop_reasons` slots, because changing an existing pinned map's layout makes `attach.Load` recreate that map empty, and the rows only CNI ADD writes do not come back until each attachment is re-added. `clamp_tcp_mss` is a global BPF function, verified once on its own, and walks at most 16 options: past about 20 steps the verifier's cost jumps from thousands of instructions to over its 1M limit. `usid_verifier_cost_test.go` fails if either program's verifier cost passes 16,000 instructions.

- **Tenant egress supports ordered and hashed shard selection.** Ordered mode uses the first resolvable configured shard. Hashed mode publishes immutable Maglev snapshots per translation class and pins tenant addresses to compatible shards. The installer owns membership; CNI ADD and repair register class-specific group routes. Empty classes stay fail-closed and class IDs are not reused until old routes are retired. See [active/active egress](../nat/active-active.md) for the publication protocol, class compatibility, concurrency fences and rollback, and [staging acceptance](../nat/active-active-rollout.md) before enabling it.

- **A packet too big for the fabric gets an ICMP error from the datapath, not a silent drop at the uplink.** `usid_egress` calls `send_too_big` after the MSS clamp and before it encapsulates. A packet longer than `encap_mtu_table`'s limit (the uplink MTU less 40, so 1460 at a 1500-byte fabric) is rewritten in place into an ICMPv6 Packet Too Big, or an ICMPv4 Fragmentation Needed for an IPv4 tenant with DF set, and redirected back out the interface it arrived on. The error carries the limit, comes from the attachment's own IPAM gateway (`tenant_gw_table`, keyed by host-side ifindex and written by `galactic-bgp` at ADD, removed by `galactic-veth`/`galactic-tap` at DEL), and quotes the packet's first 68 bytes with NPTv6 undone, so the tenant's path MTU discovery matches it to the socket that sent it. A GSO packet is judged by its segment length. No error is sent for an IPv4 packet without DF, for an ICMP error, past a per-CPU token bucket of 1,000 a second with a burst of 100 (`pmtu_icmp_bucket`), or for an attachment with no gateway in that family; those are dropped and counted as `fib_frag_needed`. Each outcome is counted in `pmtu_stats`, exported as `galactic_usid_pmtu_packets_total{result}`, and the limit as `galactic_usid_pmtu_limit_bytes`. The same `mssclamp.Reconciler` writes `encap_mtu_table` and `mss_clamp_table` from one `GALACTIC_CNI_TCP_MSS_CLAMP` setting, so the two cannot disagree. A pod's or guest's TCP and UDP packets usually arrive `CHECKSUM_PARTIAL`, which no BPF helper can clear, and a device without checksum offload (a tap whose guest did not negotiate it) would finish that checksum into the middle of the error. So the error is laid out with room pushed at the front until the kernel's checksum spot (the original transport header plus 16 for TCP, 6 otherwise) lands on a trailing slot word, with a pad word chosen so the sum the kernel writes there equals what is already there. `usid_pmtu_tap_test.go` checks this against the kernel through a `virtio_net_hdr` tap, with offload on and off.
- **Per-VRF traffic is counted in each direction in its own per-CPU map, not in `vrf_value`.** `vrf_traffic_counters` is a `BPF_MAP_TYPE_PERCPU_HASH` keyed like `vrf_table` (Block<<12|Argument, so one VPC per node) holding packets, tenant bytes and claimed drops for `ingress` and `egress`. Per CPU, because the hot path then increments its own copy with no atomic and no shared cache line; a new map, because changing `vrf_value`'s layout would make `attach.Load` recreate `vrf_table` empty. The datapath only looks rows up: `VRFTable.Register` creates a VRF's row with `BPF_NOEXIST`, so registering again never resets it, `Unregister` removes it, and `Reconcile` ends with `SyncTraffic`, which creates rows for VRFs that predate the map and removes orphans, re-checking `vrf_table` before each delete and again after it, so a VRF registered while it runs keeps its row. `galactic-cni run` also calls `SyncTraffic` once the datapath loads, so an upgraded node counts from its first packet rather than its first 5-minute GC sweep. Every writer of `vrf_table` rows (CNI ADD, the datapath repair, the GC sweep, the ingress sidecar) goes through `VRFTable`, so none needs code of its own. Inbound counts at `usid_ingress`'s two redirects (warm FIB and `bpf_redirect_neigh`). Outbound counts at `usid_egress`'s encapsulating redirect, which covers egress shards, and its VIP reply redirect, and at the service path's redirects, remote ones inside `service_remote_encap` because its caller cannot tell a forwarded packet from a Packet Too Big. Same-node traffic between two attachments never reaches `usid_ingress`: the sender's `usid_egress` matches the receiver's local pass-through entry and hands the packet to the kernel, so that hit counts once in each direction on the shared VPC row, except a destination equal to the sender's own `tenant_gw_table` gateway. Bytes are the tenant packet's own length in both directions, unlike `vrf_value.bytes`, which counts the whole frame at step 6 and stays for `galactic_usid_vrf_bytes_total` and make-before-break checks. Exported as `galactic_usid_vrf_{forwarded_packets,forwarded_bytes,dropped_packets}_total{direction}`; see [docs/metrics.md](../observability/vpc-dataplane.md#traffic). The gateway check reads the destination from `service_fib_scratch` itself rather than taking a pointer to it: passed a map-value pointer as a subprogram argument, `usid_egress`'s verifier cost went past the kernel's 1M-instruction limit.
- **An uplink that drops out of auto-detection keeps `usid_ingress` for 60 seconds.** `attach.Watch` re-resolves the uplink set on every netlink link or route event, and an uplink found only through BGP-learned routes leaves that set whenever FRR withdraws them, which it does for every restart (#778). Detaching on the first miss dropped SRv6 traffic still arriving on that bond for 6 to 14 seconds. An attached interface whose link still exists now keeps its hook, and its place in the published uplink list, until it has been missing for `detachHoldDown`. Watch re-evaluates on its own when the hold-down ends, so an uplink that really stops carrying fabric routes is still detached. A deleted link is dropped at once.
- **CRD-driven config, no sidecar gRPC.** `galactic-bgp` writes `BGPVRFInstance`/`BGPAdvertisement` CRDs directly via a bare controller-runtime client; `galactic-router`'s reconciler picks them up. No in-node gRPC calls between any of the CNI-chain binaries and `galactic-router`.
- **DEL is intentionally minimal everywhere in the CNI chain; GC reclaims shared state asynchronously.** Every binary's own `cmdDel` only cleans up what it itself created *and* is safe to release immediately per-container: IPAM deallocation via `galactic-ipam`'s own on-disk marker file; guest-netns flush/host-device DEL in `galactic-veth`; and, in both `galactic-veth`/`galactic-tap`, deleting this attachment's own host/guest veth pair or tap device outright, since that interface is private to one attachment and no sibling pod/VM can ever depend on it. None of them delete the VRF, routes, the eBPF `vrf_table` entry, or `BGPAdvertisement`/`BGPVRFInstance` CRDs — those are keyed by `(vpc, vpcAttachment)` or `(vpc, node)` and may be shared/reused by another pod/VM (deleting them in DEL would race with a concurrent ADD during restarts). `galactic-router`'s GC controller (see [ARCHITECTURE-ROUTER.md](../router/architecture.md)) reclaims orphaned CRDs and stale kernel VRFs once no live container still references them; the installer separately sweeps stale eBPF VRF entries — see [docs/cni/gc-cmd-sequence.md](../cni/gc-cmd-sequence.md) for why the host veth/tap interface has no GC path of its own at all.
- **A DSR backend's node translates the VIP, and its replies leave out the fabric uplink unencapsulated.** `galactic-gateway` carries a client's packet unmodified inside the outer IPv6 header, with Next Header 41 for an IPv6 client and 4 for an IPv4 one, to the backend node's End.DT46 uSID with the backend's slot in bits 81–96. Workloads are IPv6 only, so every backend is IPv6. For an IPv6 client, `usid_ingress` decapsulates the packet and, before the VRF FIB lookup, looks up `vip_xlat_table`'s ingress row by (Block, Argument, slot, protocol, destination address, destination port) and rewrites the destination to the backend's address and port, leaving the client's source alone. On the way back, `usid_egress` (TC ingress of the backend's host-side veth or tap, the same code for both kinds) looks up the egress row by the reply's source address and port, rewrites the source to the VIP, clamps a SYN-ACK's MSS to the IPv6 limit, and redirects the frame unencapsulated to the node's fabric uplink neighbor from `public_uplink_table`, skipping NPTv6 and `egress_route_table` entirely: that table's `::/0` and IPv4 entries would encapsulate the reply toward a NAT shard, which would translate an already correctly addressed reply. The reply is then ordinary routed traffic with the VIP as its source; where the compute node's uplink is an edge node, that node's `edge_return` forwards it because its source is in `vip_addr_table` (see [ARCHITECTURE-GATEWAY.md](../gateway/packet-paths.md#return-path-edgedsrc-program-edge_return)). An egress shard never claims it: `nat_ingress` takes only its own SID and masquerade addresses as destinations. Until `public_uplink_table` is written the reply falls through to the ordinary egress path. A packet to a multicast or link-local destination never takes this path: `usid_egress` hands it to the kernel before the VIP lookup and NPTv6, as well as `egress_route_table`, since a VIP's client is never link-local. A host-side TCP probe of the backend's bound port, sourced from the host interface's link-local address, gets its reply that way (see [the backend health design](../gateway/backend-health.md#reply-path)). The row holds one next hop, used for IPv4 frames too: the first resolved IPv6 neighbor of the first eBPF interface, in `attach.ResolveInterfaces` order, that has carrier (`srv6.ResolvePublicUplink`). Every reply from the node takes that uplink, whichever gateway node took the request, so on a compute node dual-homed to two edge nodes the row must follow the uplinks. `galactic-cni run` re-resolves it on every link change and IPv6 neighbor change (`installer.watchPublicUplink`, debounced 250 ms) and on every datapath repair pass (`attachreg.FillNode`), and rewrites it when it differs. A pass that resolves nothing keeps the row it has. `task verify:gateway-node-loss` in `deploy/containerlab/` takes one of `dfw-worker`'s two edge nodes off the fabric and checks the VIP still serves through the other.

- **An IPv4 VIP reaches its IPv6 backend through stateless translation (RFC 7915).** `vip_siit_ingress` runs on a decapsulated IPv4 TCP or UDP packet whose outer destination carries a backend slot (only `galactic-gateway`'s do; every other IPv4 packet skips it and is delivered as before). It looks up the ingress row keyed on the IPv4-mapped destination (`::ffff:a.b.c.d`) and, on a hit, rewrites the packet into IPv6 with `bpf_skb_change_proto`: the source is the RFC 6052 well-known prefix plus the client's address, so 192.0.2.10 arrives as `64:ff9b::c000:20a`; the destination and destination port are the row's backend; the traffic class is the TOS, the hop limit the TTL less one (the translator forwards as a router, RFC 7915 §4.1), the flow label 0, and the payload length the IPv4 total length less the header. IPv4 options are dropped. The packet then takes the IPv6 path to the backend, skipping the IPv6 VIP lookup and NPTv6. On the way back, `vip_siit_egress` runs first on every IPv6 TCP or UDP packet with no extension header whose destination is in `64:ff9b::/96`, a check `usid_egress` makes through the packet pointer so other IPv6 traffic pays no helper call, and looks up an *egress-translated* row (direction 2) by the reply's source address and port. A hit becomes an IPv4 packet from the VIP and VIP port to the embedded client address, with TTL the hop limit less one, TOS from the traffic class, no options, ID 0 and Don't Fragment set, and a computed header checksum. It then leaves through the IPv4 VIP-reply path: its SYN-ACK is clamped to the IPv4 MSS limit, since the client's segments reach the backend's node as IPv4 inside the gateway's 40-byte header, and it is redirected to the uplink neighbor. A reply to `64:ff9b::/96` that matches no row is ordinary NAT64 egress and goes on unchanged. Because the egress-translated row has its own direction and is looked up only for `64:ff9b::/96` destinations, one backend socket can serve an IPv4 VIP and an IPv6 VIP. Both directions fix the L4 checksum incrementally for the pseudo-header (`bpf_csum_diff` over the old and new addresses, passed to `bpf_l4_csum_replace` with `BPF_F_PSEUDO_HDR`, which keeps a `CHECKSUM_PARTIAL` packet right) and for the port. The new header is stored with `BPF_F_RECOMPUTE_CSUM`, which keeps a `CHECKSUM_COMPLETE` sum right. A translated UDP checksum that comes to zero is sent as `0xFFFF`. Three cases are dropped and counted. An IPv4 UDP datagram with no checksum is `vip_udp_no_checksum`: computing one means summing the whole payload, which the verifier budget and the loader's missing `CAP_PERFMON` rule out, and RFC 7915 lets a stateless translator refuse it. An IPv4 fragment to a backend slot is `vip_ipv4_fragment`: the gateway never sends one, and a later fragment has no ports to find its row by. A packet whose TTL or hop limit is 1 or less is `vip_ttl_exceeded`. An ingress row whose value is an IPv4-mapped address, an IPv4 backend written by a router that predates translation, is `vip_ipv4_backend`: delivering the packet untranslated would lose it at an IPv6-only workload with nothing counted, so such a skew fails closed. A translation that fails partway is `vip_xlat_failed`. These are slots 42–46, so `drop_reasons` grew, and `attach.Load` recreates that map alone on upgrade and on a downgrade past it, restarting its counters. The IPv6 paths skip an IPv4-mapped address, so an IPv6 packet can never take an IPv4 VIP's row. An IPv4 VIP's rows exist only while a gateway reports the rule's IPv4 VIP loaded, since `galactic-router` writes its bindings only then. Both translations are global BPF functions, verified once each. See [ARCHITECTURE-ROUTER.md](../router/architecture.md) for the map's layout and lifecycle, and `usid_vipxlat4_test.go` for the kernel tests.
- **`galactic-cni`'s install DaemonSet is a Go installer, not a shell script.** See Known Constraints below.

---

- **Interface traffic policy is decided at each egress exit, and is off unless a node turns it on.** `usid_egress` and `usid_service_egress` call `tp_capture` at their top, before any NPTv6 or VIP rewrite, which parses the packet with `bpf_skb_load_bytes` into the per-CPU `tp_scratch`; every exit that hands the packet on then calls `tp_decide` with the forwarding path that exit implies (a shard group sentinel or a route whose SID's locator is in `tp_nat_locator_table` is PublicNAT, the VIP reply redirect PublicService, everything else Private). `tp_decide` walks the interface's snapshot in `tp_binding_table` (a `HASH_OF_MAPS` keyed by ifindex and direction) with `bpf_for_each_map_elem` and counts exactly one outcome. Both return at once while `tp_state.mode` is off, the default, so the datapath forwards as before. Entries carry precomputed masks: a prefix compare that branched on the length cost the verifier about 13,000 instructions. The maps are written through `internal/plumbing/ebpf/tpmap`, whose kernel tests hold the datapath to the Go evaluator in `internal/trafficpolicy`. Toward the workload, `usid_ingress` decides after decapsulation and before any of its three delivery helpers, with the path read from the outer header (a private service tunnel is Private, a gateway slot PublicService, an outer source in `tp_nat_locator_table` PublicNAT), and marks what it sends through the host interface so `tp_deliver`, a new program on every managed interface's tc egress, does not decide it twice; `tp_deliver` decides everything else the host transmits to the interface as Private. While the mode is on, the master plugins leave a new host side down and `galactic-bgp` brings it up only after writing the interface's `tp_iface_table` row with a fresh policy token and reading both hooks' programs back; CNI DEL removes the row, its addresses, fallback counters and bindings; the ingress sidecar's peers are `infra` rows that are never evaluated. See [the design](../designs/interface-traffic-policy.md).

## Known Constraints

- **No binary's `cmdDel` tears down shared kernel/CRD state.** By design (see Key Design Decisions above) — cleanup of the VRF, routes, the eBPF `vrf_table` entry, and BGP CRDs is deferred to `galactic-router`'s asynchronous GC controller, not performed synchronously in any chain binary's `cmdDel`. The per-attachment host veth/tap interface is the one exception: it is private, not shared, so `cmdDel` deletes it directly instead of deferring it.
- **`internal/plumbing/vrf`'s tests run only as root, and `internal/cni/route` has no unit tests.** `vrf` requires `CAP_NET_ADMIN` and a real kernel, so its tests skip in an unprivileged `task test:unit`; `route` (wrapped by `internal/cniroute`, which does have its own tests) was never backfilled with tests of its own when the CNI plugin-chain split moved its caller out of `internal/cni`. `internal/plumbing/intf` is fully unit-testable (pure functions only). Kernel-path coverage otherwise comes from the e2e suite (`task test:e2e`).
- **The e2e suite doesn't cover `galactic-route` or `galactic-bgp`.** `TestCNITapInterface` (`tests/e2e/e2e_test.go`) only drives `galactic-tap`'s own ADD — verifying BGP/SRv6/eBPF publish end-to-end would need a `BGPRouter` CRD fixture and additional RBAC the test doesn't set up. This gap predates the CNI plugin-chain split too: the monolithic `galactic-cni` this replaced was never e2e-verified past its own CNI result shape either.
- **`galactic-cni`'s install DaemonSet is a Go installer, not a shell script.** `config/galactic-cni/configmap.yaml`/`install.sh` were deleted; `config/galactic-cni/daemonset.yaml` now runs `hostNetwork: true` with an `install-cni` init container (`command: ["/galactic-cni", "init"]`, calling `installer.Bootstrap`) and a `credential-refresh` main container (`command: ["/galactic-cni", "run"]`, calling `installer.Run`), both on the same image (see the component Dockerfile and `.github/workflows/publish.yaml`). `Bootstrap` writes every binary in the CNI chain to `/opt/cni/bin`, the static conflist to `/etc/cni/net.d/10-galactic.conflist`, and `ca.crt`/kubeconfig to `/var/lib/galactic` (chosen over `/etc/galactic` specifically so it lands under `/var`, the one path immutable-root distros like Talos allow hostPath writes to without a host-level `extraMounts` entry); `Run` refreshes the kubeconfig token every 300s and rotates the CNI log once it exceeds 10MB. `/opt/cni/bin` is fixed by the CNI/kubelet plugin-discovery convention and can't be relocated by this DaemonSet alone — on Talos it needs its own `extraMounts` entry in the machine config if it isn't writable by default. The `run` container also serves gRPC health checks on port `5180` (`livenessProbe`/`readinessProbe` in the DaemonSet spec), and `config/galactic-cni/rbac.yaml` grants `get` on `nodes` for `Bootstrap`'s node-identity check.
- **A DSR reply on an IPv4 VIP needs IPv4 routing past the backend node.** The reply leaves the node unencapsulated, so the uplink neighbor and every hop to the client must route IPv4 and reach the client, as the containerlab lab's dual-stack underlay does; a fabric that carries only IPv6 between the compute tier and the edge cannot return it. A gateway node in front of the backend forwards it only while it loads IPv4 VIPs (`GALACTIC_GATEWAY_IPV4_VIPS`), since that is what puts the VIP in its `vip_addr_table`. Only a TCP or UDP reply with no extension header is translated. An ICMPv6 error (port unreachable, Packet Too Big), a packet with an extension header and an IPv6 fragment, sent to `64:ff9b::/96`, leave through NAT64 egress from the backend's own address, so the client never receives them as VIP traffic; a backend's IPv6 stack fragments only a reply bigger than its path MTU. A VIP therefore serves only replies that fit unfragmented, which TCP's MSS clamp keeps true and a large UDP reply does not. A translated reply has Don't Fragment set, and an ICMPv4 Fragmentation Needed it draws goes to the VIP, not back to the backend, which never learns of it. The workload must accept sources in `64:ff9b::/96` and route replies to them through its default route, and interface traffic policy, which runs on the translated packet, must allow those sources: an IPv4 CIDR or `ipFamily: IPv4` rule never matches an IPv4 VIP's clients. A `galactic-router` from `main` with the native IPv4 path writes IPv4 rows with an IPv4 backend and reports them Bound; beside this datapath with IPv4 VIPs switched on, its traffic is dropped as `vip_ipv4_backend`, so backend nodes roll `galactic-cni` and `galactic-router` together before the switch goes on.
- **`usid_ingress` doesn't send an ICMP error when its FIB lookup returns `BPF_FIB_LKUP_RET_FRAG_NEEDED`.** That is a decapsulated packet bigger than the local tenant interface it is for. The program counts `DROP_REASON_FIB_FRAG_NEEDED` and drops it, unlike the static-route `SEG6_LOCAL_ACTION_END_DT46` path this datapath replaces, where the kernel's own IPv6 stack emits a Packet Too Big. It needs a tenant interface whose MTU is smaller than the fabric's limit, which galactic-veth does not create. The sending direction, a tenant packet too big to encapsulate, does get an error (see Key Design Decisions above, #641). `send_too_big`'s offload layout assumes Linux's `csum_start` for a TCP or UDP packet is its transport header right after the IP header; an IPv6 packet with extension headers before a partially checksummed transport header, or an SCTP packet whose CRC32c is offloaded, could have its error corrupted by a device without checksum offload. The edge gateway's own XDP program still sends no error for its FIB lookup; see [ARCHITECTURE-GATEWAY.md](../gateway/architecture.md#health-and-failures).

---

## Testing

Run `task test:unit` for pure logic and controller tests, `task test:unit-root` for privileged kernel paths, and `task test:e2e` for the Kind lifecycle tests. The full pre-PR pipeline is `task ci`. Unprivileged passes do not prove kernel paths that were skipped.
