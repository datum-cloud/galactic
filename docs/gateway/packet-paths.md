# Gateway reconciliation and packet paths

Read [architecture](architecture.md) for the component boundaries and [configuration](configuration.md) for API settings. This reference follows the control-plane pass and packet processing in detail.

### Control-plane reconcile flow (per gateway node, per `NetworkGateway` reconcile)

`NetworkGatewayReconciler.Reconcile` runs the aggregate, List-driven pass
that converges this node's whole gateway engine:

1. **Assemble desired state.** Lists every accepted, non-deleting
   `NetworkService` in the namespace — under the DSR anycast model every
   gateway node in a PoP serves every accepted rule identically, so there
   is no primary/secondary subset to filter on — expands each rule's
   `backendSelector` into backends: the IPv6 interface addresses of the
   `VPCAttachment`s it selects in the rule's VPC, for its IPv6 VIP and, when
   IPv4 VIPs load, its IPv4 VIP too, since workloads are IPv6 only and the
   backend node translates the IPv4 VIP's flows (`rulebackends.go`'s
   `selectRuleBackends`, over one cluster-wide attachment list per pass
   grouped by VPC; `gateway.DesiredRule` carries one list per VIP family as
   `Backends` and `IPv4Backends`, the same backends unless another rule owns
   one family's claim on a backend, and `KernelDatapath` builds a Maglev
   table per family with each backend's `srv6.BackendSlot` in its uSID, the
   slot its node keys both families' ingress rows on), leaves out each
   backend an older rule serves for the same VIP family on the same backend
   port and protocol (`ruleBackendOwners`: a backend node
   translates a backend's replies back to only one VIP, so the newer rule's
   flows would be dropped there), resolves each to the SRv6 uSID of the node its
   attachment reports via `usidresolver.go`'s `buildBackendSIDIndex`, writes
   the backend's slot (`srv6.BackendSlot`, a hash of its address and port)
   into bits 81–96 of that uSID so a node hosting several of the rule's
   backends can tell which one Maglev chose (#799), and converges
   `gateway.Engine` toward the result. The reconciler watches
   `VPCAttachment`s cluster-wide, so a backend appearing, moving node or
   changing address reconverges every gateway without a rule edit. Its
   predicate (`vpcAttachmentBackendChanged`) drops updates that change
   none of the fields `selectRuleBackends` reads (labels, `status.vpc`,
   `status.node`, `spec.interface.addresses`, `spec.interface.mode`), so a
   conditions-only status write triggers no pass. The router's
   `NetworkServiceBindingReconciler` uses the same predicate and re-queues
   only the rules in the attachment's VPC. A deleting rule stays in that state,
   as *draining*, while it still carries the teardown finalizer and any
   `BGPAdvertisement` labelled with its name exists: it is not advertised
   and its `<node>/Programmed` condition is left alone, but the datapath
   keeps serving it. Once the last labelled advertisement is gone, the node
   keeps it loaded for a further `ruleDrainDelay` (5s, tracked in memory by
   `networkgateway_drain.go`'s `ruleDrainTracker`, even after the object
   itself is gone) so the BGP withdrawal can reach every peer, then drops it
   (issue #715). The `BGPAdvertisement` watch wakes the pass when the
   advertisements are deleted, and a `RequeueAfter` wakes the one that ends
   the delay. A restarted process remembers nothing, so it drops a rule
   whose advertisements are already gone on its first pass.
2. **Wire BGP.** Reconciles one `BGPAdvertisement` per loaded rule per
   non-empty VIP address family, name-qualified by node
   (`<rule>-<node>-<hash>-v4`/`-v6` — required, not cosmetic, since every
   gateway node computes the same rule independently), and deletes any other
   advertisement this node made for the rule. This reuses the existing `l2vpn/evpn` Type-5 IP-Prefix
   advertisement path end-to-end unmodified. `VRFID`/`Function` are left
   unset (these routes need no SRv6 decap behavior of their own — a
   different Route Distinguisher per originating node, not a decap
   Function, is what keeps every node's route alive as an independent,
   non-competing path). **No `LocalPreference` is set** — every gateway
   node's route is equally preferred by construction. A rule that fails to
   build (no backend uSID resolves, or an address is malformed) or that the
   engine refuses (over quota, or a VIP the datapath rejects) is not
   advertised, and any route an earlier pass published for it is withdrawn,
   so the fabric never sends a VIP's traffic to a node with nothing loaded
   for it. A rule where only some backends resolve is loaded and advertised
   with the rest (#713). IPv4 VIPs are left out of the engine, and their
   `-v4` advertisement withdrawn with the prune above, unless
   `GALACTIC_GATEWAY_IPV4_VIPS` is on. The rule's IPv6 VIPs serve without
   them, and a rule with no other VIP is not loaded. With the switch on, the
   IPv4 VIPs are still left out, and the IPv6 ones still serve, when no
   selected attachment has an IPv6 address resolving to a backend this rule
   serves for its IPv4 VIP or the rule has more than one IPv4 VIP. Otherwise
   the IPv4 VIP is the readiness gate's (`networkgateway_ipv4gate.go`): each pass lists the namespace's
   generated IPv4 `ServiceVIPBinding`s once (`listIPv4Bindings`), and
   `resolveFamilyBackends` keeps only the backends whose IPv4 VIP binding is
   the one `generatedBinding` describes (the IPv4 VIP paired with the
   backend's IPv6 address) for the rule's current spec, is not being deleted
   and is `Bound` for its current generation (`ipv4Bindings.unbound`), naming
   the others as unresolved. `-v4` is advertised only then (`ipv4Loaded`),
   and a closed gate deletes it before the other families are written
   (`withdrawIPv4Advertisement`), so a failed `-v6` write never delays it.
   While no backend is Bound, the VIP still loads over every eligible backend
   but stays unadvertised (`ipv4Unbound`), because `galactic-router` writes
   IPv4 bindings only while a gateway reports the VIP loaded; leaving it out
   would mean no binding is ever written. A `ServiceVIPBinding` watch,
   registered only with the switch on (`ipv4BindingReadinessChanged`), wakes
   the pass when a binding appears, goes, changes spec, starts being deleted
   or changes whether it is Bound. Each node records the result on the rule
   as its
   own `<node>/Programmed` condition (`Programmed`, `BackendsUnresolved`,
   `LoadFailed`, `InvalidRule`, or `NoServedVIP` for an IPv4-only rule, with
   the error or the unresolved backends in the message), a
   `<node>/Advertised` condition (`advertisedCondition`: `True` with
   `Advertised` once the node published the rule's `BGPAdvertisement`s and
   `galactic-router` reports each one `Advertised` for its current
   generation (`uninstalledAdvertisements`), or `False` with
   `NotProgrammed`, `NoRouter`, `AdvertisementFailed` or
   `AdvertisementPending`, so a rule's publish failure is on the rule and not
   only on the node's `NetworkGateway`; a status write that changes whether
   one of its advertisements is installed wakes the pass, `installedChanged`),
   and, for a rule with an IPv4 VIP, a
   `<node>/IPv4Served` condition: `True` with reason
   `Advertised`, or `False` with `NotAdvertised` (loaded over Bound backends
   but the route not published), `BindingsNotBound` (loaded, no backend
   Bound), `Unsupported` (switch off), `NoBackend`, `MultipleVIPs` or
   `NotLoaded` (the rule as a whole is not loaded). The first three mean
   loaded (`ipv4LoadedReasons`), and `galactic-router` writes a rule's IPv4
   bindings only while some node reports one of them. Every pass also
   removes the `Programmed`, `Advertised` and `IPv4Served` conditions of any node no
   `NetworkGateway` in the namespace targets (`departedGatewayNodes`,
   `removeDepartedNodeConditions`), so a node that left without its
   conditions being cleared cannot keep a loaded reason, and with it the
   backend nodes' IPv4 bindings, alive. A node the cached list lacks is
   pruned only once an uncached `APIReader` list confirms it, and that read
   runs only when the cache suggests a departure, so a lagging cache never
   strips a new node's conditions. A node writes its conditions only after
   its own `NetworkGateway` exists, so no window remains. The type is
   node-scoped because
   `NetworkService` status is shared by every gateway node while loading
   is per node; a node writes it only when it changes, and a
   departing, deleted, or disabled node's conditions are removed with its
   advertisements. `NetworkServiceReconciler` then rolls every node's
   conditions up into rule-wide ones, `Programmed`, `Advertised`,
   `BackendsReady`, `IPv4Served` (only on a rule with an IPv4 VIP) and
   `Ready` (`summaryConditions`,
   `internal/controller/networkservice_summary.go`), so a client such as the
   tenant-facing API reads one rule and never `NetworkGateway` (#708). Only
   gateway nodes reporting a `Programmed` condition for the current
   generation count, since a node that has not reported advertises nothing.
   `Ready` reads `IPv4Served` only for a rule with no IPv6 VIP, so a rule
   whose IPv6 VIP serves is not reported down on gateways with IPv4 VIPs
   off. The summary is re-read uncached (`APIReader`), so it computes from
   the write that triggered it.
   A failing summary takes the reason every failing node shares, or a
   generic one when they differ. Every input is shared state, so every
   gateway node computes the same summary and writes it only when it
   changes; `clearNodeRuleConditions` recomputes it too, for the last
   gateway node to leave. The `NetworkGateway`'s `EngineDegraded` message
   lists every failed rule. Every rule
   advertisement carries a `networkRuleLabel` label and a plain (not
   controller, no `blockOwnerDeletion`) owner reference to its
   `NetworkService`, both backfilled on existing objects, and nothing is
   created or updated for a rule that is being deleted. A pass whose cache
   has not yet seen that deletion can still create one after teardown has
   finished. Each pass therefore withdraws this node's advertisements for
   rules missing from its list once an uncached read confirms the rule is
   gone (`sweepOrphanedAdvertisements`, #763). The owner reference lets
   Kubernetes garbage collection delete any that remain.
3. **Crash recovery.** Runs `Engine.ReconcileOrphans` (see
   [Crash recovery](architecture.md#recovery) below).

`NetworkServiceReconciler.Reconcile` separately owns two **per-object**
lifecycle pieces the aggregate pass above is the wrong place for:
`status.conditions`'s `Accepted` condition (`updateAcceptedCondition` — set
once gateway nodes exist for the namespace) and the
finalizer-guarded teardown ordering on deletion (`reconcileDelete`: delete
every `BGPAdvertisement` labelled with the rule's name, on any node,
*before* releasing quota/reservation state, then list them again through
the manager's uncached API reader and, if another node created one the
cache missed, delete it and requeue instead of removing the finalizer).
Each gateway node removes the rule's `vip_table` rows only after those
deletes and its drain delay (step 1 above), which is what the
`Datapath.RemoveRule` contract requires: withdraw the route first, or
traffic the fabric still sends to the VIP is dropped. The finalizer does
not wait for every node to finish draining; that would need a cross-node
protocol that does not exist.

Every gateway node's own process runs both reconcilers, unconditionally, on
every `NetworkGateway`/`NetworkService` in the namespace, with no leader
election anywhere in this codebase — safe because the reconcile logic is
either idempotent (finalizer add/remove, `BGPAdvertisement` create/delete)
or a pure function of inputs every gateway node observes identically
(`vip_table` registration, the Maglev table itself). A rule carries no
`gatewayRef`, so both reconcilers watch the *other* CRD type and broadcast
to every object in the namespace on change (`ruleToGatewayRequests`,
`gatewayToRuleRequests`) rather than targeting a specific object.

### Packet path (`internal/plumbing/ebpf/edgeprog/edgedsr.c`, program `edge_lb`)

IPv6 and IPv4, plain TCP/UDP: IPv6 without extension headers, IPv4 with or
without options. Attached to
the node's public/underlay-facing uplink. There is no "is this a reply to me"
direction check: a reply never reaches this program, which sees only the
forward half, so it has exactly one branch, not two. Replies are
`edge_return`'s, on a different attach point — see below.

1. **Parse** the outer Ethernet + IP header, then the L4 header (TCP or
   UDP only). An IPv4 header is checked before anything is claimed: version
   4, a header of at least 20 bytes, a total length that covers it and fits
   the frame, and a whole TCP or UDP header inside that length; options are
   skipped and carried unchanged. Not IP, unparseable, malformed, or not
   TCP/UDP — unclaimed: handed to
   the dispatcher's later slots, in practice the egress shard's, if the
   interface carries their role (see
   [below](#sharing-the-xdp-hook-xdpdispatch)), otherwise `XDP_PASS` to the
   kernel stack, e.g. BGP/SSH to the node itself. Only the
   source/destination port are ever read; nothing is rewritten.
2. **Match** `(proto, dst port, dst addr)` against `vip_table` (a VIP is
   globally unique by construction, so the key has no tenant dimension). An
   IPv4 address is keyed in its IPv4-mapped form (`::ffff:a.b.c.d`), which
   `edgemap` refuses as an IPv6 VIP, so both families share every map
   without colliding and no map changed shape for IPv4. No match —
   unclaimed, as above (not one of this gateway's VIPs). An IPv4 fragment
   addressed to a VIP is dropped and counted as `ipv4_fragment` instead: a
   later fragment carries no ports to hash, so one packet's fragments would
   reach different backends. A fragment to any other address is unclaimed.
3. **Claimed past this point** — every subsequent failure is a drop, not a
   pass-through (this gateway owns this VIP+port+protocol). Bump
   `vip_stats_table`'s hit counters (packets/bytes/last-seen), lazily
   creating the row on first match. An empty backend list drops
   (`DROP_REASON_EMPTY_BACKEND_LIST`).
4. **Maglev lookup.** Hash the client's address with what the entry's
   `affinity` byte selects (`EDGE_AFFINITY_*`, from
   `NetworkService.spec.sessionAffinity`): its source port under `None`,
   nothing more under `ClientIP`, its L4 protocol under
   `ClientIPAndProtocol`. Look up the precomputed Maglev table
   (`vip_table`'s own `maglev_table` field, populated by the Go control
   plane's `internal/maglev.Table` — see `edgemap`'s doc comment) to get a
   backend index, deterministically and statelessly: every gateway node
   computes the identical index for the identical flow from the identical
   `(VIP, backend list)` input, which is what makes this design safe under
   anycast/ECMP — a flow's packets landing on a different gateway node
   mid-connection still resolve to the same backend. Under either client-IP
   affinity `KernelDatapath` keys the table by backend address alone rather
   than address and port, so services over the same backend addresses on
   different backend ports build the same table and pin a client to the
   same backend. `affinity` occupies padding before `generation`, so it adds
   nothing to `vip_value`'s size, and a zero byte reads as `None`. See
   [configuration.md](../gateway/configuration.md#session-affinity).
5. **Push** a fresh 40-byte outer IPv6 header addressed to the chosen
   backend's own worker-node SRv6 uSID (`vip_table`'s per-backend field,
   resolved by the Go control plane the same way any other cross-node SRv6
   destination is — see [uSID resolution](architecture.md#backend-identity)
   below), sourced from this node's own `encap_config_table` entry (this
   node's plain SRv6-reachable address — never compared against anything on a
   receive path, since no reply ever re-enters this program). Resolve the L2
   next-hop via `bpf_fib_lookup`, then leave over the interface that lookup
   selected: `XDP_TX` where the route egresses the interface the client's
   packet arrived on, `bpf_redirect` + `XDP_REDIRECT` where it does not. Those
   differ on every gateway that reaches its clients and its compute nodes over
   separate links, which is this role's normal shape — see [Known
   Constraints](architecture.md#health-and-failures) for the bug that came from returning
   `XDP_TX` unconditionally. A next hop with no neighbor entry, as after a
   link flap or a node rejoining the fabric, sends the encapsulated packet to
   the kernel with `XDP_PASS` instead, since XDP cannot start neighbor
   resolution: the kernel solicits the neighbor and forwards the packet, and
   later packets stay in XDP. Those packets are counted in `neigh_fallbacks`
   (`galactic_edge_neigh_fallbacks_total`), not as drops. Unlike the XDP
   path, they cross the node's netfilter FORWARD hook, as new flows from the
   node's own encapsulation source, so a host firewall that drops forwarded
   traffic drops them too. The inner packet travels completely unmodified —
   this is DSR's entire premise: no address or port rewriting and no checksum
   touch anywhere.

See `edgedsr.c`'s own header comment for the full byte-level walkthrough,
including the `EDGE_BARRIER_VAR` eBPF-verifier bounds-narrowing workaround
and two wire-format bugs found and fixed in `push_outer_header`: the pushed
outer IPv6 header's version nibble was left zeroed instead of set to `6`,
and the outer header's `payload_len` undercounted the inner IPv6 header's
own 40 bytes (a call site passed `ip6->payload_len` directly instead of
`sizeof(ip6hdr) + payload_len`). Both were invisible on the SRv6 uSID
decap path (`usid.c`'s decap reads fixed offsets unconditionally, without
validating either field) but would have caused any version- or
length-validating intermediate hop or receiver to reject every packet this
datapath ever pushed — found via live-kernel investigation, not
`BPF_PROG_TEST_RUN`, and covered by regression tests in `edgedsr_test.go`.

### Sharing the XDP hook (`xdpdispatch`)

An interface takes one XDP program, and `galactic-nat`'s egress shard
can run on the same edge nodes, needing the same interfaces: tenant egress
arrives on the compute-facing bond (`edge_return`'s) and its replies on the
public uplink (`edge_lb`'s). Neither binary owns the hook. The node's shared
XDP dispatcher (`internal/plumbing/ebpf/xdpdispatch`) holds it, and each
datapath runs from its own slot.

- `GALACTIC_GATEWAY_XDP_ATTACH=dispatch`, the default, opens the dispatcher,
  loads `edgedsr.c` against its maps (`edgeattach.Load` with
  `CollectionOptions.MapReplacements`), fills slot 0 with `edge_lb` and slot
  1 with `edge_return`, and renews both slots' leases. `xdpattach.DispatchSet`
  puts the dispatcher on the public targets with the public role and on the
  internal targets with the return role. The links are pinned under
  `/sys/fs/bpf/galactic-xdp`, so a gateway restart swaps its programs into
  the slots without detaching anything.
- Every unclaimed exit in `edge_lb` and `edge_return`, including the
  IPv4 packets to no VIP that carry NAT64's replies, goes through
  `dispatch_next` (`dispatch.h`), which tail-calls the later slots the
  interface's roles allow. A claimed packet never reaches them.
- The return slot never runs on an interface that also carries the public
  role: the dispatcher's root and `SetRole` both refuse it, and
  `setupGatewayDatapath` refuses an internal interface that resolves to a
  public one at startup.
- `GALACTIC_GATEWAY_XDP_ATTACH=direct` attaches the programs themselves,
  unpinned. It first detaches an idle dispatcher from the targets and
  refuses to start while another datapath's slot is live there.
  Attached directly, the programs hold their own empty copies of the
  dispatcher maps, so every unclaimed packet passes to the kernel.
- The dispatcher attaches in the host's XDP mode (`xdpmode`, see
  [docs/xdp-attach-mode.md](../operations/xdp-attach-mode.md)): generic on a host with a
  `bnxt_en` NIC (#673), native elsewhere. `Linked` and `Coverage` read the
  mode back from the kernel, and `EnsureLink` migrates a pinned link left in
  the other mode, under the dispatch lock and the bond guards, keeping every
  map, slot, lease and role row.
- `GALACTIC_GATEWAY_DATAPATH_ENABLED=false` empties the gateway's
  load-balancing slot and makes `NetworkGatewayReconciler` withdraw this
  node's VIP advertisements and report `DatapathDisabled`. A backend node
  still sends replies through it (see the return path below), so with
  internal interfaces set `setupReturnPath` loads the programs, fills and
  leases only the return slot (attaching only `edge_return` in direct mode),
  and the reconciler keeps `vip_addr_table` at every VIP its namespace's
  rules list (`gateway.KernelReturnPath`, `VIPTable.ReplaceReturnAddrs`,
  which also empties `vip_table`). With none set it loads nothing and empties
  both slots.
- The two datapaths claim disjoint traffic, a VIP destination or source here
  and a shard SID or masquerade-address destination there, so the slot
  order changes no verdict.
- The kernel ties a program array to its first user's program type, JIT
  state, frags support and expected attach type, and rejects any other
  program with a bare `EINVAL`. The root, `edge_lb`/`edge_return` and the
  shard's `nat_ingress` are all ELF `SEC("xdp")` programs (`AttachXDP`), so
  they match; a hand-built program needs `AttachType: ebpf.AttachXDP` to be
  accepted (see `edgedsr_chain_test.go`).

### Return path (`edgedsr.c`, program `edge_return`)

Where the compute tier routes through this node — the shape the
containerlab topology models, compute nodes holding links only to their
site's edge nodes — a backend's reply to a VIP crosses this node on its way
to the fabric. The kernel will not forward it: the forward half reached the
backend inside an SRv6 packet through XDP, which netfilter never saw, so
connection tracking holds no entry, marks the reply `INVALID`, and
kube-proxy's `KUBE-FORWARD` chain drops it on its first rule. No forward
packet will ever create the entry the reply is judged against, so this is
structural rather than a misconfiguration to exempt.

`edge_return` forwards the reply itself, in XDP, before netfilter runs, so
the node keeps its stock forwarding rules and needs no rule of ours ahead
of kube-proxy's. It matches on the **source address alone**
(`vip_addr_table`, keyed by VIP with no port or protocol dimension), which
also covers the ICMP errors a port-keyed match would miss; decrements the
hop limit or TTL, the kernel no longer being there to do it, updating an
IPv4 header checksum incrementally (RFC 1624); resolves the next hop through
the same `bpf_fib_lookup`, `AF_INET` for an IPv4 reply; and leaves over the
interface that lookup selected. An IPv4 reply's header is validated as
`edge_lb` validates it before it is claimed. It is as stateless as the forward path and has no
relationship to the forward half's backend choice, so a site whose two edge
nodes take the request and the reply respectively still works — both hold
the same `vip_addr_table` rows.

The reply reaches this node already addressed from the VIP. The backend's own
node rewrites its source from the backend's address to the VIP in
`usid_egress`, translating an IPv4 VIP's IPv6 reply back to IPv4 from the VIP
to the client, and sends it unencapsulated
to its fabric uplink neighbor, bypassing the tenant VRF's egress routes, so no
egress shard ever sees or translates it (see
[ARCHITECTURE-CNI.md](../cni/architecture.md#key-design-decisions)). An IPv4 VIP's
address is in `vip_addr_table` only on a node that loads IPv4 VIPs, so only
such a node forwards its replies.

Whether a reply crosses an edge node at all depends on the site:

| Topology | Compute node's uplink neighbor | Reply path |
|---|---|---|
| containerlab | A site edge node (compute links only to edges) | Edge node's `edge_return` forwards it |
| Datum production and staging | The hosting provider's (servers.com, AS7979) ToR/VRRP gateway, reached over `bond0` | Straight to the provider, never touching an edge |

In a Datum site `bond0` is the compute node's first public uplink, and
`usid_egress` rewrites the MACs and `bpf_redirect`s with no FIB lookup, so the
reply goes to whatever `srv6.ResolvePublicUplink` resolved. The provider does
not source-filter Datum prefixes on compute ports (checked 2026-10-28 in
staging us-east-1: a spoofed-source probe from a compute node to `1.1.1.1` and
`2606:4700:4700::1111` got SYN-ACKs back to the site edges). So in a Datum site
the reply path needs no edge state. `edge_return` and `vip_addr_table` matter
there only if `bond0` loses its neighbor and `ResolvePublicUplink` falls back to
another interface whose first neighbor is an edge. Both edges still need IPv4
VIPs on, for the forward path and for that failover case.

Attached only to `GALACTIC_GATEWAY_INTERNAL_INTERFACES`, never the public
uplink: on the uplink an external client could source a packet from a VIP
address and have it forwarded unexamined. A node with no compute tier
behind it sets nothing, attaches no return program, and its packet path is
unchanged.

`vip_addr_table` is maintained by `edgemap.VIPTable` alongside `vip_table`
itself, an address present exactly while some rule still uses it, with its
own generation for the same crash-safe reconcile cutoff. Its counters live
in `vip_return_stats_table` and surface as `galactic_edge_return_*`,
labeled by `vip` and `vpc`.
