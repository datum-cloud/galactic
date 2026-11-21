# Worker service contract

Status: version `v1alpha1`.
[#1433](https://github.com/datum-cloud/galactic/issues/1433) implements the
service (`cmd/galactic-worker`, `internal/worker`), its protobuf API
(`api/galactic/worker/v1alpha1`), the client library (`pkg/workerclient`) and
the delivery module interface (`internal/worker/module`). The Tasks named in
each section own the rest and its tests. Decision IDs (D1, D2, …) refer to the
[decision log](README.md#decision-log).

Galactic Worker is one process per node. Service agents (NAT, Gateway, the
Envoy galactic-vrf sidecar and the provider connector) ask it to deliver tenant
traffic between their own handoff point and tenant destinations. Worker checks
the request against existing authority, decides whether each destination is
Local (on this node) or Fabric (on another node), programs the host, and reports
what it programmed and what it observed. Packets never pass through Worker: it
programs kernel hooks, maps and routes, and the datapath forwards on its own.

## Claims

A **delivery claim** is the unit of the API (D1).

| Field            | Meaning                                                                                                                                                     |
| ---------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `caller`         | The authenticated client identity (D8). Worker derives it from the connection; a client cannot supply it.                                                   |
| `node`           | The physical node. A request naming another node is refused with `INVALID_ARGUMENT`.                                                                        |
| `vpc`            | The VPC the claim acts in. It must equal the VPC of the claim's attachment (see [trusted sources](#trusted-sources)).                                       |
| `attachment_uid` | UID of the VPCAttachment or EdgeAttachment that is the service's handoff point in that VPC.                                                                 |
| `generation`     | A client-assigned `uint64`. Every change to a claim carries a larger generation than the last accepted one.                                                 |
| `spec`           | The handoff kind (`tap`, `veth_pair`, `routed_link`, `socket`), the destinations (an attachment, shard or backend reference each), and the mode preference. |

The key is `(caller, node, vpc, attachment_uid)`. The handoff resources of one
attachment (its TAP, internal veth pair or routed link) belong to one caller.
A second caller that names the same attachment gets `PERMISSION_DENIED` with
reason `AttachmentClaimedByAnotherCaller`. Fabric state for a VPC is shared:
any number of claims may resolve destinations through the same VPC.

A destination names an attachment, a shard or a backend. Worker resolves
attachment and shard destinations; a shard is named by its EgressShard's name
(`ShardRef.name`), and a request that sets the unused `group` or `index` gets
`INVALID_ARGUMENT`/`MalformedSpec` (D31). The backend resolver is added by
[#1438](https://github.com/datum-cloud/galactic/issues/1438). Until then a
backend destination is accepted and reports `Resolved=False` with reason
`DestinationKindUnsupported` (D20).

The NAT shard has no VPCAttachment in the VPCs it serves, so its `veth_pair`
claim may name its own EgressShard as `attachment_uid` (D30). Worker allows
that only when the allowlist marks the caller with `egressShardClaims`
(otherwise `PERMISSION_DENIED`/`CapabilityNotAllowed`), every destination is
a shard and the handoff is `veth_pair` (otherwise
`INVALID_ARGUMENT`/`MalformedSpec`), the EgressShard runs on this node, and
the VPC has an admitted VPCAttachment on this node (otherwise
`PERMISSION_DENIED`/`VPCNotAuthorized`). Worker checks the last two again on
every reconcile and withdraws the claim with `AuthorizationRevoked` once
either fails.

The mode preference is `auto`, `local` or `fabric`. `auto` lets Worker resolve
each destination. `local` and `fabric` restrict the result; a destination that
cannot resolve to the requested mode reports `Resolved=False` with reason
`ModeUnavailable`.

A **connector claim** (D37) is how galactic-edge hands Worker an edge host
link it created. Its spec uses the `routed_link` handoff, names no
destinations and sets `edge_link`: the link's name and the prefixes the link
carries beyond its own address. Its key names an EdgeAttachment, and Worker
resolves one Local destination for it, that attachment. Worker registers the
link with the datapath and never creates or deletes it, unlike the routed link
of the [Local module](#the-local-module). [Connector](connector.md) describes
the claim and galactic-edge's side.

## Operations

The API is a gRPC service, `galactic.worker.v1alpha1.Worker` (D7).

| RPC               | Semantics                                                                                                                                                                                                                                                                                                                                        |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `GetCapabilities` | Version negotiation and capability discovery. Must be the first call of a session. Returns the chosen API version, the session ID and lease, and each capability with its state and reason.                                                                                                                                                      |
| `Request`         | Creates a claim. Repeating the same generation and spec returns the current status and changes nothing. An existing claim with a different generation gets `FAILED_PRECONDITION`/`ClaimExists`; use `Update`. The same generation with a different spec gets `FAILED_PRECONDITION`/`GenerationConflict`.                                         |
| `Update`          | Replaces the spec of an existing claim. A generation smaller than the current one gets `ABORTED`/`StaleGeneration`. The same generation and spec is a no-op; the same generation with a different spec is `GenerationConflict`.                                                                                                                  |
| `Observe`         | Server stream of status snapshots for one claim or for all of the caller's claims. Each snapshot is complete, so a client can drop duplicates and reorderings by `observed_generation`. The stream also renews the session lease.                                                                                                                |
| `Release`         | Removes a claim. The generation must equal the current generation. An older generation gets `ABORTED`/`StaleGeneration` and a newer one `FAILED_PRECONDITION`/`GenerationConflict`; neither changes anything. A missing claim returns success, so a retried release is safe. A caller that does not own the attachment gets `PERMISSION_DENIED`. |

`Request`, `Update` and `Release` return once Worker has validated, authorized
and durably recorded the change. They do not wait for programming. The client
learns the outcome from `Observe`.

### Capabilities

`GetCapabilities` reports one row per capability: `local.tap`,
`local.veth_pair`, `local.routed_link`, `local.socket`, `fabric.srv6` and
`fabric.routes`. Each row is `Available` or `Unavailable` with a machine reason, for example
`DatapathNotLoaded`, `HookUnsupported` (an XDP mode or device the
[qualified platform](qualification.md) excludes), `RoutedLinkUnavailable`
(`local.routed_link` and `local.socket` on a Worker deployed without the
capabilities a pod end needs, see [operations](operations.md#install)) or
`ModuleNotRunning`. A claim
that needs an unavailable capability is accepted and reports `Programmed=False`
with the same reason, so a client can tell a temporary module outage from a
refused request.

A claim needs the Local capability of its handoff (`local.tap`,
`local.veth_pair`, `local.routed_link` or `local.socket`) for its Local
destinations, and `fabric.srv6` for its Fabric destinations. The caller must
be allowed the handoff's capability, and `fabric.srv6` when a destination is
on another node or resolves to Fabric at admission. Worker records the owner's
capabilities with each generation and does not program a destination that
later resolves to a mode they do not cover.

`fabric.routes` is not a delivery capability. It allows a caller to hand Worker
tenant routes through the Routes service ([tenant route handoff](#tenant-route-handoff)),
and only galactic-router is granted it (D24).

### Tenant route handoff

galactic-router keeps learning tenant routes from EVPN, and Worker's Fabric
module writes them (D24). The router hands each route to Worker through a
second service on the Worker socket, `galactic.worker.v1alpha1.Routes`, with
the same transport, identity and sessions as the Worker service (D8).

| RPC    | Semantics                                                                                                                                                                                                                                                               |
| ------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Sync` | Bidirectional stream. Each request carries upserts (VPC, the VPC's table, prefix, SID) and withdrawals (VPC, prefix). Worker records them and answers with the request's sequence and the routes it rejected with `MalformedRoute`. The open stream renews the session. |

A caller not allowed `fabric.routes` gets `PERMISSION_DENIED`/`CapabilityNotAllowed`,
and a Worker with no Fabric module `UNAVAILABLE`/`ModuleNotRunning`. Worker
keeps the routes in memory only: the router sends every route it holds and
every recent withdrawal each time it opens a stream, and each change after
that. Worker acknowledges a request once it has recorded it, before the entry
is removed, so the router keeps an acknowledged withdrawal for 10 minutes and
sends it again on each new stream. When a VRF is removed or moves to another
table, the router withdraws every route it handed Worker for the old table.
While Worker is unreachable the router keeps its changes and retries.

For every VPC scope Worker owns, the Fabric module writes the recorded routes
into `egress_route_table` inside the scope's commit, whether or not the scope
has claims:

- It writes a route only while the route's table is the VPC's current table,
  so a route never lands in another VPC's table, and never toward this node's
  own locator, which would loop.
- It re-resolves each route's underlay next hop when a route or neighbor
  event touches it, and rewrites the entry when the next hop moved.
- A route whose next hop stops resolving keeps the entry already written for
  it, so a shorter entry, such as the VPC's default toward an egress shard,
  never catches its traffic. A route that cannot be written yet, because it
  has no entry or its SID changed, is retried on the next event or resync;
  until then its traffic matches what it matched before, as when the router
  wrote it, and its destinations report why. Neither fails the commit, so
  other routes of the scope are written.
- It removes an entry only when the router withdraws its route, and never
  touches an entry the router did not hand it, such as CNI's pass-through
  entries, egress shard entries or Galactic Edge's entries.

In a VPC no Worker owns, the router writes its routes itself under the VPC's
fence with `Exclusive` (transfer step 1 in
[ownership](ownership.md#bootstrap-adoption-and-transfer)).

### Version negotiation

The client sends the range of API versions it supports. Worker picks the
highest version both support, or fails with `FAILED_PRECONDITION` and reason
`UnsupportedVersion`, listing the versions it serves. Within a version, fields
are added only, and clients ignore fields they do not know. A breaking change
is a new package (`v1alpha2`, `v1beta1`), served alongside the old one until
every client on the branch has moved to it (D7).

## State model

Worker keeps three states for each claim, and never reports one as another (D2).

| State      | What it holds                                                                                                       | Durable                                                             |
| ---------- | ------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------- |
| Desired    | The accepted generation and spec, and the owner.                                                                    | Yes, under `/var/lib/galactic-worker`                               |
| Programmed | What Worker wrote for each destination: mode, VRF table, SID, map rows, routes, and the read-back of each write.    | Rebuilt from the host after a restart                               |
| Observed   | Readiness evidence Worker did not write: the TAP or veth exists and is up, the neighbor resolves, CNI has attached. | Rebuilt from the host; link events in a VPC's VRF requeue its scope |

Each destination's status reports `forward_ready` and `return_ready`
separately, and `ready` only when both are true (D25). For a Fabric
destination, forward readiness means that the `egress_route_table` entry a
packet to each of the destination's addresses matches comes from a tenant route
toward the destination's own locator, and that the route's underlay next hop
resolves as written. Return readiness means this node decapsulates the VPC's
SID into the VPC's table: its locator is in `locator_table`, and its
BGPVRFInstance and `vrf_table` row for the VPC are in place. Each is judged per
destination, so a withdrawal or an unreachable node changes only the
destinations that use it.

Status carries `observed_generation` and these conditions, matching the
EdgeAttachment condition names where they mean the same thing:

| Condition     | True when                                                                                              |
| ------------- | ------------------------------------------------------------------------------------------------------ |
| `Admitted`    | The caller is authorized for the VPC, attachment and every destination.                                |
| `Resolved`    | Every destination resolved to Local or Fabric.                                                         |
| `Programmed`  | Programmed state matches desired state for `observed_generation`, confirmed by read-back.              |
| `Ready`       | `Programmed` is true and observed state shows every handoff can carry traffic.                         |
| `Withdrawing` | A release, revocation or lease expiry is removing programmed state. Status names the withdrawal scope. |

A claim's status also lists `handoff_interfaces`: each interface Worker
created for the claim's handoff, by role, name and ifindex
([the Local module](#the-local-module)).

The withdrawal scope names what stops: one destination, one claim, every claim
of a caller, or a whole VPC on the node. Operators read it, with every claim's
conditions and destinations, through `galactic-worker inspect`
([operations](operations.md#read-the-diagnostics)).

### Resolution

A destination whose locator is this node's locator resolves to Local; any other
locator resolves to Fabric (D11). A shard destination resolves by its node
instead (D32): its SID lives in the shard's own locator, which admission keeps
distinct from every BGPRouter's locator, so it is never the node's locator. A
shard whose EgressShard runs on this node resolves to Local, any other to
Fabric toward the shard SID's locator, and one that reports no SID or is not
Programmed and Ready reports `ShardNotReady`. Worker never falls back from Local to Fabric:
sending a Local destination out of the uplink would hairpin it and change the
return path the service depends on. A Local destination whose handoff is
missing waits, as the [worked transitions](#worked-transitions) show.

### Trusted sources

Worker takes these facts only from the sources below, never from the request (D10).

| Fact                     | Source                                                                                                                                                                                                                                                        |
| ------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Physical locator         | The node's BGPRouter Block and Node-ID, the same source `internal/installer/locatorroute.go` uses for the locator's local route.                                                                                                                              |
| VPC identity             | NetworkFabricIdentity for the VPC (`api/cloud/v1alpha1`), written by the fabric identity allocator.                                                                                                                                                           |
| Authorized VPC           | `VPCAttachment.spec.vpc` for workload and service attachments, written by NSO; for a connector, an EdgeAttachment that is `Admitted`.                                                                                                                         |
| Owner                    | The authenticated caller (D8), recorded with the claim's desired state.                                                                                                                                                                                       |
| Backend SID              | The backend node's locator plus the slot the gateway encodes in the uSID, as `docs/gateway/architecture.md` describes.                                                                                                                                        |
| Shard identity           | The EgressShard, in Worker's namespace: its node from `spec.targetRef`, its SID from `status.shardSID`, and readiness from its Programmed and Ready conditions, which galactic-nat writes for the identity its datapath translates with (D32).                |
| Shard claim authority    | For a claim whose attachment is an EgressShard: the allowlist's `egressShardClaims`, the EgressShard's node, and an admitted VPCAttachment of the VPC on this node (D30).                                                                                     |
| Tenant SID               | This node's source SID (`node_src_addr_table`) completed with the VPC's Argument (`ifindex_vrf_table` of one of its tenant interfaces), both pinned by galactic-cni.                                                                                          |
| Interface traffic policy | TrafficPolicyBinding, resolved by the cell controller. Worker applies no policy of its own.                                                                                                                                                                   |
| Destination addresses    | `VPCAttachment.spec.interface.addresses` (D26). An attachment whose guest manages its own addressing records none, and its destination reports `DestinationAddressUnknown`; taking those addresses from the attachment's advertised routes is follow-up work. |
| Tenant routes            | galactic-router, from EVPN, through the [tenant route handoff](#tenant-route-handoff).                                                                                                                                                                        |

Worker compares a VPC as the base62 identifier the attachment's status records
(`VPCAttachment.status.vpc`, `EdgeAttachment.status.vpc`). That identifier is
the VPC's fabric identity as this cell received it, and a claim's `vpc` is the
same identifier. An attachment whose identifier is still empty authorizes
nothing.

A claim is cross-VPC when any destination belongs to a VPC other than the
claim's attachment VPC. Worker refuses it. Two VPCs may use the same addresses,
so Worker compares VPC identity, never addresses.

## Local handoffs

[#1444](https://github.com/datum-cloud/galactic/issues/1444) proved each Local
handoff on the [qualified platform](qualification.md), with prototypes placed by
today's loaders (D27). Each row below is the mechanism the Local module
([#1435](https://github.com/datum-cloud/galactic/issues/1435),
`internal/worker/local`) programs, and each requirement is part of that
handoff's `Ready`. The scripts, captures and results are in
[the lab's handoff checks](../../deploy/containerlab/docs/handoffs.md);
[the Local module](#the-local-module) describes the implementation.

| Capability                          | Mechanism                                                                                                                                                                                                                                                                                                              |
| ----------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `local.tap`                         | A dispatcher slot on the receiving interface returns `XDP_PASS` with metadata naming the TAP. A tc ingress program on the same interface decides the TAP's ingress policy, marks the packet decided and delivers with `bpf_redirect_neigh`. The reply leaves from the TAP's tc ingress.                                |
| `local.veth_pair`                   | A tc program on the tenant TAP or veth redirects into the pair's tenant end. XDP on the NAT end runs the shard. The return is redirected into the NAT end and received by tc on the tenant end, which decides policy and delivers.                                                                                     |
| `local.routed_link`, `local.socket` | A veth from a VRF in the pod to the tenant VRF on the host. Its pod end uses the claim attachment's addresses (D26), each routed as a `/128` to the host end in the tenant VRF (D29). A socket bound to the pod's VRF (`SO_BINDTODEVICE`) sends and receives through it with no redirect; the kernel routes both ways. |

These amend the mechanisms the qualification plan first named:

- **The NAT end of a veth pair runs native XDP, whatever mode the host
  selects.** Generic XDP skips every packet a tc program redirected (the
  kernel's `skb_is_redirected` check in the generic receive path), so on a host
  that selects generic mode, as one with a `bnxt_en` NIC does, XDP on the peer
  never sees the tenant's traffic. A veth supports native XDP on every kernel the
  platform allows, so the peer is attached native while the uplinks follow
  `xdpmode.Select`.
- **A native `XDP_REDIRECT` from the peer to a VLAN device is unsupported**: a
  VLAN device has no XDP transmit. Where the egress is a VLAN, the peer pushes
  the 802.1Q tag itself and redirects to the VLAN's lower device. Returning
  `XDP_PASS` so the kernel forwards is not an alternative: the return comes
  back through the dispatcher's `XDP_REDIRECT`, past netfilter, so conntrack
  sees the flow's later packets as invalid and the node drops them, which
  stops TCP after the handshake.
- **Native XDP does not attach to a VLAN device.** A `local.tap` receiving
  interface that is a VLAN takes its native dispatcher on the VLAN's lower
  device and its tc program on the VLAN device; the metadata survives the
  kernel's untag. With VLAN receive offload, as on veth and most NICs, XDP on
  the lower device sees the frame untagged and cannot tell VLANs apart, so the
  slot program selects by destination, never by VLAN.
- **Each handoff decides the receiver's policy on its own path and marks the
  packet.** `tp_deliver` decides every unmarked packet on the Private path. A
  public client delivered to a TAP is PublicService and a NAT return is
  PublicNAT, so the handoff's tc program calls the datapath's policy decision
  with that path and sets the decided mark, as `usid_ingress` does for gateway
  deliveries. Left to `tp_deliver`, a public client is denied by any policy that
  grants PublicService and not Private.
- **A Local destination needs a pass-through entry in `egress_route_table`.**
  Without one, `usid_egress` sends a tenant's packet for a Local peer (a public
  client, the shard address's client, the routed link) to the VPC's `::/0` NAT
  route, encapsulated. Worker writes the pass-through under its own owner. The
  egress decision `usid_egress` then makes is on the Private path, so while
  the Local branch stays out of `usid_egress`, a tenant's Private egress grant
  also governs its Local flows, and the handoff's own program decides again
  on the right path. [#1435](https://github.com/datum-cloud/galactic/issues/1435)
  keeps the branch out (D28): the Local module writes the entries for the
  prefixes its own handoffs serve, a routed link's addresses
  (`PassThroughLocal`), and the resolver that selects a handoff writes the
  entries that steer a tenant's public flows into it (D29).
- **No other tc owner may claim a tenant TAP.** A node's other datapath,
  Cilium in particular, must never attach to a tenant interface. Deployed
  configurations meet this by pinning Cilium's `devices` to the node's uplink
  bonds and primary Ethernet interfaces, and the lab now does the same
  (`deploy/containerlab/scripts/deploy-cni.sh`). When the rule is broken, as in
  the lab before that pin, Cilium with kube-proxy replacement auto-detects any
  interface with a global address. A host TAP has one, the guest's gateway, so
  Cilium adopts it, registers that tenant address as a node address and
  attaches its programs with tcx, which deletes every legacy tc filter on the
  TAP: the egress chain, `tp_deliver` and any Local program. The TAP then
  forwards without its traffic policy; the #1444 runs recorded a public client
  reaching a guest whose policy denies it. Worker checks the TAP's chain as
  observed state and reports `HandoffInterfaceMissing` until it is present.
  Veths are not affected: Cilium excludes them.
- **A handoff program on a tenant interface runs after galactic-cni's own.**
  Its filters take the lowest tc priorities on the interface's ingress, so a
  separate Local filter sits at the next priority and sees only what
  `usid_egress` passed on. #1435 keeps that order (D28).

Each handoff places requirements on its interfaces:

| Handoff             | Requirement                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `local.tap`         | The TAP has carrier only while its reader (the hypervisor) holds it; Worker reports `HandoffInterfaceMissing` until then. `bpf_redirect_neigh` does not check the TAP's MTU: the lab delivered 8049-byte packets into a TAP at MTU 1500, and its guest took them. A real guest drops frames above its own MTU, with no ICMPv6 Packet Too Big to the sender, so the TAP's MTU is at least the receiving path's. IPv6 fragments to a TAP guest were not delivered in either mode, so Local refuses them: `local_rx` drops and counts an IPv6 fragment (D28). `local_rx` also drops a packet larger than the TAP's MTU, and the destination reports `HandoffMTUTooSmall` while the TAP's MTU is below a receiving device's. |
| `local.veth_pair`   | The tenant end of the pair needs GRO (or an XDP program) for a native `XDP_REDIRECT` into the pair to be received. XDP rewrites checksums as complete, so a frame with an offloaded, partial checksum is corrupted; see the checksum row in the [qualification plan](qualification.md#handoffs). Local runs an XDP program that passes everything on the tenant end, which turns on the NAPI a native `XDP_REDIRECT` into the pair needs on every kernel, as GRO does not. It turns transmit checksum offload off on the tenant end, so the kernel finishes a partial checksum, and segments a GSO packet, before the NAT end's program sees it.                                                                         |
| `local.routed_link` | The host end is a tenant interface the pod controls. It drops any source but the claim attachment's IPv6 addresses (at most four) and link-local ones, and each of those addresses has a route to the host end and a pass-through entry in the tenant VRF (D29).                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| `local.socket`      | The socket is bound to the pod's VRF. An unbound socket uses the pod's main table and reaches no tenant.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |

### The Local module

`internal/worker/local` is the Local module, registered with the Fabric module
in `cmd/galactic-worker`. Its tc programs are in
`internal/plumbing/ebpf/localprog` and include the uSID datapath, so every
policy decision runs `tp_capture` and `tp_decide` against the maps galactic-cni
pinned. Its own maps (`lt_*`) are pinned under `/sys/fs/bpf/galactic-local`
(`--local-pin-dir`), so a restarted Worker keeps the rows the running programs
read.

| Program            | Hook                                                                               | Does                                                                                                                                                                                                          |
| ------------------ | ---------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `local_rx`         | tc ingress of each public receiving device: its bond, or its VLANs when it has any | Delivers a packet whose metadata (`localprog/local_meta.h`) names a TAP a `local.tap` claim authorizes, on the PublicService path, and records the flow. A packet without the metadata goes on to the kernel. |
| `local_link_rx`    | tc ingress of each destination's tenant interface, after galactic-cni's filters    | Sends a recorded flow's reply out of the device the flow arrived on, on the PublicService path, and a flow whose destination has a `PassThroughLocalNAT` entry into the VPC's pair, on the PublicNAT path.    |
| `local_pair_rx`    | tc ingress of a pair's tenant end                                                  | Delivers the NAT end's return to the destination address it names in the pair's VPC, on the PublicNAT path.                                                                                                   |
| `local_link_guard` | tc ingress of a routed link's host end                                             | Drops any source the link was not given.                                                                                                                                                                      |
| `local_pair_napi`  | XDP, native, of a pair's tenant end                                                | Passes everything, so the tenant end receives what the NAT end's return redirects into the pair.                                                                                                              |

The module keeps link lifecycle apart from program ownership. CNI creates and
deletes tenant TAPs and veths; the module attaches only its own filters and
rows to them, keyed by their current ifindex, and reprograms them when CNI
replaces an interface. The module creates the service-internal veth pair of a
`veth_pair` claim and the routed link of a `routed_link` or `socket` claim,
names them `G<VPC><key><role>` with the alias
`galactic-local:<VPC>/<attachment>`, and deletes them when the claim goes. It
creates a routed link's pod end only in the pod Worker authenticated the
claim's owner from: it finds a process of that pod through its cgroup, as the
API's peer check does (D21), and refuses a pod on the host's network. A
routed link serves one pod, so each pod's link needs its own claim and
attachment. A call on the claim from another pod of its owner is refused
with `FAILED_PRECONDITION`/`ClaimHeldByAnotherPod` while the pod the link
serves runs; once that pod is gone, the call moves the link to the calling
pod, as after a pod replacement. The host end stays down until its guard is
attached, and goes down again whenever the guard is missing.

A destination is programmed when the module's rows and filters are in place,
confirmed by read-back. It is ready when, in addition:

- its tenant interface is in the VPC's VRF, has carrier and carries
  galactic-cni's chain (`HandoffInterfaceMissing` otherwise);
- the module's filters are current (`HandoffHookMissing`);
- for `local.tap`, a receiving device's dispatcher runs a live public slot
  (`DispatcherSlotUnclaimed`) and the TAP's MTU covers the device's
  (`HandoffMTUTooSmall`);
- for `local.veth_pair`, the client's program runs native on the NAT end
  (`HandoffHookMissing`, or `HookUnsupported` in generic mode), and the pair
  has carrier;
- for `local.routed_link`, the link reaches the owner's current pod and has
  carrier, which it has once the pod brings its end up;
- the destination's neighbor has not failed (`NeighborUnresolved`). A neighbor
  not yet resolved is no failure: `bpf_redirect_neigh` resolves it.

Forward readiness covers the path from the handoff to the destination and
return readiness the path back, so a missing hook withdraws only the direction
it carries.

Public ingress cannot assert tenant context. Only an XDP program can write
skb metadata, so a packet from the wire carries none, and `local_rx` delivers
only to a TAP Local authorized and drops a packet that names any other. The
programs a receiving device's dispatcher runs are trusted to name the right
one of those TAPs: a slot's holder, such as the gateway, chooses the TAP, and
Worker checks only that a claim authorizes it. `local_rx` drops an IPv6
fragment, also one behind hop-by-hop, routing or destination options
headers, and each Local redirect drops a packet its egress's MTU does not
cover. Every
Local program that delivers decides the receiver's policy on its own path and
sets the decided mark itself, and the pair delivers only to the destination
addresses a claim names. Every uplink discovery path skips a link Galactic
creates per VPC, including the NAT end of a pair, which lives in the host's
namespace outside any VRF (`attach.IsInternalLink`).

A tenant's public flows enter a pair through `egress_route_table` or through
`usid_egress`'s choice of a Local shard; [Local NAT shards](#local-nat-shards)
describes both. A `local.tap` reply reaches `local_link_rx` only when its
destination has a pass-through entry, so replies to clients anywhere need
either a default pass-through or a Local branch in `usid_egress`, which
[#1438](https://github.com/datum-cloud/galactic/issues/1438) decides (D29).

The client learns the interfaces the module created from the claim's
`handoff_interfaces`: the NAT end it attaches its native XDP program to, and
the routed link's pod end it configures.

`local_rx` records each flow it delivers in a 65536-entry LRU table, which the
flow's replies use. A sender that opens more flows than that through the
receiving devices evicts older ones, whose replies then go to the kernel
instead of the device they arrived on. `local_rx` stays on the receiving
devices while any TAP is authorized, so a restarted Worker does not take it
away before it has planned every scope.

### Local NAT shards

[#1437](https://github.com/datum-cloud/galactic/issues/1437) lets a VPC's
tenants egress through the NAT shard on their own node, through the VPC's
`veth_pair`, instead of crossing the underlay to a remote shard.

galactic-nat makes one `veth_pair` claim per VPC with an admitted
VPCAttachment on its node, naming its own EgressShard as both the attachment
and the destination (D30). The shard destination resolves to Local and
carries the VPC's attachments on this node: the Local module steers their
flows into the claim's pair and authorizes the pair's return to their
addresses. The NAT end reports `tenant_sid`, the SID that names the VPC on
this node. galactic-nat attaches its program natively to the NAT end, outside
the XDP dispatcher, whose single host mode may be generic, and keys the VPC's
sessions by that SID, exactly as it keys a remote tenant's by the outer source.
One session table serves both entries, and a reply whose saved SID has a pair
returns into it, unencapsulated; any other is encapsulated as before.

The Local module writes the VPC's `egress_local_shard` row, keyed by its VRF
table, only while the pair has carrier, runs Local's return programs, and runs
the shard's program natively on the NAT end; the destination reports
`LocalShardIneligible` until then. The row gates both egress modes:

- **Hashed (D33, amending D28).** Each shard group carries a second snapshot,
  `egress_shard_local_groups`, in which a ready local shard is alive. Only for
  a VPC with a row does `usid_egress` choose from it, and when it picks the
  local member it hands the packet, unencapsulated, to `local_link_rx` through
  `skb->cb`, which sends it into the pair on the PublicNAT path. A VPC with no
  row chooses from the unchanged snapshot, exactly as before.
- **Ordered.** galactic-cni's egress sweep writes a `PassThroughLocalNAT`
  class route in a VPC with a row when the row's shard comes first among the
  usable shards of its static list, and restores the shard's SID entry once
  the row goes. The sweep reads the rows every second, so either change takes
  about a second. CNI ADD still points a new VRF's class route at the first
  shard that resolves, and the sweep then moves it.

In either mode `local_link_rx` leaves Neighbor Discovery, and anything to a
link-local or multicast address, to the host, as `usid_egress` does: a class
route such as ordered mode's `::/0` must not take a guest's solicitation for
its gateway into the pair.

Drain, pins and NAT64 standby keep their rules: a draining local shard keeps
its pins and takes no new tenants, and a local NAT64 standby is held while a
primary is alive. A pin to the local shard holds only while the VPC keeps its
row.

Which established sessions survive:

| Event                               | Sessions through the local shard                                                                                                                                                                                     | Other sessions        |
| ----------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------- |
| The pair is recreated               | Survive when no packet of the tenant address crossed while the row was gone: the session key is the tenant SID, not the ifindex. A packet in that gap re-pins the address to a remote shard, which breaks its flows. | Unaffected            |
| NAT's program leaves one VPC's pair | That VPC's are lost: its row goes, its tenants move to the remote shards, which translate them with another address.                                                                                                 | Unaffected, every VPC |
| galactic-nat restarts               | Survive: the session table, the pair rows and the program's link (`/sys/fs/bpf/galactic-nat/links/`) are pinned, so the datapath keeps running.                                                                      | Survive               |
| Worker restarts                     | Survive: rows and programs stay while Worker rebuilds its state.                                                                                                                                                     | Survive               |
| The local shard drains              | Survive on their pins; new tenant addresses go to other shards.                                                                                                                                                      | Unaffected            |
| The local shard stops being ready   | Lost: the shard leaves the groups, as a remote shard does.                                                                                                                                                           | Unaffected            |

## Errors and retry

| gRPC code             | Reasons                                                                                             | Client action                                               |
| --------------------- | --------------------------------------------------------------------------------------------------- | ----------------------------------------------------------- |
| `INVALID_ARGUMENT`    | `MalformedSpec`, `WrongNode`                                                                        | Fix the request. Do not retry.                              |
| `UNAUTHENTICATED`     | `NoIdentity`, `IdentityExpired`                                                                     | Refresh the credential, then retry.                         |
| `PERMISSION_DENIED`   | `VPCNotAuthorized`, `AttachmentClaimedByAnotherCaller`, `NotOwner`, `CapabilityNotAllowed`          | Do not retry until authority changes.                       |
| `FAILED_PRECONDITION` | `UnsupportedVersion`, `ClaimExists`, `ClaimNotFound`, `GenerationConflict`, `ClaimHeldByAnotherPod` | Re-read with `Observe`, then use the right operation.       |
| `FAILED_PRECONDITION` | `NoSession`                                                                                         | Call `GetCapabilities` for a new session, then retry.       |
| `ABORTED`             | `StaleGeneration`                                                                                   | Re-read with `Observe`; retry only with a newer generation. |
| `UNAVAILABLE`         | `Resyncing`, `ShuttingDown`                                                                         | Retry with backoff.                                         |
| `RESOURCE_EXHAUSTED`  | `ClaimLimit`, `TableRangeExhausted`                                                                 | Retry with backoff; report if it persists.                  |

`Update` of a claim that does not exist, or is being withdrawn, gets
`ClaimNotFound`.

Status carries these reasons besides the ones above:

| Reason                                             | Where                 | Meaning                                                                                                   |
| -------------------------------------------------- | --------------------- | --------------------------------------------------------------------------------------------------------- |
| `Pending`                                          | Any condition         | Worker has not yet reconciled the generation                                                              |
| `DestinationKindUnsupported`                       | `Resolved`            | A backend destination, until #1438 resolves it                                                            |
| `ShardNotReady`                                    | `Resolved`            | The shard's EgressShard reports no SID, or is not Programmed and Ready                                    |
| `LocalShardIneligible`                             | `Ready`               | The VPC's tenants do not take the Local shard yet; they keep the remote shards                            |
| `DestinationNotFound`                              | `Resolved`            | The destination attachment no longer exists                                                               |
| `LocatorUnknown`                                   | `Resolved`            | This node or the destination's node has no SRv6 locator yet                                               |
| `ModeUnavailable`                                  | `Resolved`            | The destination resolves to a mode the preference excludes                                                |
| `ModuleNotRunning` and other capability reasons    | `Programmed`          | The capability the destination needs is unavailable                                                       |
| `CapabilityNotAllowed`                             | `Programmed`          | The destination resolved to a mode the owner was not allowed at admission, so it stays unprogrammed       |
| `ProgrammingFailed`                                | `Programmed`          | The last commit failed; the message carries the error                                                     |
| `ScopeOwnedElsewhere`                              | `Programmed`          | Another writer owns the VPC scope's fence (see [ownership](ownership.md#bootstrap-adoption-and-transfer)) |
| `Released`, `LeaseExpired`, `AuthorizationRevoked` | `Withdrawing`         | Why the claim is being withdrawn                                                                          |
| `DestinationAddressUnknown`                        | `Programmed`          | The Fabric destination's attachment records no address                                                    |
| `ForwardRouteMissing`                              | `Programmed`          | No tenant route covers one of the destination's addresses                                                 |
| `RouteWithdrawn`                                   | `Programmed`          | The tenant route covering one of the destination's addresses was withdrawn                                |
| `RouteMismatch`                                    | `Programmed`          | The route covering one of the destination's addresses leads to another node's locator                     |
| `UnderlayUnreachable`                              | `Programmed`, `Ready` | No route over an SRv6 uplink reaches the destination's locator; the entry is kept                         |
| `NeighborUnresolved`                               | `Programmed`, `Ready` | The underlay next hop, or a Local destination's guest, has no resolved neighbor, or the entry's is stale  |
| `HandoffInterfaceMissing`                          | `Programmed`, `Ready` | A Local destination's interface or handoff link is missing, has no carrier or lacks galactic-cni's chain  |
| `HandoffHookMissing`                               | `Ready`               | A Local handoff program is off its hook: Local's own filter, or the client's program on a pair's NAT end  |
| `DispatcherSlotUnclaimed`                          | `Ready`               | No receiving device's XDP dispatcher runs a live public slot for a `local.tap` destination                |
| `HandoffMTUTooSmall`                               | `Ready`               | A Local destination's MTU is below its receiving path's                                                   |
| `HookUnsupported`                                  | `Ready`               | A hook runs in a mode the handoff cannot use, such as the NAT end's program in generic mode               |
| `RoutedLinkUnavailable`                            | `Programmed`          | Worker lacks the capabilities a routed link or socket pod end needs; see operations                       |
| `ReturnPathNotProgrammed`                          | `Ready`               | This node does not yet decapsulate the VPC's SID into the VPC's table                                     |
| `HandoffInterfaceNotOwned`                         | `Programmed`          | A connector claim's link carries another attachment's stamp, or its gate names another address            |

Clients retry with exponential backoff from 200 ms to 30 s with full jitter.
Every mutating call is idempotent for a given generation, so a retry after a
lost response is safe (D3). Every refusal carries a gRPC code and a machine
reason from this table (D6). Worker retries its own programming from 1 s to
60 s and reports the last error as the reason on `Programmed=False`.

## Sessions, restart and stale deletion

Every call after `GetCapabilities` carries the session ID in the
`x-galactic-worker-session` metadata key. A call without a live session of the
caller gets `FAILED_PRECONDITION`/`NoSession`. A `GetCapabilities` that carries
a live session ID renews that session instead of starting another (D19).

A session starts with `GetCapabilities` and carries a lease of 120 s, renewed by
an open `Observe` stream or a call at least every 10 s. These are the XDP
dispatcher's slot lease values (`internal/plumbing/ebpf/xdpdispatch`), already
qualified for detecting a dead service agent (D5).

- **Client restart.** The client opens a new session and repeats `Request` for
  each claim with its last generation. Worker answers each as a duplicate. The
  owner is the caller identity, not the session, so a restart within the lease
  changes no host state.
- **Lease expiry.** When a caller has no live session for 120 s, Worker marks
  its claims `Withdrawing` with scope "every claim of the caller" and removes
  their programmed state. Desired state is deleted once the read-back confirms
  removal.
- **Authority revoked.** When the VPCAttachment is deleted or an EdgeAttachment
  loses `Admitted`, Worker sets `Admitted=False` with reason
  `AuthorizationRevoked` and withdraws the claim the same way. For a
  connector claim this is the second cut: galactic-edge's forwarding gate
  already bounds delivery after a revocation, as the
  [provider contract](../edge/provider-contract.md#bounds) states
  ([connector](connector.md#authority)).
- **Worker restart.** Worker reads desired state from disk, then takes each
  scope over and reconciles a full snapshot, as [ownership](ownership.md#bootstrap-adoption-and-transfer)
  describes. Programmed and observed state are rebuilt by reading the host.
  Forwarding continues while Worker is down, because the datapath does not call
  Worker.

## Transport, identity and access

D8 and D9 were confirmed on 2026-11-18.

- **Transport (D8).** gRPC over a unix socket at
  `/run/galactic-worker/worker.sock`, mode `0660`, owned by a dedicated group
  (GID 65441 in `config/galactic-worker`, Worker's own group there; with
  `--socket-group` Worker changes the socket's group instead, which needs
  `CAP_CHOWN`).
  No TCP listener serves the mutating API.
- **Client identity (D8).** Each call carries a projected ServiceAccount token
  with audience `galactic-worker`, bound to the calling pod, as
  `authorization: Bearer <token>`. Worker validates it with TokenReview, caches
  the result until the token expires, and checks that the bound pod runs on
  this node. Worker also reads the peer's credentials (`SO_PEERCRED`) and
  refuses a peer that is not a process of that pod. It maps the peer PID to a
  pod through the pod UID in `/proc/<pid>/cgroup`, so Worker runs in the host
  PID namespace and reads the host's `/proc`; in any other PID namespace the
  kernel reports PID 0 for a peer in another pod (D21).
  `config/galactic-worker` runs Worker with `hostPID`, so its `/proc` is the
  host's.
- **Allowlist (D8, D22).** A static YAML file, passed with `--allowlist`, maps
  each ServiceAccount to the capabilities it may use. A ServiceAccount it does
  not list may use none.

  ```yaml
  serviceAccounts:
    - serviceAccount: galactic-system/galactic-nat
      capabilities: [local.veth_pair, fabric.srv6]
      egressShardClaims: true
    - serviceAccount: galactic-system/galactic-router
      capabilities: [fabric.routes]
    - serviceAccount: galactic-system/galactic-edge
      capabilities: [local.routed_link]
  ```

- **Access model (D9).** Host-network agents (NAT, Gateway, galactic-edge) mount
  `/run/galactic-worker` with a `hostPath` volume. The galactic-vrf sidecar runs
  in the Envoy pod's network namespace and mounts the same directory; pod
  security admission limits that `hostPath` to the sidecar's ServiceAccount.

## Worked transitions

Each case names the decision it exercises and the Task that owns its test.

| Case                             | Start                                                                                                                          | Event                                                                                                              | Worker action                                                                                                                                                                                                                                                                                 | Result                                                                                                                                                                                                         | Decision     | Test owner                                                                                                                                                                                              |
| -------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Duplicate request                | Claim at generation 4, `Ready=True`.                                                                                           | The client's response was lost, so it sends `Request` again with generation 4 and the same spec.                   | Compares generation and spec hash with desired state. Takes no ticket and writes nothing.                                                                                                                                                                                                     | `OK` with the current status. Host state is byte-for-byte unchanged. The same generation with a different spec gets `FAILED_PRECONDITION`/`GenerationConflict`.                                                | D1, D3       | [#1433](https://github.com/datum-cloud/galactic/issues/1433) unit test: duplicate and out-of-order requests                                                                                             |
| Stale release                    | Claim updated from generation 4 to 5, programming in progress.                                                                 | A delayed `Release` with generation 4 arrives.                                                                     | Compares the generation with desired state and refuses before taking a ticket.                                                                                                                                                                                                                | `ABORTED`/`StaleGeneration`, carrying current generation 5. The claim and host state are unchanged, and programming of generation 5 continues.                                                                 | D3, D4       | [#1433](https://github.com/datum-cloud/galactic/issues/1433) unit test: release from a stale generation and from a non-owner                                                                            |
| Unauthorized cross-VPC claim     | The caller has a claim on an attachment in VPC A. VPC B uses the same guest addresses.                                         | `Update` adds a destination whose attachment is in VPC B.                                                          | Resolves the destination's VPC from its attachment record and its identity from NetworkFabricIdentity, finds B ≠ A, and refuses. Records nothing durable, takes no ticket, logs the refusal and counts it in a metric.                                                                        | `PERMISSION_DENIED`/`VPCNotAuthorized`. The existing generation keeps running. Routes, rules, links and pinned maps are unchanged.                                                                             | D1, D10      | [#1433](https://github.com/datum-cloud/galactic/issues/1433) zero-mutation snapshot test; [#1442](https://github.com/datum-cloud/galactic/issues/1442) observes the unauthorized destination in the lab |
| Local locator with a missing TAP | Claim admitted; one destination is a guest on this node.                                                                       | Resolution finds the node's own locator, but the guest's TAP does not exist (not yet attached, or being replaced). | Resolves the destination to Local and does not fall back to Fabric. Programs the other destinations. Leaves the missing one unprogrammed and watches CNI attachment events. When CNI ADD creates the TAP, programs it on the new ifindex and reads it back.                                   | Until the TAP appears: `Resolved=True`, `Programmed=False` and `Ready=False`, with reason `HandoffInterfaceMissing` naming the destination. Afterwards: `Ready=True`.                                          | D2, D11      | [#1435](https://github.com/datum-cloud/galactic/issues/1435) root test for Local programming; [#1434](https://github.com/datum-cloud/galactic/issues/1434) for CNI attachment observation               |
| Withdrawal during repair         | A commit failed part-way, so the VPC scope is resync-required and Worker's repair holds a ticket while it prepares a snapshot. | The owner sends `Release` with the current generation.                                                             | Records the release durably and answers. Takes the scope over again with `Takeover`, which invalidates the repair's ticket, and commits a snapshot computed from desired state without the released claim. The repair's late commit fails with a transitioning or stale error and is dropped. | `Release` returns `OK`. Status shows `Withdrawing` with scope "one claim" until the read-back confirms removal, then `Observe` reports the claim released. No row of the released claim survives the snapshot. | D3, D12, D23 | [#1433](https://github.com/datum-cloud/galactic/issues/1433) crash and interleaving tests; [#1436](https://github.com/datum-cloud/galactic/issues/1436) for Fabric rows                                 |
| Underlay next hop lost           | Claim `Ready=True` with Fabric destinations on nodes B and C.                                                                  | The underlay route toward node C's locator is withdrawn.                                                           | The route event requeues only the VPCs with a route toward that locator. The Fabric module keeps the entries toward node C and rewrites nothing. When the route returns, it rewrites each entry whose next hop moved.                                                                         | Meanwhile the destination on node C reports `forward_ready=False` with reason `UnderlayUnreachable`, and the one on node B stays `Ready`. Afterwards both are `Ready`.                                         | D11, D25     | [#1436](https://github.com/datum-cloud/galactic/issues/1436) root test for the Fabric datapath and lab captures                                                                                         |
