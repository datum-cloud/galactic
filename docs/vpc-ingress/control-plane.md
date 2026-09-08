# VPC Ingress — Control Plane

> Last verified: 2026-09-06 against `main` (`galactic` up to date with
> `origin/main` at audit time) and `go.datum.net/network
> v0.0.0-20260825185725-392ac243999b` (`go.mod:20`).

This document is for developers who need to know **which custom resources
exist, which reconcilers act on them, exactly what each one watches, and
what ultimately writes the kernel/eBPF state** the VPC ingress dataplane
reads. It is configuration-only. The packet paths themselves —
what a request looks like on the wire once this state exists — are sibling
documents: `docs/vpc-ingress/request-path.md` and
`docs/vpc-ingress/response-path.md`.

## Scope: two mechanisms, one document

Two independent, code-separate mechanisms in this repo both configure
"ingress" for a VPC-hosted workload, and both are driven by the same BGP CRD
API (`go.datum.net/network/api/v1alpha1`). Confusing them is the single
easiest mistake a new reader makes, so this section draws the line up
front:

| | L4 anycast DSR/Maglev gateway | HTTP ingress via the shared Envoy Gateway fleet |
|---|---|---|
| CRDs | `NetworkGateway`, `NetworkRule`, `ServiceVIPBinding` | `BGPVRFInstance` + `BGPAdvertisement` only (no dedicated CRD) |
| Binary | `galactic-gateway`, on dedicated `galactic.datumapis.com/node=edge` nodes | `cmd/galactic-vrf` (`internal/ingresssidecar`), a second container in every Envoy Gateway pod |
| Mechanism | Consistent-hash (Maglev) backend selection, SRv6 outer header pushed straight at the backend's worker node, no rewrite (DSR) | A per-tenant-VPC Linux VRF inside the Envoy pod's own netns, with an SRv6 egress route toward each backend Pod |
| Covered in depth by | [`docs/agents/ARCHITECTURE-GATEWAY.md`](../agents/ARCHITECTURE-GATEWAY.md) | This document (§3–§6) |

**Section 1** below documents the full CR surface, including the DSR
gateway's CRDs (`NetworkGateway`/`NetworkRule`/`ServiceVIPBinding` — "the
gateway-side ones"). **Section 2** documents the watch wiring for every
reconciler under `internal/controller/*.go`, which also means both
mechanisms. **Sections 3–6** — the CNI chain, the ingress sidecar, the node
agent, and the underlay — are specific to the Envoy-Gateway-fleet HTTP
ingress path, matching the sibling packet-path docs and the C4 diagrams
already checked into this directory (`context.puml`, `containers.puml`).

`internal/controller/nat66shard_controller.go` and `NAT66Shard` are a
third, unrelated mechanism (egress NAT66 shard placement for
compute-node egress, not ingress) and are out of scope here.

## 1. The custom resources

All types live in the external module `go.datum.net/network`
(`go.mod:20`), package `api/v1alpha1`. Field names below are as declared in
that module's source, at the pinned version.

### BGP CRDs (shared by both ingress mechanisms)

| CRD | Scope | Meaning on this path |
|---|---|---|
| `BGPRouter` | Namespaced, one per node (`spec.targetRef.name`) | The node's BGP identity: `spec.localASN`, `spec.routerID`, `spec.addressFamilies` (`router_types.go:41-80`). Two fields matter specifically to SRv6 ingress: `spec.srv6Locator` (an IPv6 `/48` uSID Block this node owns, `router_types.go:65`) and `spec.nodeID` (an 8-bit slot within that Block, `router_types.go:73`) — together they are the node's SRv6 identity, and every SID this node can ever originate or resolve is a host address inside `srv6Locator` with `nodeID` in bits 49–64. No `srv6Locator`/`nodeID` means this node cannot register eBPF uSID state at all (see §3). |
| `BGPPeer` | Namespaced, binds to one or more `BGPRouter` via `routerRef`/`routerSelector` | An iBGP/eBGP session (fabric underlay or route-reflector) this router holds. Not written by the ingress path itself — operator/route-reflector configured. |
| `BGPPolicy` | Namespaced, binds to `BGPRouter` | Import/export route-map terms. Not written by the ingress path; available for operators to shape what a router imports/exports. |
| `BGPAdvertisement` | Namespaced, targets one `BGPRouter` via `spec.routerRef` | A set of prefixes (`spec.prefixes`) originated from this router, with an SRv6 decap behavior attached when `spec.vrfID` + `spec.function` are both set (`advertisement_types.go:97,108,149,154`) — `function` is always `End.DT46` on this path. This is the CRD both the CNI chain (§3, one per pod's own address) and the ingress sidecar (§4, one for its own per-VPC "gateway" address) write. |
| `BGPVRFInstance` | Namespaced, targets one `BGPRouter` | An L2VPN EVPN VRF: `spec.vrfID` (the 16-bit uSID Argument / RFC 4364 RD low bits, `vrf_types.go:35`), `spec.importRouteTargets`/`spec.exportRouteTargets` (`vrf_types.go:42,49`), and optionally `spec.nptv6` for RFC 6296 prefix translation (`vrf_types.go:63`). Named `<vpc>-<node>` (`crdnames.BGPVRFInstanceName`, `internal/crdnames/crdnames.go:189`) — shared by every attachment of that VPC on that node, CNI-created or sidecar-created alike. |

### The DSR/Maglev gateway-side CRDs

These exist for the *other* ingress mechanism (the L4 anycast DSR/Maglev
gateway, "Scope" above) — included here for
completeness since `internal/controller/*.go` reconciles them too (§2), not
because §3–§6 use them.

| CRD | Meaning |
|---|---|
| `NetworkGateway` | Namespaced, one per gateway node (`spec.targetRef.name`, `gateway_types.go:43`). Marks a node as running the Maglev/DSR L4 engine; carries no address of its own (DSR rewrites nothing) — see the type's own doc comment for the Full-NAT design it replaced. |
| `NetworkRule` | Namespaced, tenant-writable. `spec.vpcRef`/`spec.vpcAttachmentRef` (opaque identifiers, `rule_types.go:94,101`), `spec.vipAddresses` (`rule_types.go:111`), `spec.protocol`/`spec.port`, `spec.backends` (`rule_types.go:128`). Every `NetworkGateway` node serves every accepted rule identically (anycast); there is no primary/secondary. |
| `ServiceVIPBinding` | Namespaced, one per (node, VIP, backend). `spec.targetRef` (node), `spec.vipAddress`/`spec.port` (`vipbinding_types.go:78,83`), `spec.egressKind` (`veth`/`tap`, `vipbinding_types.go:116`). Tells a worker node which local backend must answer directly on a VIP (the DSR "reply comes straight from the backend" half). **Verification note:** the type's doc comment states this is "written by ... `galactic-gateway`'s `usidresolver.go`", but as of this audit `usidresolver.go` only *resolves* backend SIDs (`internal/controller/usidresolver.go:71,117,130`) — nothing in this repo currently constructs a `ServiceVIPBindingSpec{}` or calls `CreateOrUpdate` against one (`grep -rn "ServiceVIPBindingSpec" internal/` matches only a doc comment in `internal/plumbing/ebpf/vipxlatmap/vipxlat.go:264`). `ServiceVIPBindingReconciler` (`internal/controller/servicevipbinding_controller.go`) only *consumes* the CRD once one exists. Treat the write side as **not yet implemented**, not merely undocumented. |

## 2. The reconcilers and their exact watches

Every entry below is read directly from each file's `SetupWithManager`, not
inferred. `Named(...)` and `.Complete(r)` are omitted from the "Watches"
column for brevity.

| Reconciler | File | `For` | `Watches` |
|---|---|---|---|
| `BGPRouterReconciler` | `internal/controller/bgprouter_controller.go:495-529` | `BGPRouter` | `BGPPeer` → owning router(s) (`peerToRouterRequests`); `BGPPolicy` → owning router(s) (`policyToRouterRequests`); `corev1.Secret` → routers whose peer references it (`secretToRouterRequests`); `BGPAdvertisement` → the single router named in `spec.routerRef.name` |
| `BGPVRFInstanceReconciler` | `internal/controller/bgpvrfinstance_controller.go:36-58` | `BGPVRFInstance` | `BGPVRFInstance` → the router named in its own `spec.routerRef.name` (self-watch, re-triggers on any sibling instance's change against the same router) |
| `BGPPeerReconciler` | `internal/controller/bgppeer_controller.go:31-36` | `BGPPeer` | *(none — `BGPRouterReconciler` is what actually watches `BGPPeer` and does the real work; this reconciler is a status-only watch source)* |
| `BGPPolicyReconciler` | `internal/controller/bgppolicy_controller.go:31-36` | `BGPPolicy` | *(none — same pattern as `BGPPeerReconciler`)* |
| `BGPAdvertisementReconciler` | `internal/controller/bgpadvertisement_controller.go:31-36` | `BGPAdvertisement` | *(none)* |
| `NodeReconciler` | `internal/controller/node_controller.go:35-45` | `corev1.Node` | `corev1.Node` → every `BGPRouter` whose `spec.targetRef.name` matches, via a field indexer (`nodeToRouterRequests`) |
| `SecretReconciler` | `internal/controller/secret_controller.go:34-39` | `corev1.Secret` | *(none — `secretToRouterRequests`, defined in this file, is called by `BGPRouterReconciler`'s own watch, above)* |
| `NetworkGatewayReconciler` | `internal/controller/networkgateway_controller.go:522-565` | `NetworkGateway` | `NetworkRule` → gateway(s) via `ruleToGatewayRequests`; `BGPRouter`, `BGPAdvertisement`, `BGPVRFInstance` → **broadcast to every `NetworkGateway` in the namespace** (`broadcastToGatewayRequests`) — added specifically to close a startup race where `buildBackendSIDIndex` resolves a rule's backend uSID from these three kinds but historically watched none of them (see the code comment at `networkgateway_controller.go:530-546`) |
| `NetworkRuleReconciler` | `internal/controller/networkrule_controller.go:243-253` | `NetworkRule` | `NetworkGateway` → **broadcast to every `NetworkRule` in the namespace** (`gatewayToRuleRequests`) — a `NetworkRule` carries no `gatewayRef`, so a gateway-node-pool change can affect any rule's `Accepted` condition |
| `NAT66ShardReconciler` | `internal/controller/nat66shard_controller.go:305-315` | `NAT66Shard` | `BGPRouter` → broadcast to every `NAT66Shard` in the namespace (`broadcastToShardRequests`) — *out of scope, egress not ingress (see §1)* |
| `ServiceVIPBindingReconciler` | `internal/controller/servicevipbinding_controller.go:521-526` | `ServiceVIPBinding` | *(none)* |
| `GCReconciler` | `internal/controller/gc_controller.go:59-64` | — | **No watches, no `For`, no `Owns` at all.** `SetupWithManager` only defaults `Interval` to 5 minutes if unset; it does not even register a controller against the manager. `Reconcile` is invoked directly by a hand-rolled `time.NewTicker(cfg.GCInterval)` goroutine started in `cmd/galactic-router/root.go:295-314`, after an initial `mgr.GetCache().WaitForCacheSync(ctx)`. `cfg.GCInterval` defaults to 5 minutes (`internal/config/router.go:27`, `DefaultRouterGCInterval`) and is overridden by `GALACTIC_ROUTER_GC_INTERVAL`. This is purely time-driven cleanup (orphaned `BGPAdvertisement`/`BGPVRFInstance` CRDs and orphaned kernel VRF interfaces, `internal/gc/gc.go`'s `RunGC`) — it never reacts to a CRD change. |

## 3. The CNI chain

The chain is invoked in CNI conflist order. On this path:

1. **`galactic-veth`** (or `galactic-tap` for VM workloads) — creates the
   VRF (`internal/plumbing/vrf.Add`), the veth/tap pair, and configures the
   host gateway. `internal/cni/ops_add.go:36-119` is `cmdAdd`.
2. **`galactic-ipam`** (optional, chain-invoked) — allocates the pod's
   address(es).
3. **`galactic-bgp`** (`internal/cnibgp`) — publishes everything BGP/SRv6
   needs. This is the component the rest of this section is about.

`galactic-bgp`'s `cmdAdd` calls `publishBGPState`
(`internal/cnibgp/bgp.go:414-562`), which:

1. Looks up the node's `BGPRouter` (`lookupBGPRouter`,
   `internal/cnibgp/bgp.go:246-277`) and reads `srv6Locator`/`nodeID` off it.
2. Allocates (or reuses) the `BGPVRFInstance`'s `spec.vrfID` — the uSID
   Argument — via `allocateArgument` (`bgp.go:194-220`), the lowest unused
   value in the router's Argument range, idempotent by CRD name.
3. Creates/updates the `BGPVRFInstance` (`buildVRFInstanceSpec`,
   `bgp.go:280-289`) and, once the SID is computed
   (`srv6.ComputeSID`, `bgp.go:483-489`), the `BGPAdvertisement`
   (`buildAdvertisementSpec`, `bgp.go:294-310`) carrying this attachment's
   pod subnet(s).
4. **Registers the eBPF uSID datapath** for this attachment
   (`registerEBPFDatapath`, `bgp.go:587-721`):
   - `registry.Locator.Register(block, nodeID)` → **`locator_table`**
     (`bgp.go:651`)
   - `registry.Function.Register(block, FunctionEndDT46)` → **`function_table`**
     (`bgp.go:654`)
   - `registry.VRF.Register(block, argument, vrfTableID, egressKind)` →
     **`vrf_table`** (`bgp.go:658`)
   - `ifindexTable.Register(hostIfindex, block, argument)` →
     **`ifindex_vrf_table`** (`bgp.go:667`)
   - Attaches `usid_egress` (loaded from its pin, `attach.UsidEgressPinName`)
     to this attachment's own host-side interface (`attachUsidEgress`,
     `bgp.go:799-807`).
5. Publishes a per-pod `discoveryv1.EndpointSlice`
   (`publishEndpointSlice`, `internal/cnibgp/endpointslice.go:34-`), labeled
   `galactic.datum.net/tenant-id` (`crdnames.LabelTenantID`,
   `internal/crdnames/crdnames.go:101`) — this is the ingress sidecar's
   (§4) only desired-state input.

### Which maps have no other writer, and which one self-heals

Grepping every call site of each table's `Register` method across the
non-test tree gives an exact writer list:

| Map | Writers | GC repair? |
|---|---|---|
| `locator_table` | `internal/cnibgp/bgp.go:651` (CNI ADD, one-shot); `internal/installer/sidecarreturn.go:195` (host-side sidecar return-path installer, §5, ticker-driven) | **No.** Nothing sweeps or repairs this table. |
| `function_table` | `internal/cnibgp/bgp.go:654`; `internal/installer/sidecarreturn.go:198` | **No.** |
| `vrf_table` | `internal/cnibgp/bgp.go:658`; `internal/installer/sidecarreturn.go:249`; `internal/ingresssidecar/ebpfdatapath.go:368` (the ingress sidecar's own controller-driven write, §4); **and** `internal/gc/gc.go:689` | **Yes** — the only one of the four. `gc.SweepEBPFVRFTable` (`internal/gc/gc.go:538-`) diffs the table against every live `BGPVRFInstance` CRD and re-`Register`s any key a live CRD expects but the table is missing (`gc.go:670-705`; the repair loop itself is `gc.go:670-705`, `result.EBPFVRFEntriesRegistered++` at the end). |
| `ifindex_vrf_table` | `internal/cnibgp/bgp.go:667`; `internal/ingresssidecar/ebpfdatapath.go:382` | **No.** `SweepEBPFVRFTable`'s own doc comment says so explicitly: "`ifindex_vrf_table` (which this sweep never touches)" (`internal/gc/gc.go`, comment above the `existingKeys` loop). |

Each of these three writer call sites (`internal/cnibgp/bgp.go`,
`internal/installer/sidecarreturn.go`, `internal/ingresssidecar/ebpfdatapath.go`)
is a **one-shot** registration — it runs once, at CNI ADD / at the node
agent's periodic sidecar-return reconcile tick / at the ingress sidecar's
own controller reconcile — and is never re-invoked for an attachment that
already succeeded. `vrf_table`'s GC sweep (the table just above) is the *only* mechanism
in this codebase that notices a missing entry after the fact and
re-populates it. `locator_table`, `function_table`, and
`ifindex_vrf_table` have no equivalent: if any of those three is emptied
out from under a live attachment (see §7's hazard), that attachment's
traffic stays broken until something re-runs its original one-shot writer
— for the CNI path, that means the pod itself has to be recreated.

## 4. The ingress sidecar

`internal/ingresssidecar` (binary: `cmd/galactic-vrf`, package doc at
`internal/ingresssidecar/doc.go:8-38`) is the second container in the
shared Envoy Gateway fleet's pod. Its **only** desired-state source is a
cluster-scoped watch on `discoveryv1.EndpointSlice` objects, selected by
`crdnames.LabelTenantID` presence:

```go
// internal/ingresssidecar/controller.go:66-72
func (r *Reconciler) SetupWithManager(mgr ctrl.Manager) error {
    r.Client = mgr.GetClient()
    return ctrl.NewControllerManagedBy(mgr).
        For(&discoveryv1.EndpointSlice{}, builder.WithPredicates(predicate.NewPredicateFuncs(hasTenantLabel))).
        Complete(r)
}
```

This is cluster-scoped (not namespace-scoped) because `EndpointSlice`
objects land in each pod's own namespace (`controller.go:63-65`).

### Two reconcile granularities

Per `internal/ingresssidecar/doc.go:29-38`, the same `EndpointSlice` watch
drives two different kernel resources at two different granularities:

- **VRF device: one per VPC.** Shared by every attachment of that VPC
  present on this node — matching the kernel VRF's identity everywhere
  else in this codebase (`internal/plumbing/vrf`).
- **SRv6 egress route: one per pod (per `EndpointSlice`).** Pods of the
  same tenant on different nodes carry different SIDs (a pod's SID
  depends on its *own* hosting node's `nodeID`), so there is no
  tenant-aggregate route to install — only a per-pod one.

### `PublishGateway`

`GatewayPublisher.PublishGateway` (`internal/ingresssidecar/gateway.go:120-129`)
advertises the sidecar's own local address inside a managed VPC — the
source address Envoy's outbound connections into that VPC use — so a
backend Pod's reply has an SRv6 route back to it. Its production
implementation, `k8sGatewayPublisher.PublishGateway`
(`internal/ingresssidecar/gateway.go:263-`):

1. Looks up the node's `BGPRouter` the same way `internal/cnibgp` does
   (`lookupBGPRouter`, `gateway.go:163-183`).
2. Reuses or creates the same `(vpc, node)`-keyed `BGPVRFInstance` a real
   CNI attachment on this node would use
   (`crdnames.BGPVRFInstanceName`) — a shared VRF, not a competing one.
3. Reads this pod's own host-side ifindex and MAC via a read-only netlink
   call in its own netns (`podEntryPoint`, `gateway.go:242-255`) — the two
   facts the host side of the return path (§5) needs and cannot read for
   itself without `CAP_SYS_ADMIN`.
4. Creates a `BGPAdvertisement` for the gateway address (`/128`, `End.DT46`),
   annotated with `crdnames.AnnotationIngressHostIfindex` /
   `AnnotationIngressHostMAC` so the node agent (§5) can complete the
   return path.

`GatewayAddressResolver` (`gateway.go:56-104`) is explicitly documented as
**discovery-only**: it looks for an already-provisioned global-scope IPv6
address on an interface enslaved to the VPC's VRF device, but provisioning
that address in the first place — a veth-style attachment into the VPC with
its own IPAM allocation — is called out as "a real, unimplemented gap" in
the doc comment (`gateway.go:60-64`, citing
`docs/plans/855-return-path-gateway-advertisement.md`'s "Not implemented
here" section). Treat this as **not yet implemented**, matching that plan's
own status.

### Correction: the sidecar's own egress is TC-BPF, not a kernel `seg6` route

`internal/ingresssidecar`'s own package doc comment
(`doc.go:7`, "Linux VRF device + SRv6 `seg6` encap route lifecycle") and the
`Backend` interface's doc comments (`backend.go:34-35`, "the `seg6`
`ENCAP_RED` route"; `backend.go:44-55`, "seg6-encapsulated route") describe
a kernel-native `netlink.SEG6Encap` route. **That description is stale
against the code it documents.** `Backend.EnsureRoute`'s production
implementation (`kernelBackend.EnsureRoute`, `backend.go:108-116`) calls
`srv6.RouteEgressAdd`, whose own doc comment
(`internal/plumbing/srv6/egress.go:27-40`) is explicit that it now installs
an `egress_route_table` entry — a TC-BPF (`usid_egress`) mechanism — "the
TC-BPF replacement for what used to be a kernel-native SEG6 encap route
(`netlink.SEG6Encap`)", because that kernel mechanism is "confirmed broken
by CVE-2026-31668" under this codebase's per-tenant-VRF architecture
(`seg6` lwtunnel's `dst_cache` reused blindly across differing routing
contexts). `EnsureRoute` additionally installs a plain, non-encapsulating
"redirect route" (`ensureRedirectRoute`, `ebpfdatapath.go`) purely so the
pod's own outbound traffic is routed onto the VRF interface `usid_egress`
is attached to — see `ensureEgressDatapath`'s own doc comment
(`ebpfdatapath.go:266-276`). **Read the code, not the `doc.go`/`backend.go`
comments, for the actual egress mechanism**: it is the same
`usid_egress`/`egress_route_table` TC-BPF datapath §3 and §5 already use,
not a kernel `seg6` route. `docs/plans/854-vpc-http-ingress-endpointslice.md`
and `docs/plans/855-ingress-sidecar-vpc-backend-connectivity.md`, which
both describe the `seg6 ENCAP_RED` design, are superseded on this point by
the CVE-driven TC-BPF rewrite; treat them as historical design context, not
a description of what runs today.

## 5. The node agent (`internal/installer`)

`internal/installer.Run` (`cmd/galactic-cni`'s `run` subcommand,
`cmd/galactic-cni/main.go:67`) is the long-running container of the
`galactic-cni` DaemonSet. It starts the eBPF datapath
(`startEBPFDatapath`, `installer.go:463-499`), which calls
`ebpfStartFn` → `attach.StartWatching` (production; `installer.go:223-225`).

### The netlink-driven attach/detach watch

`attach.StartWatching` (`internal/plumbing/ebpf/attach/watch.go:311-`) runs
`Start` once, then launches `Watch` in a background goroutine
(`watch.go:181-`). `Watch` subscribes to netlink **link** and **route**
change events (`linkSubscribeFn`/`routeSubscribeFn`,
`watch.go:39-40`) and, on every event, re-resolves the interface set
`usid_ingress` should be attached to, attaching to newly-resolved
interfaces and detaching from ones that dropped out
(`attach/doc.go:16-19`). This is what keeps `usid_ingress` on the right
uplink interface(s) across an interface coming up/down, independent of any
CRD.

### Every ticker in `Run`, with its real interval

All values are read directly from `internal/installer/installer.go`; none
are guessed:

| Ticker | Interval | Line | What it does |
|---|---|---|---|
| `ebpfHealthTicker` | 10s | `installer.go:47` (`ebpfHealthCheckInterval`) | Polls `attach.Handle.Healthy()`; flips the `ebpf-datapath` gRPC health service. |
| `ebpfGCSweepTicker` | 5 min | `installer.go:54` (`ebpfGCSweepInterval`) | Runs `gc.SweepEBPFVRFTable` (§3's `vrf_table` repair) **and** `gc.SweepEBPFNPTv6Table` — this is a *different* ticker/process from `GCReconciler`'s own 5-minute ticker (§2): this one runs inside the `galactic-cni` container because the pinned eBPF maps only exist there. |
| `radvReconcileTicker` | 2s | `installer.go:64` (`radvReconcileInterval`) | Tap/VM router-advertisement actor bookkeeping — unrelated to ingress. |
| `tapNeighTicker` | 30s | `installer.go:71` (`tapNeighReconcileInterval`) | Tap guest neighbor resolution — unrelated to ingress. |
| `sidecarReturnTicker` | 30s | `installer.go:80` (`sidecarReturnReconcileInterval`) | Runs `reconcileSidecarReturnPath` (see "The sidecar return path" below) — semaphore-guarded so a slow pass drops a tick rather than piling up. |
| `refreshTicker` | 300s (5 min) | `installer.go:764` | Refreshes the host kubeconfig token, rotates the CNI log file, and re-runs `reconcileLocatorLocalRoute` (see "The locator local route" below). |
| `cleanupTimer` | 2 min, one-shot | `installer.go:768` | Removes a stale `.bin` CNI wrapper file. |

### The locator local route (`internal/installer/locatorroute.go`)

`ensureLocatorLocalRoute` (`locatorroute.go:63-100`) installs a **local**
route for this node's own uSID locator `/64` (`Block(48) + NodeID(16)`,
derived from this node's own `BGPRouter`) into the kernel's `local` table,
pointed at `lo`. Without it, `netlink.RouteGet` — which
`egressroutemap`'s `resolveLinkAndL2` calls once per registration to pick
an egress interface/next-hop MAC — fails with `EINVAL` against the
locator's own `Null0` discard route whenever the destination SID belongs to
*this* node (a same-node encapsulation, e.g. an Envoy sidecar reaching a
backend on its own node). It is idempotent (`RouteReplace`) and also prunes
routes for a locator this node no longer owns
(`pruneStaleLocatorLocalRoutes`, `locatorroute.go:107-127`), run at startup
and on every `refreshTicker` tick.

### The sidecar return path (`internal/installer/sidecarreturn.go`)

The host side of §4's return-path advertisement. Per the file's own header
comment (`sidecarreturn.go:28-77`): a remote node encapsulates a backend's
reply toward this node's own SID, but nothing on this node can take
delivery of it unless this file installs, per advertised sidecar gateway
address:

1. `locator_table` + `function_table` entries for this node's own Block
   and Node-ID (`installSidecarReturn`, `sidecarreturn.go:220-`,
   `registry.Locator.Register`/`registry.Function.Register` at
   `sidecarreturn.go:195,198`) — **a node hosting only sidecars has no CNI
   attachment, so §3's `registerEBPFDatapath` never runs there; this is
   these two tables' only writer on such a node.**
2. A `vrf_table` entry under the node's real Block, keyed on the
   advertised Argument, `EgressKindVeth` (`sidecarreturn.go:249`).
3. A route for the gateway address out the host side of the pod's
   netns-crossing veth (`ensureSidecarReturnRoute`, `sidecarreturn.go:259-`).
4. A permanent neighbor for that address on the same interface
   (`ensureSidecarReturnNeighbor`, `sidecarreturn.go:277-`) — `bpf_fib_lookup`
   does not trigger NDP, so an unresolved neighbor is a silent drop.

`ensureSidecarReturnPath` (`sidecarreturn.go:151-`) discovers which
gateway addresses are currently advertised by listing this node's own
`BGPAdvertisement`s (via the `crdnames.AnnotationIngressHostIfindex`/
`AnnotationIngressHostMAC` annotations §4's `PublishGateway` wrote) and
reconciles all four pieces above every 30 seconds
(`sidecarReturnReconcileInterval`).

**Correction to `docs/plans/855-return-path-ingress-decap.md`:** that plan's
own status line reads "proposed, design review complete. No code written
for Pieces 1–3 yet" and its design (§6) proposes implementing all three
pieces inside `galactic-router`'s `BGPRouter` reconcile path (root netns,
already holding a pinned-map handle) — explicitly *not* the sidecar itself
(decision D-2: "A root-netns component owns the root-netns half —
`galactic-router`, not the sidecar"). **Both are stale.** The code exists
(`internal/installer/sidecarreturn.go`, described above), and it landed in
`galactic-cni`'s installer daemon (`internal/installer.Run`), not
`galactic-router` — a different binary and a different reconcile model
(a 30-second ticker inside a node-agent DaemonSet container, not a
CRD-watch-triggered controller-runtime reconciler) than the plan proposed.
If you're mapping "which component owns the return-path host state" from
that plan, use this document's §5 instead.

## 6. The underlay

The overlay (SRv6/EVPN over iBGP) rides on top of an eBGP underlay that has
to already provide plain IP reachability between nodes: **`fabric-router`**,
an FRR DaemonSet (`config/fabric-router/`). Its `frr-init` container reads
the pod's own node name from a `NODE_NAME` downward-API env var
(`config/fabric-router/daemonset.yaml:83`) and selects a
per-node `frr.conf.<nodename>` key out of a hand-authored `fabric-config`
ConfigMap (`daemonset.yaml:92-93`) rather than assuming one shared
`frr.conf` for the whole DaemonSet — necessary because `fabric-router`'s
own affinity can legitimately match more than one node, and BGP underlay
config (hostname, router-id, interface addresses, remote-AS) inherently
differs per physical node. `fabric-router` is **not** part of the root
`config/kustomization.yaml`'s default resource list and is not deployed by
`kubectl apply -k config/` — an operator must author the `fabric-config`
ConfigMap by hand first.

This matters to ingress specifically because the underlay must distribute
**every node's own locator `/64`** (each `BGPRouter`'s `srv6Locator` +
`nodeID`, §1) as an ordinary reachable IP prefix. If it doesn't, a remote
node's `RouteGet`/`bpf_fib_lookup` for another node's SID has no underlay
route to resolve against, and every SRv6-encapsulated packet toward that
locator — the CNI chain's pod advertisements, the ingress sidecar's
gateway-address advertisement, all of it — is unreachable regardless of
how correctly the BGP/eBPF control plane above it is configured.

## 7. Known hazard: an eBPF map schema change wipes every pinned map

`attach.Load` (`internal/plumbing/ebpf/attach/attach.go:108-`) pins every
map in the compiled collection under `pinDir` (`attach.go:141-149`) so a
control-daemon restart reuses maps already pinned from a previous run. If
the newly compiled map spec no longer matches what's pinned — a changed
value struct size or `max_entries`, i.e. any pinned map's schema changed —
`spec.LoadAndAssign` fails with `ebpf.ErrMapIncompatible`
(`attach.go:153`). The recovery path,
**`unpinIncompatibleMaps`** (`attach.go:214-233`), does this:

```go
// attach.go:222-233
func unpinIncompatibleMaps(spec *ebpf.CollectionSpec, pinDir string) error {
    var errs []error
    for name := range spec.Maps {
        path := filepath.Join(pinDir, name)
        m, err := ebpf.LoadPinnedMap(path, nil)
        if err != nil {
            if errors.Is(err, os.ErrNotExist) {
                continue
            }
            errs = append(errs, fmt.Errorf("load pinned map %q for recreation: %w", name, err))
            continue
        }
        if err := m.Unpin(); err != nil {
            errs = append(errs, fmt.Errorf("unpin stale map %q: %w", name, err))
        }
        _ = m.Close()
    }
    return errors.Join(errs...)
}
```

It iterates **`spec.Maps`** — every map compiled into the collection, not
just the one that triggered `ErrMapIncompatible` — and unpins each one that
exists on disk. The very next `spec.LoadAndAssign` call
(`attach.go:163`) then creates every map fresh, empty. **A schema change to
any one pinned map (`vrf_table`, `locator_table`, `function_table`,
`ifindex_vrf_table`, or any other map in the same collection) unpins and
recreates *all* of them, not just the changed one.**

As §3's table shows, only `vrf_table` has a repair path
(`gc.SweepEBPFVRFTable`, on a 5-minute ticker inside `galactic-cni`, §5).
`locator_table`, `function_table`, and `ifindex_vrf_table` have none. After
a schema-changing rollout, every *existing* attachment's traffic through
those three tables stays broken — even though `vrf_table` itself
self-heals — until each attachment's original one-shot writer runs again:
for the CNI path, that means the pod must be recreated (a fresh `cmdAdd`);
for the ingress sidecar's return path, the next `sidecarReturnTicker` tick
(30s) reinstalls it automatically, since that path is itself
ticker-driven rather than one-shot-only.

## 8. Diagrams

- **C4 Level 3 (Component):**
  [`control-plane-components.puml`](control-plane-components.puml),
  rendered to [`control-plane-components.png`](control-plane-components.png)
  via this doc set's own documented `podman run` command
  (`docs/architecture/README.md`).
- **Sequence (pod-up to remote-node route install):** below.

```mermaid
sequenceDiagram
    autonumber
    participant Sched as Kubernetes Scheduler
    participant Veth as galactic-veth (cmdAdd)
    participant IPAM as galactic-ipam
    participant BGP as galactic-bgp (cmdAdd)
    participant K8s as Kubernetes API
    participant Router as galactic-router<br/>(BGPRouterReconciler)
    participant GoBGP as Embedded GoBGP
    participant Remote as Remote node's<br/>galactic-router / GoBGP
    participant RemoteKernel as Remote node kernel<br/>(FIB / VRF route)

    Sched->>Veth: Pod scheduled; CNI ADD invoked
    Veth->>Veth: vrf.Add(vpc); create veth pair
    Veth->>IPAM: delegate IPAM (if "ipam" block present)
    IPAM-->>Veth: allocated address(es) (prevResult)
    Veth-->>BGP: chain-invoked with prevResult
    BGP->>K8s: lookupBGPRouter (list BGPRouter for this node)
    K8s-->>BGP: BGPRouter{srv6Locator, nodeID, localASN}
    BGP->>BGP: allocateArgument (VRFID)
    BGP->>K8s: CreateOrUpdate BGPVRFInstance
    BGP->>BGP: registerEBPFDatapath:<br/>locator_table, function_table,<br/>vrf_table, ifindex_vrf_table<br/>+ attach usid_egress
    BGP->>K8s: CreateOrUpdate BGPAdvertisement (prefixes, vrfID, End.DT46)
    BGP->>K8s: publishEndpointSlice (tenant-id label)
    K8s-->>Router: watch event: BGPAdvertisement changed
    Router->>Router: BuildDesiredRouter (gather peers,<br/>VRFs, advertisements, policies)
    Router->>GoBGP: apply DesiredRouter
    GoBGP->>Remote: EVPN Type-5 IP-Prefix route<br/>(prefix, RT, SRv6 SID via GWIPAddress)
    Remote->>Remote: BGPRouterReconciler / GoBGP<br/>imports route (matching import RT)
    Remote->>RemoteKernel: install VRF route toward<br/>this node's SID over the underlay
    Note over RemoteKernel: Remote node can now reach<br/>the new pod; see request-path.md<br/>for the packet's own journey
```

## Claims I could not verify in code

- **`docs/plans/855-return-path-gateway-advertisement.md`'s "Not implemented
  here" section** — cited in §4 for `GatewayAddressResolver`'s own doc
  comment; I read only the referencing code comment, not the plan document
  itself, to confirm its exact wording.
- **`ServiceVIPBinding`'s write side** (§1) — I confirmed by grep that no
  `ServiceVIPBindingSpec{}` literal or `CreateOrUpdate` call against one
  exists anywhere under `internal/`, but I did not exhaustively rule out a
  write path in a different repo (e.g. a future `galactic-gateway`
  `usidresolver.go` change, or a controller outside this checkout).
- **`docs/plans/854-vpc-http-ingress-endpointslice.md`** — referenced by
  `internal/cnibgp`'s own doc comments as the design source for
  `publishEndpointSlice`/`crdnames.LabelTenantID`; I read the citing code
  comments, not the plan document's own text, to confirm the annotation/
  label contract it describes matches what's implemented (the code itself,
  which I did read directly, is what §3/§4's claims are actually rooted
  in). It also describes the sidecar's egress as a kernel `seg6 ENCAP_RED`
  route — confirmed superseded by the TC-BPF mechanism, see §4's
  correction.
- **`docs/plans/855-ingress-sidecar-vpc-backend-connectivity.md`'s "core
  mechanism implemented (2026-08-18)" status line** — I read this status
  line directly and it matches what I found in `internal/ingresssidecar`,
  but the plan itself also flags two required kernel-verification passes
  as **not done** ("neither is possible from this sandbox"); I have not
  independently verified real-kernel behavior (`RouteEgressAdd`/flock-path,
  end-to-end eBPF decap) beyond reading the Go source. This plan also
  describes the `seg6 ENCAP_RED` egress design — confirmed superseded, see
  §4's correction.
- **`docs/plans/855-return-path-ingress-decap.md`'s "proposed... no code
  written" status line, and its D-2 decision to implement Pieces 1–3 in
  `galactic-router`** — confirmed stale: `internal/installer/sidecarreturn.go`
  implements those pieces, in `galactic-cni`'s installer daemon, not
  `galactic-router`. See §5's correction note.
