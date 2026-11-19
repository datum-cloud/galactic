# Host state ownership

Status: proposed. This page lists every writer of shared node state at the
branch start and assigns each resource class one mutation authority. Line
references are to the base commit `11323a99642aecb0e53220c1dbc49f61652f0b52`.

## What "one mutation authority" means

For state that several processes write, the authority is the process that
**owns the fence** of the scope the state belongs to (D12). Only the owner holds tickets
(`Claim`, `Adopt`, `Begin`) and commits with `Commit` or `CommitSnapshot`.
Another process may still write in that scope, but only through the fence, with
`Exclusive`. An `Exclusive` write takes the scope lock, changes no owner, and
makes every outstanding ticket stale, so the owner reads the state again before
its next change.

This interpretation keeps one property the epic requires: CNI attaches a
workload while Worker is down. CNI never owns a scope. It writes with
`Exclusive` whether or not Worker runs, and Worker adopts that state when it
starts. A write that bypasses the fence is a defect.

The fence is `internal/ownership`, generalized from the VPC scope Galactic
Edge introduced. Its state directory must outlive every writer, as the package
documentation requires. Every writer uses the package's `VPCScope` names and its
shared `DefaultDir`, `/var/lib/galactic-edge/ownership`, which the galactic-router
and galactic-cni DaemonSets mount from the host.

A resource class has one of two kinds of authority:

| Kind         | Authority                                   | Applies to                                                                                                                               |
| ------------ | ------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| Fenced       | The owner of the node-and-VPC scope's fence | The host VRF and its table ID, the SID Argument, BGPVRFInstance, BGPAdvertisement, `vrf_table`, VPC routes and `egress_route_table` rows |
| Sole mutator | The one process that writes the class       | State only one process writes, such as an attachment's own interface, program loading, TC attach and an XDP dispatcher slot              |

A sole mutator needs no fence, because no other process writes its class. If a
second writer appears, the class becomes fenced.

## Writers and authorities

| Resource class                                              | Writers at the branch start                                                                                                                                                                                                                                                                                                                                                                                                                            | Coordination today                                                                                       | Authority after transfer                             | Transfer step                                                                                                                                                                                                                                                                                                                                                                          | Task                                                                                                                                       |
| ----------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------- | ---------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| Host VRF device and table ID (1 to `0xEFFF`)                | `vrf.EnsureAndEnslave` (`internal/plumbing/vrf/vrf.go:116`) from galactic-veth and galactic-tap; `vrf.Add` (`vrf.go:93`) from `nodevpc.Ensure` in galactic-edge; `vrf.DeleteIfUnused` (`vrf.go:302`) from galactic-router GC                                                                                                                                                                                                                           | flock in `/var/lib/cni/galactic-vrf` (`lock.go:28`), reservations in `tables.json` (`reservation.go:35`) | Worker                                               | CNI writes with `Exclusive`; galactic-edge calls Worker. GC moves into Worker.                                                                                                                                                                                                                                                                                                         | [#1434](https://github.com/datum-cloud/galactic/issues/1434)                                                                               |
| Per-node VPC state, SID Argument and BGPVRFInstance         | `nodevpc.Ensure` (`internal/nodevpc/ensure.go:72`) from galactic-edge (`internal/edge/agent/vpcstate.go:30`); `ClaimArgument` (`argument.go:109`) and `AllocateArgument` (`argument.go:239`) from galactic-bgp and galactic-edge; the galactic-vrf sidecar writes BGPVRFInstance directly (`internal/ingresssidecar/gateway.go:273`)                                                                                                                   | Argument flock (`argument.go:33`); the sidecar's write takes no lock                                     | Worker                                               | Route the sidecar's BGPVRFInstance write through Worker. `argument.go:91` records that a writer outside the lock can still collide.                                                                                                                                                                                                                                                    | [#1434](https://github.com/datum-cloud/galactic/issues/1434), [#1439](https://github.com/datum-cloud/galactic/issues/1439) for the sidecar |
| `vrf_table` datapath rows                                   | `attachreg.RegisterDatapath` (`internal/plumbing/ebpf/attachreg/register.go:98`) and `ReleaseArgument` (`register.go:223`) from galactic-bgp and `nodevpc`; galactic-cni repair and the `SweepEBPFVRFTable` sweep (`internal/gc/gc.go:749`)                                                                                                                                                                                                            | Per-key convention and sweeps; no lock                                                                   | Worker                                               | galactic-bgp registers with `Exclusive`; Worker commits its own rows as owner. The sweep runs in Worker.                                                                                                                                                                                                                                                                               | [#1434](https://github.com/datum-cloud/galactic/issues/1434)                                                                               |
| `egress_route_table` rows                                   | galactic-router (`internal/runtime/gobgp/vrfroutes.go:34`, `vrfmove.go:30`); galactic-bgp through `attachreg` (`register.go:386`, `register.go:460`); the galactic-vrf sidecar (`internal/ingresssidecar/backend.go:144`, `backend.go:159`); galactic-cni installer, repair and prune (`internal/installer/egressgroup.go:203`, `attachreg/fill.go:123`, `internal/plumbing/ebpf/sidecarmap/prune.go:80`); galactic-edge (`attachreg/hostlink.go:204`) | An in-process mutex in galactic-router only (`vrfroutes.go:81`); no cross-process lock                   | Worker (Fabric module)                               | Worker's Fabric module writes the tenant routes of every VPC Worker owns; galactic-router keeps learning EVPN routes and hands them to Worker ([handoff](contract.md#tenant-route-handoff)), writing with `Exclusive` only in a VPC Worker does not own. The installer sweep skips those tenant routes. The other writers call Worker, or use `Exclusive` until their Task moves them. | [#1436](https://github.com/datum-cloud/galactic/issues/1436); [#1439](https://github.com/datum-cloud/galactic/issues/1439) for the sidecar |
| Per-VPC kernel routes and rules                             | VRF unreachable defaults (`vrf.go`); the locator local route (`internal/installer/locatorroute.go`); sidecar-return routes (`internal/installer/sidecarreturn.go`)                                                                                                                                                                                                                                                                                     | None beyond the sidecar-return range from `0xF000`                                                       | Worker                                               | Worker commits them as the scope owner.                                                                                                                                                                                                                                                                                                                                                | [#1434](https://github.com/datum-cloud/galactic/issues/1434)                                                                               |
| Sidecar return path (tables from `0xF000`) and reaping      | `ensureSidecarReturnPath` (`internal/installer/sidecarreturn.go:159`); `deleteIngressAdvertisement` and `pruneAllSidecarRows` (`internal/installer/sidecarreap.go:243`, `sidecarreap.go:264`), all in galactic-cni                                                                                                                                                                                                                                     | Evidence from advertisement annotations and the host veth                                                | Worker                                               | The sidecar requests a `socket` claim; Worker programs the return path and withdraws it on release or lease expiry.                                                                                                                                                                                                                                                                    | [#1439](https://github.com/datum-cloud/galactic/issues/1439)                                                                               |
| BGPAdvertisement for a VPC on a node                        | galactic-bgp; the galactic-vrf sidecar (`gateway.go:300`); edge route publication; galactic-cni reaping (`sidecarreap.go:243`); galactic-router GC (`RunGC`, `gc.go:1265`)                                                                                                                                                                                                                                                                             | CRD optimistic concurrency                                                                               | Worker                                               | CNI records its containers with `Exclusive`; Worker writes service claims and owns deletion.                                                                                                                                                                                                                                                                                           | [#1434](https://github.com/datum-cloud/galactic/issues/1434), [#1436](https://github.com/datum-cloud/galactic/issues/1436)                 |
| GC of per-VPC state                                         | `RunGC` (`internal/gc/gc.go:1265`) in galactic-router; `SweepEBPFVRFTable` (`gc.go:749`) and `SweepEBPFNPTv6Table` (`gc.go:1146`) in galactic-cni                                                                                                                                                                                                                                                                                                      | VRF lock; the edge fence for edge scopes                                                                 | Worker                                               | Each sweep runs in Worker as the scope owner, on the same evidence it uses today.                                                                                                                                                                                                                                                                                                      | [#1434](https://github.com/datum-cloud/galactic/issues/1434)                                                                               |
| Edge host links                                             | `RegisterHostLink`, `UnregisterHostLink` and `SyncHostLinkRoutes` (`attachreg/hostlink.go:50`, `:161`, `:203`) from galactic-edge                                                                                                                                                                                                                                                                                                                      | The edge VPC fence                                                                                       | Worker                                               | galactic-edge calls Worker through its `Datapath` implementation ([connector](connector.md)).                                                                                                                                                                                                                                                                                          | [#1440](https://github.com/datum-cloud/galactic/issues/1440)                                                                               |
| Attachment interface and its rows                           | galactic-veth and galactic-tap create and delete the device; `RegisterTenantGateway` (`register.go:632`) from galactic-bgp; `UnregisterInterface` (`attachreg/unregister.go:33`) from CNI DEL and `internal/installer/staletaps.go`                                                                                                                                                                                                                    | Device private to one attachment                                                                         | CNI                                                  | None. Worker observes the interface and never deletes it.                                                                                                                                                                                                                                                                                                                              | [#1434](https://github.com/datum-cloud/galactic/issues/1434) for observation                                                               |
| Sidecar pod VRFs (tables from `0x10000`) in the pod         | `vrf.AddInRange` (`internal/ingresssidecar/backend.go:95`) in the pod's network namespace                                                                                                                                                                                                                                                                                                                                                              | Separate network namespace                                                                               | galactic-vrf sidecar                                 | None. Service-specific state stays in the service agent.                                                                                                                                                                                                                                                                                                                               | [#1439](https://github.com/datum-cloud/galactic/issues/1439)                                                                               |
| BGP and EVPN route origination                              | galactic-router (GoBGP, from CRDs)                                                                                                                                                                                                                                                                                                                                                                                                                     | One process                                                                                              | galactic-router                                      | None.                                                                                                                                                                                                                                                                                                                                                                                  | None                                                                                                                                       |
| Pinned programs and maps in `/sys/fs/bpf/galactic`          | galactic-cni loads and pins them (`internal/plumbing/ebpf/attach/attach.go:31`)                                                                                                                                                                                                                                                                                                                                                                        | One loader                                                                                               | galactic-cni (loading only; rows follow their class) | None.                                                                                                                                                                                                                                                                                                                                                                                  | None                                                                                                                                       |
| TC attachment on an interface                               | galactic-cni (`attach.go:499`)                                                                                                                                                                                                                                                                                                                                                                                                                         | flock `/run/galactic/tc-<interface>.lock`                                                                | galactic-cni                                         | None.                                                                                                                                                                                                                                                                                                                                                                                  | None                                                                                                                                       |
| XDP dispatcher slots                                        | galactic-gateway (slots 0 and 1) and galactic-nat (slot 2) through `Fill`, `Clear`, `Release`, `SetRole` and `Renew` (`internal/plumbing/ebpf/xdpdispatch/dispatcher.go:678-881`), 8 slots (`dispatcher.go:60`)                                                                                                                                                                                                                                        | Lock on the pin directory and a 120 s lease per slot                                                     | The service that holds the slot                      | None. Worker reads slot state for capability status only.                                                                                                                                                                                                                                                                                                                              | None                                                                                                                                       |
| `/sys/fs/bpf/galactic-nat`, `galactic-edge`, `galactic-xdp` | galactic-nat; galactic-gateway; both through the dispatcher                                                                                                                                                                                                                                                                                                                                                                                            | One writer each, plus the dispatcher lock                                                                | The owning service                                   | None.                                                                                                                                                                                                                                                                                                                                                                                  | None                                                                                                                                       |
| IPAM, FRR configuration                                     | `internal/cni/ipam`; `cmd/fabric-config-agent`                                                                                                                                                                                                                                                                                                                                                                                                         | flock each                                                                                               | Unchanged                                            | None.                                                                                                                                                                                                                                                                                                                                                                                  | None                                                                                                                                       |

NAT translations and shard sessions, Gateway VIP selection and Maglev, and
Envoy's proxy sockets stay in their service agents.

## Bootstrap, adoption and transfer

Each step uses the fence operations that exist today (D13).

1. **Bootstrap with Worker down.** CNI ADD writes the VPC scope with
   `Exclusive`, which needs no owner. Workload attach never waits for Worker.
   `Exclusive` returns `ErrTransitioning` only while a `Fence` waits for its
   `Adopt`, and CNI retries within its own ADD deadline. Worker never leaves a
   scope in that state: it takes scopes over with `Takeover` (D23), which
   fences and adopts under one lock, so a Worker that dies while taking a
   scope over cannot block CNI until it returns.
2. **Adoption of preexisting state.** When Worker starts, it takes each scope it
   finds: every host VRF device, and every fence record a Worker incarnation
   owns, which covers a transfer left open before CNI created the VRF.
   It uses `Claim` for an unowned scope, or `Takeover` for one an earlier
   Worker incarnation owned, including one an older incarnation left between
   `Fence` and `Adopt`. Both return a ticket that requires `CommitSnapshot`,
   which Worker runs with its complete desired state read from disk, merged
   with the host's current rows. Until that snapshot commits, Worker refuses
   claim changes for the scope with `UNAVAILABLE`/`Resyncing`. Each Worker
   incarnation's owner ID starts with `galactic-worker:`, which is how a new
   incarnation recognizes a scope an earlier one owned. Worker never takes
   over a scope another writer owns: its claims there report
   `Programmed=False` with reason `ScopeOwnedElsewhere` until that writer's
   transfer step (3) hands the scope over.
3. **Ownership transfer.** A legacy writer moves to Worker in two steps. First it
   writes with `Exclusive` on the shared fence instead of writing directly.
   Then Worker adopts the scope, and the legacy writer calls Worker instead of
   writing. The `Fence` before `Adopt` makes every earlier ticket stale.
4. **Cleanup after partial application.** A commit that fails, or whose process
   dies part-way, leaves the scope resync-required. The next owner reconciles
   a full snapshot before accepting incremental changes, so a half-applied
   change is neither assumed done nor assumed undone.
5. **Loss of the state directory.** Stop every writer, reconcile host state, and
   create a new authority, as `internal/ownership` requires. Never restore
   the directory while writers run.

## Node and VPC scope

[#1434](https://github.com/datum-cloud/galactic/issues/1434) implements the
fenced authority for the node and VPC scope and the first transfer step for
CNI and garbage collection.

- **CNI writes with `Exclusive`.** galactic-tap and galactic-veth create the VRF
  and enslave the host link with `Exclusive` on the VPC's scope. galactic-bgp
  does the same for each publish attempt (Argument claim, BGPVRFInstance,
  `vrf_table` registration and BGPAdvertisement), its rollback and the DEL
  advertisement release (`internal/cni/vpcfence`). The installer's sidecar
  return install and advertisement reap use the endpoint's VPC scope. CNI waits
  at most 30 s for an open transfer and never waits for Worker.
- **Worker owns the scope.** Worker takes every VPC scope it discovers that no
  other writer owns. A VPC with claims gets its canonical state from
  `nodevpc.Ensure` inside Worker's commit, before the delivery modules run.
  Adopting a scope with no claims writes nothing.
- **References.** A VPC's host state is in use while Worker holds a claim in
  it, a link is enslaved to its VRF, or a Galactic Edge attachment uses it.
  Worker reclaims the VRF and BGPVRFInstance once the VPC has gone unused for
  `--host-grace` (60 s), on the same evidence galactic-router's GC uses
  (`gc.ReclaimVPC`). The grace keeps the state across an attachment's
  replacement.
- **GC transfer.** galactic-router's GC (`maintenance.Guard.Reclaim`) and the
  installer's `vrf_table` repair refuse a scope a Worker incarnation owns
  (`ownership.ErrWorkerOwned`) and keep doing their work everywhere else. A
  Worker-owned scope is reclaimed only by a running Worker.
- **Observation.** Worker subscribes to link events. A link joining, leaving or
  changing in a VPC's VRF requeues that VPC, and `hostscope.AttachmentsOf`
  reads each attachment's current ifindex and neighbors when a module asks.
  Worker never creates or deletes an attachment's link.

[#1436](https://github.com/datum-cloud/galactic/issues/1436) moves the
router's `egress_route_table` writers:

- **galactic-router writes under the fence.** Every tenant route write, and
  each removal after a VRF moves table, runs under the VPC's scope with
  `RefuseWorkerOwned`. A VPC no Worker owns is written as before; one a Worker
  incarnation owns is left to Worker.
- **Worker's Fabric module writes the tenant routes.** The router hands every
  route it installs or withdraws to Worker through the Routes service, and the
  Fabric module writes the routes of each VPC Worker owns in that scope's
  commit. It never touches an entry the router did not hand it.
- **The installer sweep leaves them alone.** In the table of a VPC a Worker
  owns, the `egress_route_table` refresh sweep re-resolves only egress shard
  entries and sentinels; the Fabric module keeps the tenant routes' next hops
  current. Those shard writes, CNI's pass-through and shard writes and the
  repair fill still write without the fence; no Task moves them yet.

The galactic-vrf sidecar's in-pod BGPVRFInstance and backend writes (#1439)
and edge host links (#1440) move in their own Tasks.

## Defects this transfer removes

Two writers bypass any cross-process lock at the branch start. Both become
transfer steps of this epic, listed in the table above:

- The galactic-vrf sidecar writes BGPVRFInstance without the Argument lock
  (`internal/ingresssidecar/gateway.go:273`).
- Five processes write `egress_route_table` rows with no shared lock:
  galactic-router, galactic-bgp, the galactic-vrf sidecar, galactic-cni and
  galactic-edge. Table IDs keep only the sidecar apart from the others
  (`internal/plumbing/ebpf/egressroutemap/owner.go`); the four host writers share
  the host range from 1 to `0xEFFF` with nothing to separate them.
