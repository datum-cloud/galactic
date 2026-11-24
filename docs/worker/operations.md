# Operating Galactic Worker

This runbook covers installing galactic-worker from branch artifacts,
reading its diagnostics, following a flow, and draining, uninstalling or
rolling a node back. It applies to the `integration/galactic-worker` branch
([branch workflow](branch-workflow.md)).

## Install

Worker runs on every node where galactic-router runs as a per-node router
(`galactic.datumapis.com/galactic=router`, with `node=compute` or
`node=edge`). Services call the Worker on their own node, so edge and compute
nodes both need one.

Pick a placement profile:

| Profile   | Nodes                                                                                        | Manifests                                                                                                                                                                           |
| --------- | -------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Dedicated | Services on `node=edge` with their opt-ins; tenant workloads on `node=compute`               | `config/galactic-worker/base` as shipped; each NAT node keeps its own XDP attach mode                                                                                               |
| Combined  | As dedicated, and TAP-backed guests pinned to `node=edge` nodes that run the gateway and NAT | Adds `config/galactic-worker/profiles/combined`, which runs `galactic-nat` in dispatch mode and gives `galactic-gateway` the Worker socket and backend health for its Local handoff |

[Node labels](../operations/node-labels.md#combined-placement) defines both
placements. The allowlist is the same in both: `galactic-router` may use
`fabric.routes`, `galactic-nat` `local.veth_pair` and `fabric.srv6`, and
`galactic-gateway` `local.tap` and `fabric.srv6`. A caller needs its handoff's
capability for every claim, Local or Fabric
([contract](contract.md#capabilities)). `tests/manifests/worker-profiles/`
composes each placement with the namespace, CNI, router, NAT and gateway, and
is the rendered example:

```sh
kustomize build tests/manifests/worker-profiles/combined > combined.yaml
```

A deployment copies that composition, sets its own uplink names and pins every
image to one commit, `v0.0.0-<short-sha>`. The fixtures use the moving
`v0.0.0-integration-galactic-worker` tag.

Install in this order:

1. The CRDs and the `galactic-system` namespace, as for any Galactic install.
2. The rendered profile. Worker's pods turn ready once the API cache syncs and
   the socket listens. On first start each Worker takes over every VPC scope
   on its node that no other writer owns.
3. Restart nothing else. galactic-router finds the socket and hands Worker its
   tenant routes.

`task test:manifests` renders both profiles and compares every container's
capabilities, host namespaces and hostPath mounts, every RBAC rule and the
allowlist against `privileges.yaml` beside each fixture. Galactic Worker runs
with `hostNetwork`, `hostPID` and the capabilities `NET_ADMIN`, which
programs VRFs, links, routes, neighbors and tc filters, and `BPF`, which
opens the pinned maps and loads the Local programs.

Compose `config/galactic-worker/profiles/routed-link` into a placement whose
allowlist grants `local.routed_link` or `local.socket`, which the galactic-vrf
sidecar uses. The Component adds:

- `SYS_PTRACE`, because Worker finds a routed link's pod end through the
  pod's `/proc/<pid>/ns/net`, and the kernel's ptrace access check refuses
  that open for another user's process.
- `SYS_ADMIN`, because setting the pod end up enters that namespace with
  `setns`. Kubernetes refuses `allowPrivilegeEscalation: false` beside it, so
  the Component removes that setting.
- Permission to create and update BGPAdvertisements in `galactic-system`,
  where Worker publishes return prefixes for routed-link and socket claims.

Without the Component, Worker detects the missing capabilities at start,
logs it, and reports both capabilities unavailable with
`RoutedLinkUnavailable`. A claim that needs one is accepted and reports
`Programmed=False` with that reason. The privilege record beside each fixture
says why that placement grants what it grants.

The cluster's CNI must not claim Galactic's interfaces. Pin Cilium's devices
to the uplinks (the lab uses `eth0 bond+`). Worker creates links named
`G<VPC><key>N`, `T`, `R` and `P`, and a device pattern that matches them breaks
Local delivery.

### Roll out ingress sidecars separately

The installer preserves the return path for a legacy `galactic-vrf` sidecar
while its gateway advertisement and primary veth still describe a live
endpoint. You can upgrade Worker and the node installer before rolling the
cluster's sidecar image and controller.

The installer keeps a fallback route in the VPC's host table while the legacy
sidecar runs. If Worker, CNI ADD, or garbage collection repoints the shared
SRv6 entry first, it carries the active legacy route into the VPC table before
switching the entry. When Worker advertises the same gateway and its routed
link can deliver replies, the installer retires the fallback. On rollback,
the replacement sidecar can publish its legacy gateway again and the installer
restores the path. Replacing the proxy pod interrupts the connections it held.

## Read the diagnostics

### Inspect

`galactic-worker inspect` prints the node's view: each capability's
availability, each VPC scope's owner and generation, and each claim's
destinations with their locality, readiness and reason. It reads files only,
and runs in the Worker pod:

```sh
pod=$(kubectl -n galactic-system get pod -l app.kubernetes.io/name=galactic-worker \
  --field-selector spec.nodeName=<node> -o name)
kubectl -n galactic-system exec "$pod" -- /galactic-worker inspect
kubectl -n galactic-system exec "$pod" -- /galactic-worker inspect -o json
```

Worker writes the snapshot `inspect` reads to `/var/lib/galactic-worker/status.json`
(mode `0600`) within 5 seconds of a status change, and at least once a
minute. `inspect` reads each scope's owner and generation from the live
fence, so it also shows scopes another writer owns or a handback left.

### Metrics

Worker serves metrics on port 9104.

| Metric                                                     | Shows                                                                                                               |
| ---------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| `galactic_worker_capability_ready{capability,reason}`      | 1 when the capability is available; 0 with the reason it is not                                                     |
| `galactic_worker_destinations{capability,locality,reason}` | Live destinations by delivering capability, `local`, `fabric` or `unresolved`, and reason (`AsExpected` when ready) |
| `galactic_worker_local_hooks{state}`                       | Programmed Local destinations whose hooks are `covered`, `missing` or `unsupported`                                 |
| `galactic_worker_scopes{state}`                            | VPC scopes `owned`, `owned_elsewhere`, `transitioning`, `pending`, `resyncing` or under `repair`                    |
| `galactic_worker_claims_behind`                            | Claims whose status still describes an older generation                                                             |
| `galactic_worker_drift_repairs_total{module}`              | Repairs of host state that changed under Worker, such as a Local filter another process removed                     |
| `galactic_worker_refusals_total{reason}`                   | Refused calls, by contract reason                                                                                   |
| `galactic_worker_reconciles_total{outcome}`                | Reconcile passes, by outcome                                                                                        |
| `galactic_worker_fabric_routes_skipped_total{reason}`      | Tenant routes the Fabric module did not write                                                                       |

### Logs

Worker logs `claim is not ready` with the claim, caller, generation and
`reason` each time a claim's readiness or reason changes, and `claim is ready`
when it recovers. It logs `repaired host state that changed under Worker`,
with the VPC, module and the first difference, when it puts back state another
process removed.

### Removed hooks

Worker restores a hook it owns, such as a `galactic_local_*` filter, on its
next reconcile: a link or route event, or the 30-second resync. The
destination stays `Ready` unless traffic arrives in between, and the repair
shows as a `galactic_worker_drift_repairs_total` increment, the log line above
and a `repaired drift` line in `inspect` naming the filter and device. A hook
Worker does not own stays missing and keeps its reason: the client's XDP
program on a pair's NAT end (`HandoffHookMissing`) or the gateway's dispatcher
slot (`DispatcherSlotUnclaimed`).

### Reasons

| Reason                                  | Look at                                                                                                                                   |
| --------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| `HandoffHookMissing`                    | The `galactic_local_*` tc filter on the destination's interface or the pair's tenant end, or the client's XDP program on a pair's NAT end |
| `DispatcherSlotUnclaimed`               | The public slot of the receiving device's XDP dispatcher, which galactic-gateway holds in dispatch mode                                   |
| `HookUnsupported`                       | A hook running in a mode the handoff cannot use, such as generic XDP on a pair's NAT end                                                  |
| `HandoffInterfaceMissing`               | The guest's TAP or veth (CNI ADD has not run, or the pod was replaced), or a Local link with no carrier                                   |
| `HandoffMTUTooSmall`                    | The TAP's MTU against the receiving device's                                                                                              |
| `UnderlayUnreachable`                   | The underlay route to the destination node's locator (`ip -6 route get <locator>`)                                                        |
| `NeighborUnresolved`                    | The underlay next hop's or guest's neighbor entry (`ip -6 neigh`)                                                                         |
| `ReturnPathNotProgrammed`               | This node's BGPVRFInstance for the VPC and its `vrf_table` row                                                                            |
| `ForwardRouteMissing`                   | The tenant route galactic-router hands Worker for the destination                                                                         |
| `ScopeOwnedElsewhere`                   | The scope's owner in `inspect`: another writer owns it                                                                                    |
| `ModuleNotRunning`, `DatapathNotLoaded` | The capability row in `inspect` and the Worker log at start                                                                               |

The [contract](contract.md#errors-and-retry) lists every reason.

## Follow a flow

Run these from a node debug pod (`containers/galactic-debug/README.md`), which
has `ip`, `tc`, `bpftool` and `tcpdump`. Start from `inspect`: it names the
claim's destinations, their locality and the handoff interfaces Worker
created.

1. **TAP.** CNI names a guest's host interface `G<VPC><attachment>H`. Its tc
   ingress holds galactic-cni's chain, then Local's filters:

   ```sh
   tc filter show dev <tap> ingress
   tcpdump -ni <tap>
   ```

2. **Public NIC.** Ingress for a `local.tap` destination passes the shared XDP
   dispatcher's public slot, then Local's `galactic_local_rx` tc filter on the
   receiving device delivers it to the TAP:

   ```sh
   ip -d link show dev <uplink>         # xdp or xdpgeneric, and the dispatcher
   bpftool net show dev <uplink>
   tc filter show dev <uplink> ingress  # galactic_local_rx
   ```

3. **Internal pair.** A `local.veth_pair` claim has a pair named
   `G<VPC><key>N` (the NAT end, in the host namespace, where the client's XDP
   program runs) and `G<VPC><key>T` (the tenant end, in the VPC's VRF):

   ```sh
   ip -d link show dev G<VPC><key>N
   tc filter show dev G<VPC><key>T ingress   # galactic_local_pair_rx
   ```

4. **Remote locator.** A Fabric destination's forward path is the VPC's
   `egress_route_table` entry toward the destination node's locator, then the
   underlay route and neighbor. Its return path is this node's BGPVRFInstance
   for the VPC and its `vrf_table` row:

   ```sh
   bpftool map dump pinned /host/sys/fs/bpf/galactic/egress_route_table
   ip -6 route get <locator>
   ip -6 neigh show <next-hop>
   kubectl -n galactic-system get bgpvrfinstances -o wide | grep <node>
   ```

   In the lab, `deploy/containerlab/scripts/worker-fabric.sh dump NODE VPC`
   decodes one VPC's entries.

## Drain a node

Worker is a DaemonSet, so `kubectl drain --ignore-daemonsets` leaves it
running while the node's workloads leave. Forwarding never calls Worker, so
established flows run until their endpoints go.

1. Cordon and drain the node.
2. Watch `inspect` and `galactic_worker_destinations`: a Local destination
   whose guest left reports `HandoffInterfaceMissing` until its owner updates
   or releases the claim, and Fabric destinations elsewhere stop resolving
   to this node once its routes are withdrawn.
3. Restarting Worker during the drain is safe. A new incarnation takes over
   its predecessor's scopes and reconciles them from stored claims.

## Stop Worker on one node

The DaemonSet has no per-node opt-out label. To keep Worker off one node,
exclude its hostname:

```sh
kubectl -n galactic-system patch ds galactic-worker --type=json -p='[{"op":"add",
  "path":"/spec/template/spec/affinity/nodeAffinity/requiredDuringSchedulingIgnoredDuringExecution/nodeSelectorTerms/0/matchExpressions/-",
  "value":{"key":"kubernetes.io/hostname","operator":"NotIn","values":["<node>"]}}]'
```

The Worker pod on that node terminates. Its scopes stay Worker-owned, so
nothing else writes them, until you hand them back.

## Hand scopes back

Router garbage collection, galactic-router's route writes and the installer
skip every scope a galactic-worker incarnation owns, including one whose
Worker is gone. A node whose Worker was removed without a handback never
reclaims those VPCs' host state, and its router never writes their tenant
routes again.

Delete the DaemonSet, or exclude the node from it, before the handback: a
Worker pod that comes back during a handback takes the scopes again, and the
handback then stops without removing its claims or pins. Run the handback on
each node after its Worker pod is gone:

```sh
kustomize build config/galactic-worker/handback |
  sed 's/REPLACE_WITH_NODE_NAME/<node>/' | kubectl apply -f -
kubectl -n galactic-system logs -f pod/galactic-worker-handback-<node>
kubectl -n galactic-system delete pod galactic-worker-handback-<node>
```

Build it from the `galactic-kustomize` bundle the Worker came from, which
stamps the same image tag. From a checkout, pin that tag first:
`kustomize edit set image ghcr.io/datum-cloud/galactic-worker:<tag>` in
`config/galactic-worker/handback`.

The pod runs `galactic-worker handback`:

1. It refuses while a Worker answers on `/run/galactic-worker/worker.sock`.
2. For each Worker-owned VPC scope it leaves the owner
   `galactic-handback:<time>` with a resync pending
   ([ownership](ownership.md#handing-scopes-back)).
3. It removes the handoff links, tc filters and pass-through entries Worker's
   Local module wrote, and Local's pins under `/sys/fs/bpf/galactic-local`.
   It leaves galactic-edge's provider attachment links registered, with their
   pass-through entries, so their traffic keeps flowing until galactic-edge
   takes them back ([connector](connector.md#rollback)).
4. It empties `/var/lib/galactic-worker/claims` and removes the status
   snapshot.

It leaves the tenant routes Worker's Fabric module wrote, so traffic keeps
flowing. Then restart galactic-router on the node, which writes those routes
again as their owner. The lab check measures how long each node's state takes
to match its state before Worker after that restart
([lab guide](../../deploy/containerlab/docs/worker.md)):

```sh
kubectl -n galactic-system delete pod -l app.kubernetes.io/name=galactic-router \
  --field-selector spec.nodeName=<node>
```

The handback is safe to repeat. A scope another writer took after it is left
alone. Garbage collection reclaims a handed-back VPC's VRF and BGPVRFInstance
once nothing uses it, which can take two of its 5-minute passes, and then
releases the handback label. A provider attachment link enslaved to the VRF
keeps it in use, so on a node that keeps galactic-edge's links the VRF stays
until galactic-edge or Worker next reconciles the VPC. A Worker installed again later takes back every
handed-back scope that no other writer took in between.

## Uninstall

1. Stop the services' Worker clients: deploy service builds that do not call
   Worker, or remove their opt-ins. Each releases its claims. `inspect` then
   lists no claims. A claim left behind is withdrawn by the handback.
2. Delete the DaemonSet and wait for its pods to go:
   `kubectl -n galactic-system delete ds galactic-worker`.
3. Hand back the scopes and restart galactic-router on every node, as above.
   On a node with provider attachments, run galactic-edge again, pinned or
   through a new Worker, so it releases or keeps them: the handback leaves
   their links registered. A node that will not run galactic-edge again needs
   its attachments deleted while galactic-edge still runs, before the
   handback, or one Worker run afterwards with no claims, which unregisters
   the links' rows and pass-through entries.
4. Delete the rest: `kubectl delete -k config/galactic-worker` and the
   `galactic-worker-allowlist-*` ConfigMap.
5. Check each node from a node debug pod: no record in
   `/host/var/lib/galactic-edge/ownership/*.json` names a `galactic-worker:`
   owner, `ip link` shows no `G…N`, `G…T`, `G…R` or `G…P` links, and no
   interface carries a `galactic_local_*` filter. Provider attachment links
   (`E…`) remain while their attachments exist.

## Roll back a provider attachment node

The provider connector (`cmd/galactic-edge`, [connector](connector.md)) can
run pinned, writing attachments itself, instead of through Worker. To move a
node back to that mode:

1. Stop Worker on the node.
2. Hand back its scopes, as above.
3. Restart galactic-edge in pinned mode. It takes the scopes its attachments
   use from the handback label. This needs the pinned mode
   [#1440](https://github.com/datum-cloud/galactic/issues/1440) adds; an
   earlier galactic-edge refuses a handed-back scope.
4. Restart galactic-router on the node.

## Lab check

`task worker:verify` in `deploy/containerlab` installs each placement on the
lab's dfw site, injects a route, attachment and hook failure, and checks the
handback ([lab guide](../../deploy/containerlab/docs/worker.md)).

## Return a combined node to dedicated placement

1. Move the guests pinned to the node elsewhere. CNI DEL removes each TAP, and
   the services update or release the claims that delivered to them.
2. Keep galactic-nat in dispatch mode while the gateway runs on the node: the
   uplinks still carry both. Worker needs no change.
3. Check `inspect` and the metrics: no `local` destinations, every
   `galactic_worker_local_hooks` series at 0. Local's receiver filter leaves
   the public device once no `local.tap` claim remains.
