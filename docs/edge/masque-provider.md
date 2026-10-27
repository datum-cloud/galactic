# MASQUE provider adapter

`internal/edge/masque` connects a CONNECT-IP server (`internal/edge/connectip`) to a tenant VPC through the [provider contract](provider-contract.md). It implements `connectip.Admission` and `connectip.PacketBackend`, so every transport uses the same attachment, route and packet checks. It has no command of its own: the service binary that embeds it, and the grant authority that issues its grants, are separate deliverables of the [MASQUE connector design](../designs/masque/contract.md). The conformance fixture in `tests/edgeconformance/masqueprovider` runs it with static test credentials.

The adapter never touches host networking. galactic-edge programs and releases each attachment's host state, core accepts or refuses each route, and the adapter only writes what the contract assigns to a provider: its instance and Lease, its attachments and their `Ready` condition, and its route claims.

## Setup

The cell must run galactic-controller with `--edge` and the galactic-edge DaemonSet on the provider's node ([deployment](provider-contract.md)). The provider's node also needs a TUN device plugin, and the VPC needs a workload on that node, because an attachment joins the VPC's existing host VRF.

1. Register the provider: an `EdgeProvider` that lists contract version `v1alpha1`, `PacketAccess/v1` and `PrefixReachability/v1`, and names the provider's ServiceAccount. An operator approves it (`status.approved`). galactic-controller then binds the provider role and admission policy to that ServiceAccount.
2. Grant each connector an `EdgeService` in its VPC's namespace. It grants `PacketAccess` and `PrefixReachability`, lists the connector's /96 in `prefixes`, and sets a `clientPool` outside every connector /96. A service that lacks `PrefixReachability` gets an attachment, but core refuses every route on it.
3. Run the provider pod as that ServiceAccount, with a pod-bound token, the downward-API pod name, namespace, UID and node name, a device-plugin TUN, and no host namespace, hostPath, `NET_ADMIN` or BPF access. `tests/edgeconformance/masqueprovider/deploy/` is a worked example.

The adapter's `Authorizer` turns a request's credential and VPC selector into a `Grant`: connector ID, VPC UID and base62 identifier, the `EdgeService` reference, the connector /96, the routes to advertise and an absolute deadline. A grant the adapter cannot use (wrong VPC, no service, not a masked IPv6 /96, already expired) is refused.

## Readiness

The adapter registers its instance at start and admits nothing until it holds the instance's Lease. It prepares a connector on the connector's first request:

1. It requests the pod's attachment to the grant's service (`ea-<pod UID>-<service UID>`), requesting `PacketAccess` only, and verifies the stored object names this pod, instance, provider and service.
2. It waits until core admits the attachment for the grant's VPC on this node and galactic-edge reports it `Programmed` with a packet device. It then opens that device and sets `Ready=True` with reason `Serving`.
3. It claims the connector's route (`er-` and a hash of the VPC UID and /96) and waits until core accepts that claim for this attachment's UID and this Lease's incarnation and epoch.

Only then does the request get its packet path. The request waits up to 30 seconds for these steps (`Config.Prepare`), including any wait behind another request preparing the same attachment or route, and is answered 503 if they do not complete. It fails at once, also with 503, when core refuses the attachment, the attachment is draining, its status names another VPC or node or no packet device, the device cannot be opened, or core refuses the route outright (for example `CapabilityNotGranted`, `PrefixNotGranted` or `PrefixConflict`). On a refusal after the device is known, the attachment reports `Ready=False` with reason `DataPlaneFailed`.

Connectors of one service share its attachment and device. A connector has at most one open request: another request for it is answered 503 before any preparation, and the open request is left in place.

## Forwarding

A request forwards a packet, in either direction, only while its instance Lease is held at the epoch it was admitted under and before the Lease's deadline, before its grant's deadline, and while the request is open. Every second the adapter also checks each attachment and route it uses. It ends the requests on an attachment that is deleted, replaced, draining, no longer programmed or reprogrammed, and the requests on a route whose claim core no longer accepts, whose gate the node closed, or whose claim moved to another attachment. Losing the lease ends every request. A full device drops the packet and counts it instead of ending the request. These checks are in addition to the foundation's: galactic-edge closes a route's gate at the Lease deadline even if the provider stops.

## Drain and shutdown

When core drains an attachment, after its service is deleted or its authority ends, the adapter ends that attachment's requests at its next check and serves no new request on it. Core deletes the attachment after the service's `drainSeconds`.

On shutdown, stop the transports first so every request ends, then call `Shutdown`. It stops admitting, releases each route claim the adapter still holds, deletes its attachments and releases the instance Lease. A replacement can therefore take nothing over while this pod still forwards. Shutdown is bounded by the caller's context; the fixture gives it 20 seconds.

## Cleanup

- When a connector's last request ends, the adapter releases that connector's route claim. Core deletes the route once its attachments are gone.
- An attachment with no request for 30 seconds (`Config.Idle`) is deleted. A reconnect within that time, such as an HTTP/3 to HTTP/2 fallback, reuses it.
- Every delete carries the attachment's UID as a precondition, so a late delete never removes a replacement under the same name.
- Core holds a deleted attachment with its finalizer until the node reports `Released`. A new request for the same service waits for that before requesting a new attachment.
- A process that restarts in the same pod adopts the pod's attachments and reports them `Ready=False` until it serves them again on request. It deletes the unused ones once idle. It restores no forwarding permission from the previous process; each route is claimed again under the Lease it acquires.
- When the pod is deleted without shutdown, core reaps its instance, Lease, attachments and routes ([contract](provider-contract.md)).

`kubectl get edgeattachments,edgeroutes,leases -n <provider namespace>` shows what remains, and [troubleshooting](troubleshooting.md) explains each condition.

## Verification

- `go test ./internal/edge/masque/` runs the adapter's unit tests and, with `KUBEBUILDER_ASSETS` set, `TestAgainstCore`. That test runs the adapter as a provider pod's pod-bound identity against core's attachment and route controllers and the shipped RBAC and admission policies.
- `task verify:masque-conformance`, run from `deploy/containerlab`, runs the fixture in the lab: packet access, isolation, NAT egress, shared-attachment cancellation, maintenance, process restart, partial setup, recreation and teardown. A lab result is not target-platform qualification.
