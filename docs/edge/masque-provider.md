# MASQUE provider adapter

`internal/edge/masque` connects a CONNECT-IP server (`internal/edge/connectip`) to a tenant VPC through the [provider contract](provider-contract.md). It implements `connectip.Admission` and `connectip.PacketBackend`, so every transport uses the same attachment, route and packet checks. It has no command of its own: the service binary that embeds it is a separate deliverable of the [MASQUE connector design](../designs/masque/contract.md). The [grant authority](masque-authority.md) issues its grants, and `authority.Client` is its production `Authorizer`. The conformance fixture in `tests/edgeconformance/masqueprovider` runs it with static test credentials, or with the grant authority when configured.

The adapter never touches host networking. galactic-edge programs and releases each attachment's host state, core accepts or refuses each route, and the adapter only writes what the contract assigns to a provider: its instance and Lease, its attachments and their `Ready` condition, and its route claims.

## Setup

The cell must run galactic-controller with `--edge` and the galactic-edge DaemonSet on the provider's node ([deployment](provider-contract.md)). The provider's node also needs a TUN device plugin, and the VPC needs a workload on that node, because an attachment joins the VPC's existing host VRF.

1. Register the provider: an `EdgeProvider` that lists contract version `v1alpha1`, `PacketAccess/v1` and `PrefixReachability/v1`, and names the provider's ServiceAccount. An operator approves it (`status.approved`). galactic-controller then binds the provider role and admission policy to that ServiceAccount.
2. Grant each connector an `EdgeService` in its VPC's namespace. The [grant authority](masque-authority.md) issues one per connector authorization. It grants `PacketAccess` and `PrefixReachability`, lists the connector's /96 in `prefixes`, and sets a `clientPool` outside every connector /96. A service that lacks `PrefixReachability` gets an attachment, but core refuses every route on it.
3. Run the provider pod as that ServiceAccount, with a pod-bound token, the downward-API pod name, namespace, UID and node name, a device-plugin TUN, and no host namespace, hostPath, `NET_ADMIN` or BPF access. `tests/edgeconformance/masqueprovider/deploy/` is a worked example.

The adapter's `Authorizer` turns a request's credential and VPC selector into a `Grant`: connector ID, VPC UID and base62 identifier, the `EdgeService` reference, the connector /96, the routes to advertise and an absolute deadline. A grant the adapter cannot use (wrong VPC, no service, not a masked IPv6 /96, already expired) is refused. The `Authorizer` also refreshes an open request's grant (`Refresh`) and retires a grant (`Retire`); see [Grant refresh and revocation](#grant-refresh-and-revocation).

## Readiness

The adapter registers its instance at start and admits nothing until it holds the instance's Lease. It prepares a connector on the connector's first request:

1. It requests the pod's attachment to the grant's service (`ea-<pod UID>-<service UID>`), requesting `PacketAccess` only, and verifies the stored object names this pod, instance, provider and service.
2. It waits until core admits the attachment for the grant's VPC on this node and galactic-edge reports it `Programmed` with a packet device. It then opens that device and sets `Ready=True` with reason `Serving`.
3. It claims the connector's route (`er-` and a hash of the VPC UID and /96) and waits until core accepts that claim for this attachment's UID and this Lease's incarnation and epoch.

Only then does the request get its packet path. The request waits up to 30 seconds for these steps (`Config.Prepare`), including any wait behind another request preparing the same attachment or route, and is answered 503 if they do not complete. It fails at once, also with 503, when core refuses the attachment, the attachment is draining, its status names another VPC or node or no packet device, the device cannot be opened, or core refuses the route outright (for example `CapabilityNotGranted`, `PrefixNotGranted` or `PrefixConflict`). On a refusal after the device is known, the attachment reports `Ready=False` with reason `DataPlaneFailed`.

Connectors of one service share its attachment and device.

## Replacing a connector's request

A connector forwards through at most one request. A new request for a connector that already has one open, such as a reconnect or an HTTP/3 to HTTP/2 fallback, replaces it:

1. The new request is authorized and prepared as above while the open request keeps forwarding. When both name the same service, they share its attachment and route claim, so the claim is neither released nor written again.
2. The open request ends. Its packets stop at once, and its transport closes it.
3. The adapter waits up to 1 second for the old request to close: its packet I/O stopped, its device registration and any packets queued for it discarded, and its references dropped. Only then is the new request registered and given its packet path.
4. If the old request does not close within that second, the new request is answered 503 and the adapter retires the connector's grant through `Authorizer.Retire`, so neither request forwards.

A request arriving while another request for the same connector is being admitted is answered 503 and can be retried. Each request carries a new `SessionInfo.ID`. A replaced request's late `Close` releases only its own references and never the claim its successor holds.

A replacement on another provider pod is not done by the adapter. The grant authority retires the old pod's service before granting the new one, and core then moves the route only after the old holder's gate is closed ([MASQUE connector design](../designs/masque/contract.md#cross-instance-replacement-and-stale-cleanup)).

## Forwarding

A request forwards a packet, in either direction, only while its instance Lease is held at the epoch it was admitted under and before the Lease's deadline, before its grant's deadline, and while the request is open. Every second the adapter also checks each attachment and route it uses. It ends the requests on an attachment that is deleted, replaced, draining, no longer programmed or reprogrammed, and the requests on a route whose claim core no longer accepts, whose gate the node closed, or whose claim moved to another attachment. Losing the lease ends every request. A full device drops the packet and counts it instead of ending the request. These checks are in addition to the foundation's: galactic-edge closes a route's gate at the Lease deadline even if the provider stops.

## Packet policy

The CONNECT-IP proxy (`internal/edge/connectip`) checks every packet of a request against the request's grant before forwarding it in either direction. It applies the parsing profile in the [MASQUE connector design](../designs/masque/contract.md#interfaces-and-session-transitions):

- Only complete IPv6 packets pass. The payload length must match the packet, so jumbograms are refused.
- The proxy walks at most 8 extension headers and 256 extension header bytes. Hop-by-Hop must come first.
- Any Fragment header is refused, atomic fragments included, as is a Routing header with segments left, a Mobility, HIP or Shim6 header, or an experimental one.
- A packet toward the gVPC must come from the connector's /96, ICMPv6 errors included, and go to an advertised route.
- A packet toward the client must go to the /96 and come from an advertised route. The one exception is an ICMPv6 error (types 1 to 4), such as Packet Too Big from a gVPC router, that quotes a packet sent from the /96 to a route.
- The Packet Too Big that connect-ip-go builds for a packet the tunnel cannot carry goes through the same checks as the client's own packets.

A grant that routes IPv4 is refused with 503, so the proxy never advertises IPv4. A route change at refresh ends the request ([Grant refresh and revocation](#grant-refresh-and-revocation)). gVPC traffic policy is enforced by the foundation on the attachment, not here.

`galactic_connectip_packets_denied_total{direction, reason}` counts every refused packet. `direction` is `to_vpc` or `to_client`. `reason` is one of these:

- `malformed`
- `ipv4_unsupported`
- `fragment`
- `extension_headers`
- `routing_header`
- `source`
- `destination`
- `no_session`, a device packet for a /96 with no open request. The kernel's own multicast and link-local packets on the device are dropped without being counted

connect-ip-go runs its own address checks first on client packets and drops what it refuses with a log line. Those drops are not counted.

## Grant refresh and revocation

Every 5 seconds (`Config.Refresh`) the adapter calls `Authorizer.Refresh` for each open request, with a 2 second deadline. A refreshed grant with the same connector, VPC, service, /96, routes, authorization and credential revision moves the request's deadline. Any other answer has one of these results:

- Unauthenticated or forbidden: the connector's grant was revoked, retired or rotated, and only that connector's request ends.
- A changed grant: the request ends.
- Any other error, or an answer after the 2 second deadline: the request keeps the deadline it had and ends at it unless a later refresh succeeds.

`Adapter.Revoke(connector)` ends a connector's request at once, for an authority that notifies revocations. Neither path is the backstop. Each connector has its own `EdgeService`, and galactic-edge closes the connector's route gate at that service's `validUntil`, even while other connectors keep the shared instance's Lease renewing.

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
- `task verify:masque-conformance`, run from `deploy/containerlab`, runs the fixture in the lab. Its rows cover:
  - packet access, isolation and NAT egress
  - shared-attachment cancellation, maintenance and process restart
  - same-pod replacement
  - provider stall, agent stall and API partition, each measuring local cutoff and local withdrawal separately
  - partial setup, recreation and single-connector revocation
  - teardown

  The lab cannot read the compute node's tenant routes, so it does not measure remote convergence. A lab result is not target-platform qualification.
