# Gateway architecture

`galactic-gateway` provides anycast L4 ingress for VPC workloads. Every participating edge node derives the same backend table from Kubernetes resources and uses a stateless XDP program to select a backend. The gateway encapsulates traffic over SRv6; the backend node performs the VIP-to-backend translation and returns replies directly toward the client.

Use [deployment](deployment.md) to install it, [configuration](configuration.md) to look up settings and API behavior, and [packet paths](packet-paths.md) for the full reconciliation and packet-processing sequences.

## Components and ownership

| Component          | Owns                                                                                                                                        |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------------------------- |
| `galactic-gateway` | `NetworkGateway` and `NetworkService` reconciliation, Maglev tables, XDP attachment, per-rule `BGPAdvertisement` objects and gateway status |
| `galactic-router`  | EVPN advertisement through embedded GoBGP, backend `ServiceVIPBinding` creation and programming, backend health probes                      |
| `galactic-cni`     | Backend TC-BPF programs and pinned maps used for VIP translation and tenant forwarding                                                      |
| `galactic-nat`     | Independent NAT66/NAT64 egress sessions; shares XDP through the dispatcher when colocated                                                   |

The gateway and router run as separate pods. The gateway requires a public uplink and a node locator; it does not require a tenant VRF on the gateway itself. The DaemonSet selects `node=edge` and `gateway=enabled`, and the co-located router is independently selected by `galactic=router`. See [node labels](../operations/node-labels.md).

## Control plane

A `NetworkGateway` identifies one node. A `NetworkService` describes the VIPs, protocol, ports, VPC and backend selector. A gateway reconciles the complete set of rules targeting it rather than incrementally patching one rule in isolation. It resolves eligible backends, builds deterministic Maglev tables, programs the engine, and publishes the resulting routes and per-rule conditions.

All gateways advertise a VIP identically through `BGPAdvertisement` resources consumed by their local routers. There is no primary gateway. BGP ECMP chooses a gateway and its table chooses a backend. One rule's invalid input or advertisement failure must not prevent other rules from converging, and a failed publication must not be reported as successful advertisement.

### Backend identity

A backend needs a valid node locator, VPC identity and attachment context. The gateway encodes the backend slot in the uSID; the backend's ingress translation row includes that slot. Gateway and router releases must agree on this map/key contract. A new gateway paired with an older router that has not written slot-aware rows drops the affected flows.

The router owns each backend's `ServiceVIPBinding` and reports `Bound` after programming its rows. IPv4 VIP advertisement is additionally gated on these bindings. See [IPv4 rollout](deployment.md#rolling-out-and-rolling-back-ipv4-vips) before enabling the feature or rolling either backend component back.

## Datapath

The gateway parses supported TCP/UDP packets, looks up the VIP tuple and deterministic backend, encapsulates the original packet toward its SRv6 SID, and forwards through the selected uplink. A packet that is not a gateway VIP remains available to another dispatcher slot or the host stack. The gateway's own XDP path preserves the inner addresses; the backend TC-BPF program translates them to the selected backend and translates replies to the VIP.

IPv4 VIPs use IPv6 backends. The backend sees the IPv4 client's synthesized IPv6 source in `64:ff9b::/96`, so its traffic policy must permit that form and its reply path must route IPv4 after translation. IPv6 extension headers, fragments and ICMP translation limitations are described in [configuration](configuration.md#what-an-ipv4-vip-needs). The public service API admits TCP and UDP only; other transport protocols are not implemented.

The XDP program answers an oversized encapsulation with the applicable Packet Too Big or Fragmentation Needed response. A failed neighbor lookup that the kernel can resolve is handed to the host forwarding path. The [packet-path reference](packet-paths.md) records the exact claim, drop, forwarding and fallback branches.

## XDP ownership and recovery

The shared dispatcher owns the interface hook. Gateway and NAT use separate slots and leases, so one can stop without detaching the other's program. Direct attachment remains an explicit configuration choice. Attach selection, driver mode and bond-member sequencing follow the [host XDP guide](../operations/xdp-attach-mode.md).

<a id="recovery"></a>
### Recovery

Pinned maps and the dispatcher outlive a process. Restart reconciles desired rules, adopts compatible state, and retries attachments; startup must retain the owning handles for as long as the datapath serves. Changes to a bond's members are reconciled after startup. A missing target causes readiness failure while the remaining targets continue serving; a liveness restart is not the repair mechanism for missing coverage.

Map layout changes require an explicit upgrade plan because recreating a pin discards rows written by another component. Existing connections can also move when backend membership or the flow hash changes. [Deployment and upgrades](deployment.md) contains the compatibility procedures.

## Health and failures

Backend nodes perform probes and publish health through their bindings. Gateways consume the same published health state so their tables remain deterministic. Health filtering is opt-in and mixed-version behavior is defined in [backend health](backend-health.md).

A successful engine update, BGP advertisement and backend binding are distinct states. Check all three when a VIP is unreachable. IPv4 readiness, no-backend handling, quotas and per-rule reasons are in [configuration](configuration.md).

## Constraints

- In the gateway namespace, `NetworkService` is an internal API. The publishing platform verifies tenant ownership before writing it; `Accepted=True` is not proof of that authorization. RBAC must restrict other writers.
- In a project namespace (one holding no `NetworkGateway`), the gateway checks ownership itself: a service is accepted (`OwnershipVerified`) only while a `VPC` in that namespace carries its `vpcRef`, is refused (`OwnershipDenied`, `VIPClaimed`) otherwise, and takes backends only from its own namespace. Its `BGPAdvertisement` and `ServiceVIPBinding` objects live in the gateway namespace with a `galactic.datum.net/network-rule-namespace` label and no owner reference. See [Services in a project namespace](configuration.md#services-in-a-project-namespace).
- Backend tenant resolution depends on the deterministic `BGPVRFInstance` name shared by the CNI and router. A naming mismatch refuses the backend rather than selecting one from another tenant.
- An automatically derived encapsulation source is read at startup. Changing the node's locator or node ID requires restarting the gateway.
- The public uplink and each resolved bond member need forwarding sysctls before FIB lookup. An empty bond is a startup error. Missing coverage after startup fails readiness and is retried without detaching working members.
- `edge_return` drops oversized replies without generating ICMP. TCP MSS clamping reduces that risk; large UDP replies and client ICMP do not gain transparent end-to-end PMTU translation.
- An IPv4 VIP must not also be a shard's IPv4 masquerade address: the earlier gateway dispatcher slot would claim that address's NAT64 replies.

## Implementation entry points

- `cmd/galactic-gateway/root.go` starts the manager; `gateway.go` owns datapath lifecycle.
- `internal/controller/networkgateway_controller.go` reconciles rules and publications.
- `internal/gateway` builds and applies engine state.
- `internal/plumbing/ebpf/edgeprog/edgedsr.c` implements the XDP programs.
- `internal/plumbing/ebpf/xdpdispatch` owns shared attachment and leases.

## Testing

`task test:unit` covers pure engine and reconciliation behavior. `task test:unit-root` exercises real BPF/kernel paths, which unprivileged tests skip. The ContainerLab `verify:gateway-ingress` and `verify:gateway-ingress-ipv4` tasks exercise traffic from an off-fabric client through each gateway. These live-lab checks are separate from `task ci`; passing the ordinary pipeline does not qualify a production ingress rollout.
