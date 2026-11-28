# Galactic Edge public listener

Status: proposed. Nothing in this design is implemented. It extends the [Galactic Edge Foundation](galactic-edge.md) and reuses the [XDP/DSR gateway](../gateway/architecture.md). The [provider contract](../edge/provider-contract.md) remains the reference for behavior that exists today.

This design follows the [Datum enhancement template](https://github.com/datum-cloud/enhancements/blob/main/enhancements/template/README.md).

- [Summary](#summary)
- [Motivation](#motivation)
- [Proposal](#proposal)
- [Design Details](#design-details)
- [Production Readiness Review Questionnaire](#production-readiness-review-questionnaire)
- [Implementation History](#implementation-history)
- [Drawbacks](#drawbacks)
- [Alternatives](#alternatives)

## Summary

`PublicListener/v1` gives an approved edge provider a public, anycast address on the existing gateway nodes, delivered to the provider's pods through Galactic rather than through Kubernetes Services. The platform authority declares an `EdgeListener` with the public addresses and ports. Core turns it into a gateway-namespace `NetworkService` whose backends are the provider instances' `SocketAccess` attachments in a platform-owned ingress gVPC. The gateway keeps its datapath: Maglev selection, SRv6 delivery to the backend node, address translation on the backend node and direct server return. Each provider instance serves the listener from a socket bound to its pod VRF, so the provider still needs no host privilege.

## Motivation

An edge provider has two sides. Galactic Edge owns the inside: attachments into tenant gVPCs, prefix publication, fencing and policy. The outside, the address clients connect to, has no Galactic contract. The MASQUE provider's Service manifest calls its `ClusterIP` a placeholder that "an overlay exposes", and the only overlays available are Kubernetes mechanisms on the cluster pod network: a `LoadBalancer` Service with the CNI's address pools and BGP, a `NodePort`, or `hostPort`.

Those overlays sit outside everything the Edge foundation guarantees. Their addresses are allocated per site by hand, their reachability is not tied to instance leases or drain, traffic policy does not see them, and the gateway's anycast, Maglev and health machinery does not apply. Each new provider (MASQUE, iroh, tailnet) would repeat the same per-site work.

The gateway already serves public VIPs with anycast and direct server return, but only for backends that are tenant `VPCAttachment`s. A provider pod is not one. This design closes that gap without a second ingress datapath.

### Goals

1. An approved provider can be reached on a public IPv6 and IPv4 address and port, served identically by every gateway node.
2. The public address, ports and the provider allowed to receive them are platform decisions, recorded in one object and validated by core. The provider cannot choose or change them.
3. Instances join and leave the backend set from Edge state (attachment programmed, provider `Ready`, lease valid), within the foundation's existing deadlines.
4. Replies leave by direct server return with the public address as source, exactly as tenant VIP replies do today.
5. The provider keeps the foundation's privilege rule: no host namespace, hostPath, `NET_ADMIN` or BPF access.
6. Listener traffic stays isolated from tenant gVPCs. A listener attachment can reach only its own pod and the public return path.

### Non-Goals

- Allocating public addresses. The authority supplies addresses inside the gateway's configured VIP prefixes, as gateway-namespace services do today.
- DNS publication, certificates and client-facing hostnames.
- Connection-state load balancing or QUIC connection-ID routing. See [Risks](#risks-and-mitigations).
- Public customer APIs for listeners.
- Replacing `NetworkService` for tenant workloads.

## Proposal

### System context

```
                 internet client
                        │  VIP:443 (UDP and TCP), anycast
          ┌─────────────┴─────────────┐
          ▼                           ▼
   gateway node A               gateway node B        galactic-gateway XDP: VIP match, Maglev
          │  outer IPv6 to backend uSID (End.DT46, ingress VRF, slot)
          ▼
   edge node: usid_ingress ── VIP:443 → attachment address:8443 ── ingress VRF ── host veth
                                                                                     │
                                                       provider pod: pod VRF ── listener socket
                                                                                     │
   edge node: usid_egress ◄── attachment address:8443 → VIP:443 ◄────────────────────┘
          │  direct server return, unencapsulated
          ▼
   public uplink → internet client
```

### Core concepts

- **`PublicListener/v1`**: a new capability. A provider lists it in `EdgeProvider.spec.capabilities`. An `EdgeService` grants it. It is never requested on an `EdgeAttachment`. Like `PrefixReachability`, it is exercised through a separate object.
- **Ingress gVPC**: a platform-owned gVPC, one per provider that holds `PublicListener`, created and owned by core in the gateway namespace. It contains only that provider's listener attachments. Nothing routes between it and any tenant gVPC.
- **`EdgeListener`**: written by the platform authority. It names the provider and the `EdgeService` that grants the ingress gVPC, the public addresses, and one or more ports. Core validates it and reports status.
- **Listener attachment**: an ordinary `EdgeAttachment` with `SocketAccess` against the listener's `EdgeService`. Each provider instance creates one per node it serves on. The node agent programs it as today: pod VRF, veth into the ingress gVPC's host VRF, an IPv6 address from the service's `clientPool`.
- **Listener backend**: a listener attachment that is programmed, whose instance lease is valid and whose provider has reported `Ready`. Only listener backends receive new flows.

### Representative provider

MASQUE serves CONNECT-IP on UDP/443 (HTTP/3) and TCP/443 (HTTP/2). With this design:

1. The operator adds `PublicListener/v1` to the `masque` `EdgeProvider`. Approval works as today.
2. Core creates the ingress gVPC `edge-ingress-masque`.
3. The authority writes an `EdgeService` granting `SocketAccess` and `PublicListener` on that gVPC, and an `EdgeListener` with one IPv6 and one IPv4 address from the gateway's VIP prefixes and two ports, `443/UDP → 8443` and `443/TCP → 8443`.
4. Each `masque-provider` instance creates a listener attachment, binds its QUIC and TLS sockets to the pod VRF on the attachment address, port 8443, and reports `Ready`.
5. Clients connect to the VIP. `--authority` becomes the public hostname that resolves to it.

The Kubernetes Service and any `LoadBalancer`, `NodePort` or `hostPort` overlay are no longer needed.

### Risks and Mitigations

| Risk | Mitigation |
| --- | --- |
| Maglev is stateless. A change in the backend set moves about 1/N of flows, which breaks QUIC and TLS connections on the moved flows. | Default affinity is `ClientIPAndProtocol`. Drain removes an instance from new selection only after `drainSeconds`, so providers can send HTTP/3 GOAWAY or HTTP/2 GOAWAY first. Connection-ID routing is a follow-up, not part of v1. |
| An edge node that also runs the gateway can select a backend on itself. The gateway has no qualified local-delivery branch: a node's own locator can match a discard route. | Phase 0 qualifies local delivery on the containerlab gvpc lab. Until it passes, the listener controller excludes backends on nodes that advertise the listener's VIPs, and reports `LocalBackendsExcluded`. |
| The return rewrite needs the listener attachment's host veth in `ifindex_vrf_table`, which the CNI datapath owns today. | The node agent registers the veth through the same datapath interface the CNI uses, never by writing the map directly. Ownership is fixed in Phase 1 before any code lands. |
| A compromised provider could try to originate internet traffic through the listener. | The ingress VRF has no default route and no egress shard. Only replies that match a VIP translation row leave on the public uplink. Anything else is dropped and counted. |
| One provider's listener reaches another provider or a tenant. | One ingress gVPC per provider, no route leaking, and the `PublicService` traffic policy path on the listener attachment. |

## Design Details

### Responsibility split

| Actor | Writes | Never writes |
| --- | --- | --- |
| Operator | `EdgeProvider.spec` (adds `PublicListener/v1`), gateway VIP prefixes | `EdgeListener` |
| Platform authority | `EdgeService` for the ingress gVPC, `EdgeListener.spec` | `NetworkService`, `ServiceVIPBinding` |
| Core (`galactic-controller --role=cell`) | Ingress gVPC, `EdgeListener.status`, the gateway-namespace `NetworkService`, the `/128` advertisement for each listener attachment | `EdgeListener.spec` |
| Node agent (`galactic-edge`) | Listener attachment programming, veth registration with the datapath | Gateway VIP state |
| Gateway (`galactic-gateway`, router) | VIP rules, `ServiceVIPBinding`, VIP advertisements | Edge objects |
| Provider | Listener `EdgeAttachment`, `Ready`, instance and lease | `EdgeListener`, `EdgeService`, `NetworkService` |

### API changes

**Capability enums.** Add `PublicListener` to the enums on `EdgeProvider.spec.capabilities[].name` and `EdgeService.spec.capabilities`, and raise `EdgeService.spec.capabilities` `MaxItems` from 3 to 4. `EdgeAttachment.spec.capabilities` is unchanged. Core's `supportedCapabilities` gains `PublicListener`. Following the contract rule, this adds a name and changes the meaning of no existing version.

**`EdgeListener`** (`galactic.datumapis.com/v1alpha1`, namespaced, in the gateway namespace):

```yaml
apiVersion: galactic.datumapis.com/v1alpha1
kind: EdgeListener
metadata:
  name: masque-public
  namespace: galactic-system
spec:
  providerRef: {name: masque}              # immutable
  serviceRef: {namespace: masque-system, name: masque-ingress}   # grants SocketAccess + PublicListener on the ingress gVPC
  addresses:                               # at most one per family; must fall in the gateway VIP prefixes
    - 2001:db8:100::10
    - 192.0.2.10
  ports:
    - {name: h3, protocol: UDP, port: 443, backendPort: 8443}
    - {name: h2, protocol: TCP, port: 443, backendPort: 8443}
  sessionAffinity: ClientIPAndProtocol     # defaults to ClientIPAndProtocol
  failurePolicy: FailClosed                # withdraw the VIPs when no listener backend exists
status:
  conditions:
    - {type: Accepted, reason: Accepted}            # or ProviderNotApproved, CapabilityNotGranted, AddressOutsidePool, AddressClaimed
    - {type: Programmed, reason: BackendsReady}     # or NoBackends, LocalBackendsExcluded
  backends:
    - {attachment: ea-…, node: edge-1, address: 'fd00:e1::101', serving: true}
```

**`NetworkService`** gains `spec.edgeListenerRef`, mutually exclusive with `backendSelector`. Core sets it on the gateway-namespace service it writes for each `EdgeListener`. Gateways resolve backends from the listener's backends instead of from `VPCAttachment`s. The service's `vpcRef` is the ingress gVPC identifier. Project namespaces cannot set `edgeListenerRef`.

### Ingress gVPC

Core creates one gVPC per provider holding `PublicListener`, named `edge-ingress-<provider>`, in the gateway namespace, with a `/64` from a platform ULA prefix that the operator configures. The gVPC is never exported to tenants and carries no egress policy. Its canonical host VRF exists only on nodes with a listener attachment, using the same mechanism that serves edge attachments on nodes without a local workload.

### Control path

1. Core admits the `EdgeListener`: the provider is approved and lists `PublicListener`, the service grants `SocketAccess` and `PublicListener` on the provider's ingress gVPC, each address falls in a gateway VIP prefix, and no other service claims the address and port.
2. A provider instance creates a listener attachment. Admission, allocation and programming follow the existing attachment state machine.
3. Once the attachment is programmed, core writes a `BGPAdvertisement` for the attachment's `/128` into the ingress VRF with `VRFID` and `End.DT46`, the same shape as edge route publication. This lets the gateway resolve the backend's uSID.
4. Core writes or updates the gateway-namespace `NetworkService` with the listener's addresses, ports, affinity, failure policy and `edgeListenerRef`.
5. Each gateway computes the backend set from listener backends, programs its Maglev table, and writes a `ServiceVIPBinding` for each backend on the backend's node. The router advertises the VIPs once at least one binding is `Bound`.

### Data path

**Request.**

1. The client sends to `VIP:443`. ECMP delivers the packet to any gateway node.
2. Gateway XDP matches `(protocol, port, VIP)`, selects a backend with Maglev, and encapsulates the packet in an outer IPv6 header addressed to the backend node's uSID: the node locator, `End.DT46`, the ingress gVPC's VRF identifier and the backend slot.
3. On the edge node, `usid_ingress` resolves the VRF, strips the outer header, and translates `VIP:443` to `attachment-address:8443` from `vip_xlat_table`.
4. The FIB lookup in the ingress VRF selects the listener attachment's host veth. The packet crosses to the pod VRF and reaches the provider's socket.

For an IPv4 VIP, step 3 also applies the gateway's stateless IPv4-to-IPv6 translation, and the provider sees the client under `64:ff9b::/96`.

**Reply.**

1. The provider replies from `attachment-address:8443`. The pod VRF's default route sends the packet over the veth.
2. `usid_egress` on the host veth finds the veth in `ifindex_vrf_table`, rewrites the source to `VIP:443` (or translates back to IPv4), and sends the packet unencapsulated to the public uplink neighbor.

### Backend eligibility and failure

A listener attachment is a listener backend only while all of these hold:

- the attachment is `Programmed` and not `Draining`;
- the provider has set `Ready` on the attachment;
- the instance lease is valid by the foundation's rules;
- its node is not excluded by the local-delivery rule.

| Event | Effect | Bound |
| --- | --- | --- |
| Provider clears `Ready` | Removed from new selection | One gateway reconcile |
| Attachment starts draining | Removed from new selection after `drainSeconds` | `drainSeconds` (default 30 s) |
| Instance lease expires or the API is unreachable | Node agent removes the attachment, and its binding fails | The foundation's 15.5 s local cutoff |
| Last listener backend leaves | With `FailClosed`, every gateway withdraws the VIPs | The gateway's existing withdrawal path |
| Gateway node fails | ECMP moves flows to the remaining gateways. Maglev selects the same backend there. | Underlay convergence |

Gateway health checks stay available as a second signal. The router's TCP probe from the host link-local address reaches the provider's TCP listener in the pod VRF.

### Policy

Listener attachments use the `PublicService` traffic policy path in both directions, like tenant VIP backends. The ingress VRF has no default route. A packet from a listener attachment that does not match a VIP translation row is dropped and counted under a new reason, `ListenerUnmatchedEgress`.

### Implementation phases

| Phase | Work | Gate |
| --- | --- | --- |
| 0 | On the containerlab gvpc lab, hand-wire a `SocketAccess` attachment as a DSR backend: veth registration, `/128` advertisement, binding. Qualify local and remote delivery. | Bidirectional UDP and TCP to a pod VRF socket through a gateway VIP, for both families, with a backend on a gateway node and on a node that is not a gateway |
| 1 | API: capability enums, `EdgeListener`, `NetworkService.spec.edgeListenerRef`. Fix datapath ownership of veth registration. | API review and CRD validation tests |
| 2 | Core: ingress gVPC, listener admission and status, `/128` publication, `NetworkService` writer | envtest coverage of every status reason |
| 3 | Node agent: veth registration, unmatched-egress drop | Lab packet tests, including negative egress |
| 4 | Gateway: backend resolution from listener backends, eligibility, local-delivery exclusion | Lab failover: drain, lease expiry, API outage, gateway loss |
| 5 | MASQUE: listener attachment, sockets bound to the pod VRF, public `--authority`. Remove the Service overlay in deployment. | An independent client passes HTTP/3 and HTTP/2 through the VIP, IPv6 and IPv4 |

## Production Readiness Review Questionnaire

### Feature Enablement and Rollback

The feature is enabled per provider by listing `PublicListener/v1` and creating an `EdgeListener`. Deleting the `EdgeListener` withdraws the VIPs through the gateway's drain path, then removes the `NetworkService`. Rolling back the controllers leaves `EdgeListener` objects unserved and the VIPs withdrawn. Providers keep working on tenant attachments.

### Rollout, Upgrade and Rollback Planning

Roll out to the staging labs first, with the existing overlay left in place on a different address. Move clients by DNS. Remove the overlay only after the Phase 5 gate passes on staging.

### Monitoring Requirements

- `EdgeListener` conditions `Accepted` and `Programmed`, and per-backend `serving`.
- The gateway's existing per-rule packet, drop and advertisement metrics, labelled with the listener name.
- `galactic_edge_foundation_failures_total` for listener attachment failures.
- A counter for `ListenerUnmatchedEgress`.

### Dependencies

The gateway VIP prefixes must cover the listener addresses. Gateway nodes must run with IPv4 VIPs enabled to serve an IPv4 address. Edge nodes need the canonical host VRF for the ingress gVPC.

### Scalability

Each listener is one `NetworkService` with up to 16 ports and two addresses. Each listener backend costs one `/128` advertisement, one `ServiceVIPBinding` and one Maglev slot per gateway. One ingress gVPC per provider uses one VPC identifier per provider.

### Troubleshooting

| Symptom | Check |
| --- | --- |
| `Accepted=False` | The reason names the failed rule: provider approval, capability grant, address pool or address claim. |
| `Programmed=False, NoBackends` | Listener attachments: `Programmed`, provider `Ready`, lease valid. |
| VIP answers on some gateways only | `ServiceVIPBinding` status on the backend nodes, and the `/128` advertisement in the ingress VRF. |
| Replies are missing | The veth registration on the backend node and `ListenerUnmatchedEgress`. |

## Implementation History

- 2026-11-27: proposed, after a staging test reached MASQUE only through a hand-made `NodePort`.

## Drawbacks

- The design adds a capability, a kind and a `NetworkService` field for a small number of providers.
- Listener backends inherit the gateway's stateless selection, which suits short flows better than long QUIC connections.
- Each provider consumes one VPC identifier and one platform `/64`.

## Alternatives

| Alternative | Why not |
| --- | --- |
| `LoadBalancer` Service with the CNI's address pools and BGP | It works today, but it is outside Galactic: no Edge fencing, policy or drain, per-site manual addressing, and no anycast. |
| `hostPort` on the edge node | The address follows the pod between nodes, it binds a host port against the foundation's privilege rule, and it offers no failover. |
| A new gateway endpoint kind that delivers to any pod address | Direct server return needs a Galactic VRF, a registered host interface and an IPv6 backend. A pod on the cluster pod network has none of these, so the gateway would need a second delivery and return path. |
| Publish a per-instance public prefix through `PrefixReachability` into the underlay | Edge publication is single-owner and fail-closed, which fits per-connector prefixes but not a replicated listener. It would also add a new path from Edge into the underlay. |
| Datum Network Load Balancer | Its routes send traffic only to tenant `NetworkService` ports in the load balancer's project. |
| Reuse a tenant gVPC for the listener | Mixes public ingress with tenant traffic and makes listener isolation depend on per-tenant policy. |
