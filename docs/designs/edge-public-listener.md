# Galactic Edge public listener

Status: proposed, with its open decisions settled. The Phase 0 lab proof is done (see [Phase 0 results](#phase-0-results)), and Phase 1, the API, is implemented: `EdgeListener`, the `PublicListener` capability and `NetworkService.spec.edgeListenerRef` exist, but nothing serves a listener yet. It extends the [Galactic Edge Foundation](galactic-edge.md) and reuses the [XDP/DSR gateway](../gateway/architecture.md). The [provider contract](../edge/provider-contract.md) remains the reference for behavior that exists today.

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

`PublicListener/v1` gives an approved edge provider a public address in its cell, advertised by that cell's gateway nodes and delivered to the provider's pods through Galactic rather than through Kubernetes Services. The platform authority declares an `EdgeListener` with the public addresses and ports. Core turns it into gateway-namespace `NetworkService`s, one per port, whose backends are the provider instances' `SocketAccess` attachments in a platform-owned ingress gVPC. The gateway keeps its datapath: Maglev selection, SRv6 delivery to the backend node, address translation on the backend node and direct server return. Each provider instance serves the listener from a socket bound to its pod VRF, so the provider still needs no host privilege.

## Motivation

An edge provider has two sides. Galactic Edge owns the inside: attachments into tenant gVPCs, prefix publication, fencing and policy. The outside, the address clients connect to, has no Galactic contract. The MASQUE provider's Service manifest calls its `ClusterIP` a placeholder that "an overlay exposes", and the only overlays available are Kubernetes mechanisms on the cluster pod network: a `LoadBalancer` Service with the CNI's address pools and BGP, a `NodePort`, or `hostPort`.

Those overlays sit outside everything the Edge foundation guarantees. Their addresses are allocated per site by hand, their reachability is not tied to instance leases or drain, traffic policy does not see them, and the gateway's multi-node advertisement, Maglev and health machinery does not apply. Each new provider (MASQUE, iroh, tailnet) would repeat the same per-site work.

The gateway already serves public VIPs from every gateway node in a cell, with direct server return, but only for backends that are tenant `VPCAttachment`s. A provider pod is not one. This design closes that gap without a second ingress datapath.

### Goals

1. An approved provider can be reached on a public IPv6 and IPv4 address and port that belongs to one cell and is served identically by every gateway node in that cell.
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
                        │  VIP:443 (UDP and TCP), advertised by every gateway node in the cell
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
   node uplink → internet client
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
| An edge node that also runs the gateway can select a backend on itself. The gateway has no local-delivery branch: its FIB lookup of a backend uSID on its own node meets the discard route for the node's locator. | Phase 0 showed every such flow dropped as `fib_unreachable`. The listener controller excludes backends on nodes that advertise the listener's VIPs, and reports `LocalBackendsExcluded`, until the gateway gains a local-delivery branch. |
| The return rewrite needs the listener attachment's host veth in `ifindex_vrf_table` with `usid_egress` attached. | The node agent already does this for every edge attachment, and Phase 0 showed `usid_egress` applying the VIP reverse translation on an edge host link for both families. See [Decisions](#decisions). |
| A client reaches a cell that does not hold its grant. | A listener's addresses belong to one cell. Each cell's gateway VIP prefixes are disjoint from every other cell's, and core refuses an address outside its own prefixes. |
| A compromised provider could try to originate internet traffic through the listener. | The ingress VRF has no default route and no egress shard. Only replies that match a VIP translation row leave through the node's uplink. Anything else is dropped and counted. |
| One provider's listener reaches another provider or a tenant. | One ingress gVPC per provider, no route leaking, and the `PublicService` traffic policy path on the listener attachment. |

## Design Details

### Decisions

These were open when the design was proposed and were settled in [#1506](https://github.com/datum-cloud/galactic/issues/1506).

| Question | Decision | Reason |
| --- | --- | --- |
| Who supplies listener addresses | The platform authority, from the cell's gateway VIP prefixes. Core refuses any other address with `AddressOutsidePool`. | This is how gateway-namespace services get addresses today. An allocator can follow later without an API change. |
| How many ingress gVPCs exist | One per provider type, not one per listener | It isolates providers from each other at the cost of one VPC identifier each. A provider has one listener, so a gVPC per listener adds no isolation. |
| Who registers a listener attachment's host veth in `ifindex_vrf_table` | No new component. The node agent (`galactic-edge`) already registers every edge host link through `attachreg.RegisterHostLink`, which writes the `ifindex_vrf_table` row, sets the veth egress kind and attaches `usid_egress`. | The registration a listener needs exists today, and Phase 0 showed the VIP reverse translation working on an edge host link. |
| What happens to a backend on a node that also advertises the VIP | It is excluded, and the listener reports `LocalBackendsExcluded`. Phase 0 showed local delivery failing, so the exclusion stays until the gateway can deliver to its own node. | Excluding those backends keeps the rest of the work unblocked. |

A listener's addresses belong to one cell. Grants are scoped to one cell, so an address announced from two cells would send some clients to a cell that cannot authorize them. Core in one cell cannot see other cells' addresses, so address planning enforces the rule: each cell's gateway VIP prefixes are disjoint from every other cell's.

### Responsibility split

| Actor | Writes | Never writes |
| --- | --- | --- |
| Operator | `EdgeProvider.spec` (adds `PublicListener/v1`), gateway VIP prefixes | `EdgeListener` |
| Platform authority | `EdgeService` for the ingress gVPC, `EdgeListener.spec` | `NetworkService`, `ServiceVIPBinding` |
| Core (`galactic-controller --role=cell`) | Ingress gVPC, `EdgeListener.status`, one gateway-namespace `NetworkService` per listener port, the `/128` advertisement for each listener attachment | `EdgeListener.spec` |
| Node agent (`galactic-edge`) | Listener attachment programming and host link registration, as for every edge attachment | Gateway VIP state |
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
  serviceRef: {namespace: galactic-system, name: masque-ingress}  # in the ingress gVPC's namespace; grants SocketAccess + PublicListener
  addresses:                               # at most one per family; must fall in the gateway VIP prefixes
    - 2001:db8:100::10
    - 192.0.2.10
  ports:
    - {name: h3, protocol: UDP, port: 443, backendPort: 8443}
    - {name: h2, protocol: TCP, port: 443, backendPort: 8443}
  healthPort: 8443                         # TCP backend port probed for health; defaults to the first TCP backendPort, required when every port is UDP
  sessionAffinity: ClientIPAndProtocol     # defaults to ClientIPAndProtocol
  failurePolicy: FailClosed                # copied into each NetworkService's healthCheck
status:
  conditions:
    - {type: Accepted, reason: Accepted}            # or ProviderNotApproved, CapabilityNotGranted, AddressOutsidePool, AddressClaimed
    - {type: Programmed, reason: BackendsReady}     # or NoBackends, LocalBackendsExcluded
  backends:
    - {attachment: ea-…, node: edge-1, address: 'fd00:e1::101', serving: true}
```

**`NetworkService`** gains `spec.edgeListenerRef`. A `NetworkService` serves one protocol and port, so core writes one gateway-namespace service per listener port, each with `edgeListenerRef` set and the port's `protocol`, `port` and `backendPort`. Gateways resolve backends from the listener's backends instead of from `VPCAttachment`s. The service's `vpcRef` is the ingress gVPC identifier. Project namespaces cannot set `edgeListenerRef`.

`backendSelector` is required today, with a rule that it is not empty. The change makes exactly one of `backendSelector` and `edgeListenerRef` required, and keeps the non-empty rule for `backendSelector` when it is set.

Draft PR #845 ("Allow NLB backends by address within a VPC") also changes this rule: it makes `backendSelector` optional and adds `backendAddresses`, so a service needs a non-empty selector or an address list. The two changes stay compatible, because `edgeListenerRef` selects backends from an `EdgeListener` while #845 selects `VPCAttachment`s within a VPC, and a service uses one model or the other. Whichever change lands second reconciles the validation, so that exactly one of the selector-or-address model and `edgeListenerRef` is required.

`NetworkService` has a failure policy only inside `spec.healthCheck`, where the default is `FailOpen`. Core therefore sets `spec.healthCheck` on every listener service, with the listener's `failurePolicy` and a TCP probe on `healthPort`. `healthPort` defaults to the first TCP `backendPort`, and the API refuses a listener whose ports are all UDP unless it sets `healthPort`.

### Ingress gVPC

Core creates one gVPC per provider holding `PublicListener`, named `edge-ingress-<provider>`, in the gateway namespace, with a `/64` from a platform ULA prefix that the operator configures. The gVPC is never exported to tenants and carries no egress policy. Its canonical host VRF exists only on nodes with a listener attachment, using the same mechanism that serves edge attachments on nodes without a local workload.

### Control path

1. Core admits the `EdgeListener`: the provider is approved and lists `PublicListener`, the service grants `SocketAccess` and `PublicListener` on the provider's ingress gVPC, each address falls in one of this cell's gateway VIP prefixes, and no other service claims the address and port.
2. A provider instance creates a listener attachment. Admission, allocation and programming follow the existing attachment state machine.
3. Once the attachment is programmed, core writes a `BGPAdvertisement` for the attachment's `/128` into the ingress VRF with `VRFID` and `End.DT46`, the same shape as edge route publication. This lets the gateway resolve the backend's uSID.
4. Core writes or updates one gateway-namespace `NetworkService` per listener port, each with the listener's addresses, the port, affinity, health check and `edgeListenerRef`.
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
2. `usid_egress` on the host veth finds the veth in `ifindex_vrf_table`, rewrites the source to `VIP:443` (or translates back to IPv4), and sends the packet unencapsulated to the node's uplink neighbor, exactly as for tenant VIP replies. Where that neighbor is a fabric router, the site's routing carries the reply to the client, so the listener's edge nodes need an uplink path back to the internet.

### Backend eligibility and failure

A listener attachment is a listener backend only while all of these hold:

- the attachment is `Programmed`, and if it is `Draining`, its drain deadline has not passed;
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

Every listener service also carries a gateway health check, as a second signal beside Edge state. The router probes `healthPort` over TCP from the host link-local address, so each provider instance needs a TCP listener on that port in its pod VRF.

### Policy

Listener attachments use the `PublicService` traffic policy path in both directions, like tenant VIP backends. The ingress VRF has no default route. A packet from a listener attachment that does not match a VIP translation row is dropped and counted under a new reason, `ListenerUnmatchedEgress`.

### Implementation phases

| Phase | Work | Gate |
| --- | --- | --- |
| 0 | On the containerlab gvpc lab, hand-wire a `SocketAccess` attachment as a DSR backend: `/128` advertisement and binding, relying on the existing host link registration. Confirm the VIP reply translation on the edge host link, and qualify local and remote delivery. | Bidirectional UDP and TCP to a pod VRF socket through a gateway VIP, for both families, when the backend is not on the receiving gateway's node; local delivery's outcome recorded. Done, see [Phase 0 results](#phase-0-results). |
| 1 | API: capability enums, `EdgeListener`, `NetworkService.spec.edgeListenerRef` and its rule against `backendSelector` | API review and CRD validation tests |
| 2 | Core: ingress gVPC, listener admission and status, `/128` publication, `NetworkService` writer | envtest coverage of every status reason |
| 3 | Node agent and datapath: unmatched-egress drop. Phase 0 found no gap in VIP reply translation on edge host links. | Lab packet tests, including negative egress |
| 4 | Gateway: backend resolution from listener backends, eligibility, local-delivery exclusion | Lab failover: drain, lease expiry, API outage, gateway loss |
| 5 | MASQUE: listener attachment, sockets bound to the pod VRF, public `--authority`. Remove the Service overlay in deployment. | An independent client passes HTTP/3 and HTTP/2 through the VIP, IPv6 and IPv4 |

### Phase 0 results

Run on 2026-11-28 on the containerlab gvpc lab by `task verify:edge-listener` (`TestListenerBackend` in `tests/edgeconformance`), for [#1507](https://github.com/datum-cloud/galactic/issues/1507). The test wires one backend by hand, with no controller change:

1. A dedicated ingress VPC under the lab's `public-service` traffic policy, granted to the reference provider with `SocketAccess` only. The provider serves UDP and TCP echo from a socket bound to its pod VRF.
2. A stand-in `VPCAttachment` naming the edge attachment's address and node, because the gateway and `galactic-router` select backends from `VPCAttachment`s.
3. The attachment's `/128` `BGPAdvertisement` in the ingress VRF, with `VRFID` and `End.DT46`.
4. One gateway-namespace `NetworkService` per protocol, each with an IPv6 and an IPv4 VIP and no health check.

`galactic-router` on the backend's node bound all four VIP and protocol pairs. The off-fabric client then sent eight flows per protocol and family, with the VIP pinned on the transit router to one gateway at a time.

| Case | Result |
| --- | --- |
| Remote delivery: the VIP pinned to the gateway that does not hold the backend | Every UDP and TCP flow answered, over IPv6 and IPv4. Replies came from the VIP. The backend saw the IPv6 client's own address, and the IPv4 client under `64:ff9b::/96`. |
| Local delivery: the VIP pinned to the backend's own node | No flow answered. The gateway matched every packet and dropped each one as `fib_unreachable`. |

What this settles:

- `RegisterHostLink` and `usid_egress` already carry listener replies, including the IPv4 translation. Phase 3 needs no reply-translation work.
- The gateway cannot deliver to a backend on its own node, so the `LocalBackendsExcluded` exclusion is required, not precautionary.

Limits of the proof:

- Every edge node in the lab also runs a gateway. The proof's "node that is not a gateway" is therefore a node that is not the gateway the packet arrives on. The receiving gateway's datapath is the same either way.
- The stand-in attachment has no `hostInterface`, so the gateway health check was not exercised. Phase 4 covers it.

## Production Readiness Review Questionnaire

### Feature Enablement and Rollback

The feature is enabled per provider by listing `PublicListener/v1` and creating an `EdgeListener`. Deleting the `EdgeListener` withdraws the VIPs through the gateway's drain path, then removes the listener's `NetworkService`s. Rolling back the controllers leaves `EdgeListener` objects unserved and the VIPs withdrawn. Providers keep working on tenant attachments.

### Rollout, Upgrade and Rollback Planning

Roll out to the staging labs first, with the existing overlay left in place on a different address. Move clients by DNS. Remove the overlay only after the Phase 5 gate passes on staging.

### Monitoring Requirements

- `EdgeListener` conditions `Accepted` and `Programmed`, and per-backend `serving`.
- The gateway's existing per-rule packet, drop and advertisement metrics, labelled with the listener name.
- `galactic_edge_foundation_failures_total` for listener attachment failures.
- A counter for `ListenerUnmatchedEgress`.

### Dependencies

The gateway VIP prefixes must cover the listener addresses. Gateway nodes must run with IPv4 VIPs enabled to serve an IPv4 address. Edge nodes need the canonical host VRF for the ingress gVPC, and an uplink path that carries VIP-sourced replies to the internet.

### Scalability

Each listener has up to 16 ports and two addresses, and each port is one `NetworkService`. Each listener backend costs one `/128` advertisement, one `ServiceVIPBinding` and one Maglev slot per gateway. One ingress gVPC per provider uses one VPC identifier per provider.

### Troubleshooting

| Symptom | Check |
| --- | --- |
| `Accepted=False` | The reason names the failed rule: provider approval, capability grant, address pool or address claim. |
| `Programmed=False, NoBackends` | Listener attachments: `Programmed`, provider `Ready`, lease valid. |
| VIP answers on some gateways only | `ServiceVIPBinding` status on the backend nodes, and the `/128` advertisement in the ingress VRF. |
| Replies are missing | The host link's `ifindex_vrf_table` row and `usid_egress` attachment on the backend node, the VIP translation rows, and `ListenerUnmatchedEgress`. |

## Implementation History

- 2026-11-27: proposed, after a staging test reached MASQUE only through a hand-made `NodePort`.
- 2026-11-28: open decisions settled in [#1506](https://github.com/datum-cloud/galactic/issues/1506), and listener addresses scoped to one cell.
- 2026-11-28: Phase 0 proved remote delivery and the reply path, and showed local delivery failing ([#1507](https://github.com/datum-cloud/galactic/issues/1507)).

## Drawbacks

- The design adds a capability, a kind and a `NetworkService` field for a small number of providers.
- Listener backends inherit the gateway's stateless selection, which suits short flows better than long QUIC connections.
- Each provider consumes one VPC identifier and one platform `/64`.

## Alternatives

| Alternative | Why not |
| --- | --- |
| `LoadBalancer` Service with the CNI's address pools and BGP | It works today, but it is outside Galactic: no Edge fencing, policy or drain, per-site manual addressing, and no failover across gateway nodes. |
| `hostPort` on the edge node | The address follows the pod between nodes, it binds a host port against the foundation's privilege rule, and it offers no failover. |
| A new gateway endpoint kind that delivers to any pod address | Direct server return needs a Galactic VRF, a registered host interface and an IPv6 backend. A pod on the cluster pod network has none of these, so the gateway would need a second delivery and return path. |
| Publish a per-instance public prefix through `PrefixReachability` into the underlay | Edge publication is single-owner and fail-closed, which fits per-connector prefixes but not a replicated listener. It would also add a new path from Edge into the underlay. |
| Datum Network Load Balancer | Its routes send traffic only to tenant `NetworkService` ports in the load balancer's project. |
| Reuse a tenant gVPC for the listener | Mixes public ingress with tenant traffic and makes listener isolation depend on per-tenant policy. |
| Announce one listener address from several cells | Grants are scoped to one cell, so a client routed to another cell is refused. Sharing an address would first need grants that every cell can authorize. |
