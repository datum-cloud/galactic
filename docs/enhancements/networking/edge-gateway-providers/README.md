---
status: provisional
stage: alpha
latest-milestone: "TBD"
---

# Edge gateway providers

- [Summary](#summary)
- [Motivation](#motivation)
  - [Goals](#goals)
  - [Non-goals](#non-goals)
- [Proposal](#proposal)
  - [Capabilities](#capabilities)
  - [Risks and mitigations](#risks-and-mitigations)
- [Design details](#design-details)
  - [Host-owned attachments](#host-owned-attachments)
  - [Node-local write authority](#node-local-write-authority)
  - [Forwarding claims](#forwarding-claims)
  - [Expiry and withdrawal bounds](#expiry-and-withdrawal-bounds)
  - [Resource model](#resource-model)
  - [Provider contract](#provider-contract)
  - [Traffic policy](#traffic-policy)
  - [Connectivity protocols](#connectivity-protocols)
  - [Tenant BGP peering](#tenant-bgp-peering)
  - [Tailnet gateways](#tailnet-gateways)
  - [Numeric limits](#numeric-limits)
  - [Test environments and evidence](#test-environments-and-evidence)
- [Rollout](#rollout)
- [Alternatives](#alternatives)

## Summary

Several tenant-facing gateway services must share each edge node with the
services already there: Envoy with its galactic-vrf sidecar, the XDP load
balancer (galactic-gateway), the egress NAT shards (galactic-nat) and the iroh
application proxy. The new services are galactic-connect, which terminates
native MASQUE CONNECT-IP and a separate iroh packet service; galactic-peering,
which runs tenant BGP sessions; and galactic-tailnet, which joins a VPC to a
tenant's tailnet.

This proposal defines one platform those services plug into as independently
packaged providers. The platform owns everything shared on the node: the
canonical VPC VRFs and SIDs, the shared eBPF maps, the effective routes and
the authority to forward. Providers own their protocols. A provider that only
composes existing capabilities installs through its own package and
registration, without any change to galactic's controllers, CNI, router or
datapath.

## Motivation

The ingress sidecar today registers pod-namespace table IDs and interface
indexes in the node's shared maps under a reserved Block, derives one return
address per node and VPC, and prunes by uSID Argument. That model cannot
represent two pods on one node serving the same VPC, and every new service
would have to copy it. Several independent processes also write the same
datapath state (CNI plugins, the installer's refresh and repair, garbage
collection, galactic-router) with no shared fencing, so a delayed write can
undo a newer one. Service traffic also needs authority that ends on its own
when a provider is partitioned or dies, which advertisements do not have
today.

### Goals

- One host-owned attachment contract for socket consumers (Envoy, tenant BGP)
  and packet consumers (connect, tailnet), with only host identifiers in
  shared state.
- Every write to shared datapath state fenced by one node-local authority.
- Forwarding authority with a finite, locally enforced lifetime and a
  replacement that never overlaps the old owner.
- A versioned, language-neutral provider API, so a provider for an existing
  capability needs no core change.
- Routed IPv6 between tenant sites or clients and authorized VPC workloads,
  with identical addresses allowed in different VPCs.

### Non-goals

- IPv4 site access, prefix translation and NAT for gateway services. They are
  separate capabilities with their own design.
- Unrestricted internet egress or exit-node behavior through a gateway
  service.
- Active-active ownership of one connector.
- CONNECT-UDP in the first release (see [Connectivity
  protocols](#connectivity-protocols)).

## Proposal

### Capabilities

A service requests a capability, never raw host networking.

| Consumer             | Capability                       | Consumer owns                                            | Platform provides                                        |
| -------------------- | -------------------------------- | -------------------------------------------------------- | -------------------------------------------------------- |
| Envoy / galactic-vrf | Socket access                    | Listeners, upstream policy, VRF-bound sockets            | Pod VRF and a veth into the canonical host VRF           |
| galactic-connect     | Packet access                    | HTTP/3, admission, session policy, TUN I/O               | Pod VRF, veth, TUN, assigned addresses and prefix grants |
| galactic-peering     | Socket access and route exchange | Peers, per-VPC RIBs, import and export policy            | Socket attachment plus separately authorized claims      |
| galactic-tailnet     | Packet access and route exchange | Enrollment, tunnel transport, peer policy, subnet export | Binding namespace, pod VRF, tunnel device, prefix claims |
| galactic-gateway     | Backend forwarding               | VIP selection, XDP DSR                                   | Authorized VPC and backend references                    |
| galactic-nat         | Egress relationship              | Session state, shard selection, translation              | Authorized VPC and shard relationship                    |

The load balancer and NAT keep their own datapaths. Nothing is forced through
a TUN, and protocol code never runs in the shared controllers.

### Risks and mitigations

| Risk                                                                     | Mitigation                                                                                                         |
| ------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------ |
| A stale writer overwrites a replacement's routes or maps                 | Every writer commits through the node-local authority; a stale generation or revision is refused                   |
| A partitioned provider keeps forwarding after replacement                | Locally enforced lease deadlines; takeover waits out the drift-stretched duration                                  |
| Shared maps fill up                                                      | Admission reserves capacity per attachment before allocating; [numeric limits](#numeric-limits) hold back headroom |
| A provider widens its own authority                                      | Registration describes capability only; admission intersects operator approval, grants and capacity                |
| A tenant packet misses state and leaves through the pod's own interfaces | Pod VRF unreachable default; missing host state fails inside the canonical VRF                                     |

## Design details

### Host-owned attachments

A node-local provisioner attaches one pod to one VPC:

1. Verify the pod's network namespace. The provisioner works through a handle
   to the namespace and checks it against its path before and after every
   change, so a sandbox replaced mid-provisioning is refused, and no change
   can land in its replacement.
2. Create a veth pair from inside the pod. The pod end joins a VRF in the pod;
   the host end joins the VPC's canonical host VRF, the one ordinary workloads
   use. The host link carries the attachment's ID as its alias, and nothing
   changes or deletes a link carrying another ID.
3. Route the attachment's address, and every prefix it serves, in the host
   table to that address on the host link, with one permanent neighbor entry,
   so a site prefix never triggers neighbor discovery per destination.
4. Route the pod VRF's default to the host link's link-local address, with an
   unreachable default behind it, so a pod packet that misses fails inside the
   VRF and never leaves through the pod's `eth0`.
5. For packet access, create a TUN in the pod VRF that the served prefixes
   route to, owned by the consuming process's user and group.
6. Read everything back, including the kernel's local route for the
   attachment address, before reporting it programmed.

The host link is registered with the uSID datapath exactly like a workload's,
through `attachreg.RegisterDatapath`, by host ifindex and canonical table
only. Pod-local table IDs and interface indexes may equal any other pod's.
Envoy keeps binding its sockets to `G<vpc>V`: the pod VRF carries that name.

**MTU.** Both ends of an attachment carry the fabric's tenant MTU, the largest
packet any tenant interface can send. A packet the datapath decapsulates
therefore always fits the host link. This matters because the decapsulation
path drops a packet that does not fit its egress link without sending Packet
Too Big. A narrower limit further in, such as a TUN whose session carries less,
is set on that device, and the pod's own forwarding answers larger packets
with Packet Too Big.

### Node-local write authority

`internal/edge/ownership` serializes and fences every write to one scope of
shared datapath state, one VPC's canonical table and SID on one node, across
all the processes that write it.

```text
writer:     Begin ──► prepare (no lock) ──► Commit(ticket, mutate)
authority:                                  flock(scope) ─► check owner, generation, revision
                                                         ─► mark pending ─► mutate ─► revision++
```

The scope's record (owner, generation, revision, pending) is durable and lives
next to a lock file every writer opens. A commit runs its kernel or map
mutation while holding the lock, so checking the ticket and writing are one
step. A ticket issued before another commit, before a transfer, or to a writer
that no longer owns the scope is refused. This is what stops a paused writer,
a retry, or a refresh built from an old snapshot from undoing newer state.

Ownership moves through a barrier:

1. `Fence` marks the scope transitioning and advances the generation. It
   returns only after any commit in progress finishes, and from then on every
   outstanding ticket is refused.
2. The new owner reads the complete inventory and prepares its desired state.
3. `Adopt` names the new owner. Its first commit must be a snapshot commit
   that reconciles the complete state; incremental commits are refused until
   then.
4. The new owner validates forwarding and drains only what it proved
   unreferenced.

Handback uses the same barrier in the other direction. A mutation that fails,
or whose process dies, leaves the scope requiring a snapshot commit, because a
partly applied change cannot be assumed done or undone.

Every existing writer must commit through the authority before any scope is
adopted:

| Writer                                                        | Writes                                                      |
| ------------------------------------------------------------- | ----------------------------------------------------------- |
| `attachreg.RegisterDatapath` (CNI ADD)                        | vrf_table, ifindex maps, egress kinds, pass-through routes  |
| `installer` sidecar return path                               | Return tables and routes                                    |
| `installer` egress group refresh (`EgressRouteTable.Refresh`) | egress_route_table bulk refresh                             |
| `attachreg` fill                                              | vrf_table and shard routes                                  |
| `gc` sweep and datapath repair                                | Deletion and repair of attachments, VRFs and map rows       |
| `runtime/gobgp` VRF route installation and retries            | Learned EVPN routes in egress_route_table and kernel tables |
| Ingress sidecar (until replaced by host attachments)          | Synthetic map rows under the reserved Block                 |

Until all of them do, adoption stays disabled.

### Forwarding claims

A forwarding claim is the authority one service instance holds to forward for
one attachment. `internal/edge/claim` implements its lease.

- **Store.** The cell's Kubernetes API, using compare-and-swap on
  `resourceVersion`. A claim never spans cells: an attachment is placed in
  exactly one cell, and federation carries only desired state.
- **Liveness.** Each service instance renews one lease for itself, not one per
  attachment. A claim names its holder instance and epoch and is written only
  on acquisition, release and takeover, and is valid only while the holder's
  lease is.
- **Renewal.** Each renewal grants `Duration` on the holder's own monotonic
  clock, measured from just before the request was sent, so a slow write only
  shortens validity.
- **Takeover.** A replacement takes over when the holder released the lease
  after it stopped forwarding, or after observing the lease unchanged for
  `TakeoverWait = Duration × (1 + MaxDrift) / (1 − MaxDrift) + Margin` on its
  own monotonic clock. The takeover is a compare-and-swap on the observed
  version that advances the epoch.
- **Assumption.** Only clock-rate drift between nodes is bounded. Wall clocks
  are not assumed synchronized; wall time is used only to cap a deadline at an
  authorization ceiling, such as a credential expiry, minus `MaxSkew`.
- **Restart.** A restarted instance cannot revive authority from state it did
  not renew. A release or renewal from an old epoch changes nothing.

A pod recreated on the same node gets a new instance identity and a new
epoch. Moving a claim between cells requires release in the old cell,
observed through the attachment's federated status, or `TakeoverWait` from the
last observed change of that status.

### Expiry and withdrawal bounds

Three bounds are kept separate:

| Bound                          | Enforced by                                                                                           | Holds while                               |
| ------------------------------ | ----------------------------------------------------------------------------------------------------- | ----------------------------------------- |
| Local packet expiry            | The datapath, which drops the attachment's traffic once its kernel-monotonic deadline passes          | The provider process is stopped or hung   |
| Local advertisement withdrawal | galactic-router, which withdraws a service advertisement whose claim deadline passed on applied state | The API and the publisher are unreachable |
| Remote convergence             | BGP withdrawal propagation                                                                            | The underlay and route reflectors are up  |

Local packet expiry reuses the private-service datapath's pattern
(`serviceroutemap.authorizationDeadline`): the deadline is converted to the
kernel's monotonic clock when written, checked with `bpf_ktime_get_boot_ns`,
and a replay of the same lease never extends it. galactic-router schedules
withdrawal from the deadline it applied, independent of watch progress, and a
restarted router revalidates every claim before advertising it.

### Resource model

All resources are in `galactic.datumapis.com/v1alpha1`.

| Kind                   | Scope     | Written by                                          | Purpose                                                  |
| ---------------------- | --------- | --------------------------------------------------- | -------------------------------------------------------- |
| `GatewayProvider`      | Cluster   | Operator                                            | Registration: identity, contract versions, capabilities  |
| `GatewayService`       | Namespace | Tenant control plane                                | Binds a provider version to a VPC with grants and config |
| `VPCServiceAttachment` | Namespace | galactic-controller (spec), node authority (status) | One admitted capability for one instance and pod         |
| `ForwardingClaim`      | Namespace | Provider instance                                   | Holder instance and epoch for one attachment             |
| `RouteCandidate`       | Namespace | Provider instance                                   | A prefix the provider asks to publish, with provenance   |

```yaml
apiVersion: galactic.datumapis.com/v1alpha1
kind: GatewayProvider
metadata:
  name: connect-ip
spec:
  contractVersions: ["v1alpha1"]
  capabilities:
    - name: PacketAccess
      version: v1
  configuration:
    group: connect.galactic.datumapis.com
    kind: ConnectIPConfig
  runtime:
    image: ghcr.io/datum-cloud/galactic-connect@sha256:<digest>
    serviceAccount: galactic-connect
    privilegeProfile: packet-access
status:
  approved: true # written by the operator's approval flow, never the provider
---
apiVersion: galactic.datumapis.com/v1alpha1
kind: GatewayService
metadata:
  name: office-sites
  namespace: tenant-a
spec:
  providerRef: {name: connect-ip}
  contractVersion: v1alpha1
  vpcRef: {name: prod, uid: 6b0f…}
  capabilities: [PacketAccess]
  grants:
    sitePrefixes: ["fd00:5::/48"]
    clientPool: "fd00:c0::/64"
  trafficPolicyBindingRef: {name: office-sites}
  configRef: {kind: ConnectIPConfig, name: office-sites}
```

Rules:

- `GatewayService` references are immutable: provider, VPC UID, capabilities.
  Changing them means a new service.
- `VPCServiceAttachment` is created by galactic-controller per admitted
  instance and pod, with immutable consumer, pod, node and VPC references. Its
  status separates conditions written by the node authority (`Admitted`,
  `Allocated`, `Programmed`) from those written by the provider (`Ready`), and
  only galactic-controller combines them into `Published`.
- A provider may write only its own claims and candidates, and never chooses a
  host table, ifindex or next hop.
- Finalizers keep allocation references until the node authority confirms
  cleanup, but datapath correctness never depends on finalizer completion:
  claims expire on their own.
- Each attachment is a traffic-policy subject the same way a `VPCAttachment`
  is: `TrafficPolicyBinding` resolves by name, and the node authority writes
  the attachment's host link into the policy maps with its own token.
- `ConnectorAttachment`, from the Datum Connectors proposal, is control-plane
  intent from a connector to a VPC. It maps onto a `GatewayService` and the
  claims it admits; it does not own datapath state.

### Provider contract

- **Registration.** A `GatewayProvider` binds an approved image digest to an
  identity, contract versions and capability versions. Registration never runs
  supplied code and grants no tenant authority.
- **Admission.** galactic-controller admits a `GatewayService` only if the
  provider is approved, supports the requested contract and capability
  versions, and the tenant holds the grants. An unknown provider, an
  unsupported version or invalid provider configuration fails before any host
  resource is allocated, with a condition naming the reason.
- **Configuration.** Each provider owns its configuration CRDs and their
  validation. Core resources hold only a typed reference and the accepted
  configuration's UID and generation, so a new provider adds no core field or
  enum.
- **Privilege.** A provider's pods get a privilege profile the operator
  approved for its capabilities. Changing its manifest cannot add privilege.
- **Kit.** Schemas, generated clients, a provider template, sample deployment
  and RBAC, a fake core and packet backend, and a conformance suite are
  published together.
- **Extension target.** Starting from the template and an existing packet or
  socket runtime, adding a provider takes at most two engineer-days to an
  installed provider passing baseline conformance, with no change to core
  source, schema, image or deployment. Elapsed effort is recorded each time it
  is measured.

### Traffic policy

Attachment host links are tenant interfaces to the traffic policy datapath:
each gets a `tp_iface_table` row with a policy token for its interface
lifetime, `tp_deliver` on the host link, and a compiled snapshot per direction
bound from its `TrafficPolicyBinding`, exactly like a workload interface. An
unbound attachment denies everything. Session policy inside a packet provider
(source, destination and protocol grants checked before writing to the TUN)
is enforced in addition, never instead.

### Connectivity protocols

- **Native MASQUE.** galactic-connect terminates CONNECT-IP (RFC 9484) over
  HTTP/3 (RFC 9297) with `github.com/quic-go/connect-ip-go` and quic-go. It runs
  with no iroh dependency at all. The first release supports CONNECT-IP only;
  CONNECT-UDP needs its own target, DNS and destination policy design.
- **Credentials.** A bearer token resolves a principal; a principal binding
  grants that principal exactly one VPC per request. Missing or ambiguous
  authority rejects the request. A token's expiry is the claim's authorization
  ceiling.
- **Addressing.** Each request gets addresses from the service's client pool;
  site prefixes come only from grants. Assignment, return lookup and cleanup
  are common to every packet provider.
- **iroh packet service.** A separate ALPN, listener, key and admission path
  from the application proxy's `iroh-http-proxy/1`. Its authorization never
  derives from the proxy's endpoint header.

### Tenant BGP peering

galactic-peering runs one BGP server per VPC routing domain, because a single
GoBGP v4 server rejects duplicate neighbor addresses before VRF handling. Both
listening and outgoing sockets bind to the VPC's attachment VRF. Each peer
route is a `RouteCandidate` with provenance and a dependency on the transport
it arrived over, and expires with that transport's claim even while the BGP
session stays up. Re-export to the originating domain is refused.

### Tailnet gateways

Each binding runs its own tailscaled in its own network namespace, in kernel
TUN mode, with its own state, keys and local API socket. The attachment
provisioner pre-creates the tunnel device as a TUN in the binding's pod VRF;
tailscaled opens that existing device, so decrypted traffic stays in the VRF
while tailscaled's own transport follows its marked policy routes out the
binding's management interface. tailscaled removes routes through the device
when it restarts, so the provisioner owns those routes and restores them.
Subnet routes are exported without SNAT and require both remote approval and
a Galactic grant. Local expiry releases the host attachment, which works while
tailscaled keeps running and does not depend on it. A Headscale control plane
elects one primary per prefix across all its users, so tenants whose prefixes
may overlap need separate Headscale instances.

### Numeric limits

These are the provisional values; rollout values come from measurements.

| Parameter                         | Value                       | Notes                                                 |
| --------------------------------- | --------------------------- | ----------------------------------------------------- |
| Lease `Duration`                  | 15 s                        | Local packet expiry after the last successful renewal |
| Renewal interval                  | 5 s                         | Two renewals can fail before expiry                   |
| `MaxDrift`                        | 0.001                       | 1000 ppm between any two nodes' monotonic clocks      |
| `Margin`                          | 500 ms                      | Scheduling delay between deadline and stop            |
| `TakeoverWait`                    | 15.53 s                     | Derived                                               |
| `MaxSkew`                         | 2 s                         | Wall-clock error, for authorization ceilings only     |
| Local advertisement withdrawal    | deadline + 1 s              | Measured with the API unreachable                     |
| Remote convergence                | target 5 s after withdrawal | Measured, not enforced                                |
| Service instances per cell        | 200                         | 40 lease writes per second at the renewal interval    |
| uSID Arguments                    | 4095 per locator            | Admission keeps 10% in reserve                        |
| `vrf_table`                       | 8192 rows                   | 10% reserve                                           |
| `ifindex_vrf_table`, egress kinds | 16384 rows each             | 10% reserve, covering drain overlap                   |
| `egress_route_table`              | 32768 rows                  | 10% reserve                                           |
| `tenant_gw_table`                 | 16384 rows                  | 10% reserve                                           |
| Prefixes per `BGPAdvertisement`   | 256                         | Publisher shards deterministically                    |
| Tenant MTU on attachments         | 1500                        | CNI veth default; minimum 1280 on any session         |

### Test environments and evidence

| Environment                       | Proves                                                                      |
| --------------------------------- | --------------------------------------------------------------------------- |
| Root unit tests in CI             | Namespace, VRF, TUN, uSID datapath and policy behavior on a real kernel     |
| Containerlab and Kind lab         | Multi-node EVPN, NAT and gateway coexistence                                |
| Staging edge cell (Talos, Cilium) | Namespace acquisition, privileges, hook ordering, Envoy backend delivery    |
| Independent peers                 | CONNECT-IP and BGP interoperability, Headscale and Tailscale control planes |

Root-gated tests (`requireRoot(t)`) run as root in CI automatically. Infra owns
deployed cross-service assertions; component behavior is tested here.

## Rollout

1. Install CRDs and ownership-aware binaries with adoption disabled.
2. Move every writer onto the node-local authority; verify on the lab.
3. Enable adoption for a scoped staging cohort, then production cohorts with
   stop conditions on expiry, withdrawal and competing-service latency.
4. Install providers independently. Disabling one stops new bindings and
   lets its claims expire; it never touches shared resources or other
   providers.

Rolling back to binaries without the write authority requires draining
adopted attachments first.

## Alternatives

- **Keep the ingress sidecar model.** Rejected: pod-local identifiers in shared
  maps cannot represent several pods per VPC, and every service would copy it.
- **One mutex per process.** Rejected: the writers are separate processes.
- **Wall-clock lease expiry.** Rejected: it ties safety to clock
  synchronization; bounded drift is a weaker assumption.
- **Per-attachment claim renewal.** Rejected: thousands of attachments per cell
  would renew through the API every few seconds.
