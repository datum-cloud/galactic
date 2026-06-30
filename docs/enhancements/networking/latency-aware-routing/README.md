---
status: provisional
stage: alpha
latest-milestone: "v0.1"
---

<!-- omit from toc -->
# Latency-Aware Routing

- [Summary](#summary)
- [Motivation](#motivation)
  - [Goals](#goals)
  - [Non-Goals](#non-goals)
- [Proposal](#proposal)
  - [Policy Model](#policy-model)
  - [Delay Measurement](#delay-measurement)
  - [Delay Distribution via BGP](#delay-distribution-via-bgp)
  - [Path Selection](#path-selection)
  - [Tag-Based Policy Routing](#tag-based-policy-routing)
  - [Policy Enforcement Points](#policy-enforcement-points)
  - [Tenant Observability](#tenant-observability)
  - [How It Comes Together](#how-it-comes-together)
- [Design Decisions](#design-decisions)
- [Roadmap](#roadmap)
- [Dependencies](#dependencies)

## Summary

Latency-aware routing enables VPC customers to express routing intent — low
latency, geographic constraints, bandwidth requirements — as declarative
policies attached to their workloads. The platform continuously measures
network delay between nodes, distributes delay metrics through
[BGP][bgp-overview], and makes autonomous, per-node path selection decisions
using [SRv6][srv6] traffic engineering. Customers see the results through
metrics exposed in the platform's telemetry system.

This enhancement builds on the existing [BGP control plane][datum-bgp] and
[SRv6 data plane](../vpc/) to add three capabilities: active delay
measurement, delay-aware route advertisement, and policy-driven path
selection — all operating autonomously within each cluster without
management cluster involvement in the forwarding path.

## Motivation

Today, traffic between VPC workloads follows the shortest available path
through the network fabric — but the shortest path isn't always the fastest.
As the platform scales across regions and availability zones, the gap between
"shortest path" and "lowest latency path" grows. Customers running
latency-sensitive workloads have no way to express that their traffic should
prefer low-latency paths, and no visibility into the actual latency their
traffic experiences.

Different services within the same VPC have fundamentally different
connectivity requirements. A real-time trading API needs sub-millisecond
optimization while a batch log shipper just needs reachability. Geo-aware
routing, latency-based routing, and bandwidth optimization are per-service
concerns, not per-network concerns. The platform needs to support this
granularity down to the individual connection.

The core insight from research into protocols like [DDM][ddm] (Delay Driven
Multipath) and Google's [Swift][swift] is that **delay is a simple,
effective, and universal signal** for path quality — it inherently encodes
congestion, distance, and link health into a single measurable value.

### Goals

- Continuously measure network delay between all nodes using active probes
  based on [STAMP][stamp]
- Distribute measured delay metrics through the existing BGP control plane
  using standard path attributes ([AIGP][aigp])
- Enable each node to make autonomous, delay-aware path selection decisions
  without management cluster involvement
- Allow VPC customers to express routing intent (low latency, geographic
  constraints) as declarative policies with workload selectors
- Apply policies at attachment time — when a pod starts or a
  [MASQUE][masque] tunnel is established — not per-packet
- Expose measured path latency, jitter, and loss to customers through the
  platform's telemetry system
- Provide basic connectivity optimization for all VPCs by default

### Non-Goals

- Replacing the primary CNI for intra-cluster pod-to-pod networking
- Per-packet deep inspection or application-layer routing decisions
- Centralized path computation (PCE) for routine routing decisions — nodes
  must operate autonomously
- Hardware-specific optimizations (ASIC timestamping, hardware queuing)
- Guaranteed bandwidth reservation (this is a path selection enhancement,
  not a QoS reservation system)

## Proposal

### Policy Model

Routing intent is expressed through two resource types: a tenant-facing
**VPCRoutingPolicy** that selects workloads and assigns tags, and a
platform-level **RoutingProfile** that defines what each tag means in terms
of forwarding behavior.

**VPCRoutingPolicy** — created by tenants, scoped to a VPC:

```yaml
apiVersion: networking.galactic.datumapis.com/v1alpha1
kind: VPCRoutingPolicy
metadata:
  name: gold-realtime
spec:
  vpcRef: my-vpc
  selector:
    matchLabels:
      app: trading-engine
  tag: gold
  requirements:
    maxLatency: 5ms
    geoConstraint: US
```

```yaml
apiVersion: networking.galactic.datumapis.com/v1alpha1
kind: VPCRoutingPolicy
metadata:
  name: standard-batch
spec:
  vpcRef: my-vpc
  selector:
    matchLabels:
      app: log-shipper
  tag: standard
```

Multiple policies can coexist for the same VPC — different services get
different routing behavior. Policy selectors match against workload labels
on VPCAttachments and ConnectorAttachments.

**RoutingProfile** — defined by the platform, delivered to clusters by the
fleet agent:

```yaml
apiVersion: networking.galactic.datumapis.com/v1alpha1
kind: RoutingProfile
metadata:
  name: gold
spec:
  color: 100
  dscp: 46                    # EF - Expedited Forwarding
  pathSelection: min-delay
  constraints:
    maxLatency: 5ms
    affinities:
      include: [US]
---
apiVersion: networking.galactic.datumapis.com/v1alpha1
kind: RoutingProfile
metadata:
  name: standard
spec:
  color: 300
  dscp: 0                     # Best Effort
  pathSelection: default
```

The RoutingProfile translates a tag into three forwarding behaviors:

- **Color** ([SR Policy Color Extended Community][sr-policy]): determines
  which set of delay-aware routes the headend resolves against
- **DSCP**: marks the outer IPv6 header so every transit node applies the
  correct queuing behavior without any tenant awareness
- **Path selection constraints**: delay ceiling, geographic affinity
  inclusion/exclusion, bandwidth floor

### Delay Measurement

Each galactic-agent node runs a [STAMP][stamp] sender and reflector to
actively measure one-way and round-trip delay to its BGP peers. STAMP is the
IETF standard for active measurement, with [SRv6-specific
extensions][stamp-sr] that ensure probes follow the exact same paths as real
traffic.

Measurement operates entirely in-memory on each node:

1. The agent sends STAMP test packets to each peer at a configured interval
   (e.g., every 2 seconds)
2. Timestamps are applied at send (T1), receive (T2), reflect (T3), and
   return (T4)
3. Two-way delay = (T4 - T1) - (T3 - T2) — no clock synchronization
   required
4. The agent maintains a rolling average delay value per peer link
5. Delay values are stored in the agent's local memory — **never written to
   etcd**

On Linux, the STAMP reflector can be implemented as an [eBPF][ebpf] program
attached to SRv6 SID processing via the kernel's `End.BPF` behavior,
providing kernel-space timestamping with negligible forwarding impact.

### Delay Distribution via BGP

Measured delay is distributed through BGP itself — the same TCP sessions
already exchanging routes. No additional protocols, no etcd writes, no
management cluster involvement.

The mechanism is the [AIGP attribute (RFC 7311)][aigp], an optional BGP path
attribute that accumulates a metric across AS boundaries. The
[draft-ietf-idr-performance-routing][perf-routing] proposes a
NETWORK_LATENCY TLV within AIGP specifically for delay values.

**How it flows:**

1. Node A measures 2ms delay to Node B via STAMP
2. When Node A advertises its SRv6 /48 prefix, the advertisement reconciler
   attaches an AIGP attribute with the measured delay value (2000
   microseconds)
3. Node B receives the route. When re-advertising to Node C, Node B adds
   its own measured link delay to the AIGP value (accumulation)
4. By the time a route reaches a decision point, the AIGP value represents
   the total end-to-end delay along that path

```
Node A originates route for 2001:db8:x::/48
  → AIGP: 0 μs (originated locally)

Node B receives from Node A, re-advertises to Node C
  → AIGP: 2000 μs (0 + 2000 measured on A→B link)

Node C receives from Node B, re-advertises to Node D
  → AIGP: 5000 μs (2000 + 3000 measured on B→C link)

Node D has two paths to 2001:db8:x::/48:
  Path 1 via Node C: AIGP = 5000 μs
  Path 2 via Node E: AIGP = 3000 μs
  → GoBGP selects Path 2 (lower AIGP wins)
```

[GoBGP][gobgp] already implements AIGP-aware best-path selection — AIGP
comparison runs before AS-path length in the tie-breaking sequence. No
custom path selection logic is needed.

**What touches etcd vs. what doesn't:**

| Data | Where it lives | Update frequency |
|------|---------------|-----------------|
| Delay measurements | Agent memory | Every few seconds |
| AIGP attribute on routes | BGP sessions (TCP) | On measurement change |
| RoutingProfile definitions | etcd (CRD) | Infrequent (policy changes) |
| VPCRoutingPolicy | etcd (CRD) | Infrequent (tenant changes) |
| Per-link delay metrics | Prometheus | Scraped periodically |

High-frequency delay data never touches the API server.

### Path Selection

When a node has multiple BGP paths to the same prefix, GoBGP's existing
best-path algorithm uses the AIGP value as a tiebreaker — lower accumulated
delay wins. The route watcher receives the best-path update and programs the
kernel via `netlink.AddRoute`. No explicit segment lists are needed for
basic delay optimization.

For Color-aware routing, the node resolves routes differently per Color:

1. A BGP route arrives with a [Color Extended Community][sr-policy]
   (e.g., Color 100 = min-delay)
2. The node resolves the route against paths tagged with that Color
3. Among matching paths, AIGP selects the lowest-delay option
4. The route watcher programs the appropriate kernel forwarding entry

This is the distributed model — every node makes its own path selection
decision based on locally-received BGP routes with delay annotations. No
central controller is involved in the forwarding path. The management
cluster's only role is delivering the RoutingProfile definitions that map
Colors to constraints, which happens infrequently via the fleet agent.

### Tag-Based Policy Routing

Tags connect tenant intent to forwarding behavior through three layers:

**Classification (at the source node):**

When a pod starts and the CNI plugin creates its VPC network interface, the
galactic-agent evaluates VPCRoutingPolicy selectors against the pod's
labels. The matching policy's tag resolves to a RoutingProfile, and the
agent programs an eBPF classifier on the pod's veth interface that:

- Sets the DSCP value in the outer IPv6 header
- Steers traffic toward routes matching the profile's Color

This classification is programmed once at attachment time. Per-packet
processing is a simple eBPF lookup — no policy evaluation per packet.

**Path steering (at the headend):**

The DSCP-marked, Color-steered packet is SRv6-encapsulated using the
delay-optimized path selected for that Color. The segment list is determined
by the BGP route resolution for the destination prefix at the specified
Color.

**Per-hop treatment (at transit nodes):**

Transit nodes see only the DSCP value in the outer IPv6 header and the SRv6
destination. They apply queuing behavior based on DSCP (standard Linux
traffic control) and forward based on the segment list. Transit nodes have
no knowledge of tenants, policies, or tags.

```
Source node (headend):
  - Knows the tenant policy (VPCRoutingPolicy CRD)
  - Classifies traffic by pod labels
  - Chooses path based on Color
  - Sets DSCP based on tag
  - Encapsulates in SRv6

Transit nodes:
  - See DSCP in outer IPv6 header → queue priority
  - See SRv6 destination → forward per segment list
  - No knowledge of tenants, policies, or tags

Destination node:
  - End.DT46 decapsulates into VRF
  - Delivers to destination pod
```

### Policy Enforcement Points

Policies are applied at **attachment time** — the moment a workload connects
to the VPC network. This is the identity boundary where the platform knows
which tenant, service, and routing requirements apply.

**Pod attachment (CNI time):**

The galactic-agent programs the eBPF classifier on the pod's veth pair when
the CNI plugin creates the network interface. The pod's labels are matched
against VPCRoutingPolicy selectors, and the resulting classification rules
are installed.

**Connector attachment ([MASQUE][masque] tunnel establishment):**

When a Connector establishes a MASQUE tunnel, the proxy:

1. Authenticates the client (mTLS client certificate)
2. Looks up the ConnectorAttachment — confirms VPC binding
3. Evaluates VPCRoutingPolicy selectors against the ConnectorAttachment's
   labels
4. Programs classification rules for this tunnel
5. All traffic entering through the tunnel gets the correct DSCP marking
   and Color-based path selection

Different Connectors to the same VPC can get different routing treatment
based on their labels:

```yaml
ConnectorAttachment "trading-link":
  labels: { app: trading, tier: premium }
  → matches VPCRoutingPolicy "gold-realtime"
  → Color 100, DSCP 46, min-delay path

ConnectorAttachment "log-link":
  labels: { app: logging, tier: standard }
  → matches VPCRoutingPolicy "standard-batch"
  → Color 300, DSCP 0, default path
```

**Gateway attachment:**

Gateway pods connecting to VPC networks follow the same pattern as pod
attachment — the galactic-agent programs classification rules when the
Gateway's VPCAttachment is created.

**Policy updates:**

If a tenant updates their VPCRoutingPolicy, the galactic-agent watches for
the change and reprograms the eBPF classifiers on affected attachments. The
data plane connections remain up — only the forwarding behavior changes.

### Tenant Observability

Measured delay data is exposed to tenants through the platform's telemetry
system — the same metrics and dashboards they use for everything else.

**Platform-level metrics (for operators):**

- `bgp_link_delay_microseconds{peer="..."}` — per-link measured delay
- `bgp_link_delay_variation_microseconds{peer="..."}` — jitter
- `bgp_path_aigp_microseconds{prefix="...", peer="..."}` — accumulated
  end-to-end delay per path

**Tenant-visible metrics:**

- Per-VPC latency between attachment points
- Per-policy SLO compliance (is traffic actually meeting the maxLatency
  constraint?)
- Path performance for traffic matching each VPCRoutingPolicy

These are derived from the same STAMP measurements that drive routing
decisions, but aggregated and scoped per-tenant through the telemetry
pipeline. Tenants observe outcomes; they don't interact with the measurement
infrastructure directly.

### How It Comes Together

When a new workload connects to a VPC with latency-aware routing:

1. Tenant creates a **VPCRoutingPolicy** with a selector and tag
2. The fleet agent has already delivered the **RoutingProfile** definitions
   to the cluster (Color, DSCP, path selection constraints)
3. A pod starts — the **CNI plugin** creates the VPC interface
4. The **galactic-agent** evaluates the policy selector against the pod's
   labels, resolves the tag to a RoutingProfile, and programs the **eBPF
   classifier** on the pod's veth
5. Meanwhile, STAMP probes have been continuously measuring link delays
   between all nodes
6. Delay values are attached as **AIGP attributes** on BGP route
   advertisements and accumulate across the path
7. GoBGP selects the **lowest-delay path** for routes matching the pod's
   Color
8. The first packet from the pod is classified (DSCP marked, Color
   steered), **SRv6-encapsulated** with the delay-optimized segment, and
   forwarded
9. Transit nodes **queue by DSCP** and forward by SRv6 — no tenant
   awareness needed
10. The destination node **decapsulates** (End.DT46) into the VRF and
    delivers to the target pod
11. **Telemetry** exposes the measured latency to the tenant, confirming
    the SLO is being met

The management cluster's involvement was limited to delivering the
RoutingProfile definitions. Everything else — measurement, route
advertisement, path selection, classification, forwarding — operates
autonomously within the cluster.

## Design Decisions

### Distributed path selection over centralized PCE

The platform uses BGP-distributed delay metrics and per-node path selection
rather than a centralized Path Computation Element. This follows the
existing design principle that clusters are self-sufficient once the fleet
agent delivers initial configuration.

A centralized PCE would create a latency and availability bottleneck —
every path decision would depend on reachability to the controller. The
distributed model means each node makes decisions using locally-received BGP
routes, reacting to delay changes in real-time without calling home.

The tradeoff is that complex multi-constraint optimization (e.g., "low delay
AND avoid region X AND disjoint from path Y") may require a controller in
the future. The Color-based architecture accommodates this — a central
controller could populate SR Policies for specific Colors without changing
the tenant-facing model.

### AIGP for delay transport over custom attributes

AIGP (RFC 7311) is a standard BGP attribute with native accumulation
semantics — each node adds its contribution as the route propagates. GoBGP
already supports it. Using a standard attribute means the delay information
works across eBGP boundaries between clusters without custom interop.

### Policy at attachment time over per-packet classification

Evaluating tenant policies once when the workload connects (CNI time or
MASQUE tunnel establishment) avoids per-packet policy lookups. The eBPF
classifier programmed at attachment time executes in the kernel fast path
with no user-space involvement. Policy changes trigger reprogramming of the
classifier, not per-packet evaluation.

### Delay data in BGP over etcd

STAMP measurements update every few seconds per link. Writing these to CRDs
would generate massive etcd write load and trigger reconciliation storms.
Instead, delay values flow through BGP sessions (existing TCP connections
between nodes) and are consumed by GoBGP's in-memory path selection.
Prometheus metrics provide observability. etcd stores only infrequently
changing policy definitions.

### Default optimization for all VPCs

All VPCs get basic connectivity optimization without explicit policy. The
platform always prefers better-performing paths when they exist, because
AIGP-aware best-path selection runs for all routes regardless of Color.
Explicit policies let tenants tighten constraints beyond the baseline.

## Roadmap

| Phase | Scope |
|-------|-------|
| **Phase 1** | STAMP measurement between nodes; AIGP delay attribute on route advertisements; basic delay-aware best-path selection for all traffic |
| **Phase 2** | VPCRoutingPolicy and RoutingProfile CRDs; Color Extended Community support; tag-based classification with eBPF; DSCP marking; per-tag path selection |
| **Phase 3** | MASQUE Connector policy enforcement; geographic affinity constraints; tenant-facing latency metrics; SLO compliance alerting |
| **Phase 4** | Cross-cluster delay optimization via eBGP AIGP propagation; predictive routing using delay derivatives (DDM-inspired); bandwidth-aware path selection |

## Dependencies

- **[VPC Networking](../vpc/)**: Provides the SRv6 data plane, VPC/
  VPCAttachment resources, VRF isolation, and the CNI plugin where
  classification rules are installed.

- **[Fleet Networking](../../infrastructure/fleet-networking/)**: Provides
  the BGP control plane, IPAM, and topology policy that this enhancement
  extends with delay awareness. RoutingProfile definitions are delivered to
  clusters through the same fleet agent mechanism.

- **[BGP Control Plane][datum-bgp]**: The topology-agnostic BGP system
  running on every cluster. This enhancement extends its CRDs and
  reconcilers with AIGP support, Color Extended Communities, and STAMP
  measurement integration.

- **Telemetry System**: Platform observability infrastructure where
  per-tenant latency metrics are exposed. The galactic-agent exports
  Prometheus metrics; the telemetry pipeline aggregates and scopes them
  per-tenant.

<!-- References -->
[bgp-overview]: https://datatracker.ietf.org/doc/html/rfc4271
[srv6]: https://datatracker.ietf.org/doc/html/rfc8986
[sr-policy]: https://datatracker.ietf.org/doc/html/rfc9256
[stamp]: https://datatracker.ietf.org/doc/html/rfc8762
[stamp-sr]: https://datatracker.ietf.org/doc/html/rfc9503
[aigp]: https://datatracker.ietf.org/doc/html/rfc7311
[perf-routing]: https://datatracker.ietf.org/doc/draft-ietf-idr-performance-routing/
[bgp-car]: https://datatracker.ietf.org/doc/draft-ietf-idr-bgp-car/
[flex-algo]: https://datatracker.ietf.org/doc/html/rfc9350
[flex-algo-bw]: https://datatracker.ietf.org/doc/html/rfc9843
[bgp-ls-te]: https://datatracker.ietf.org/doc/html/rfc8571
[isis-te]: https://datatracker.ietf.org/doc/html/rfc8570
[network-slicing]: https://datatracker.ietf.org/doc/html/rfc9543
[ibn]: https://datatracker.ietf.org/doc/html/rfc9315
[ddm]: https://rfd.shared.oxide.computer/rfd/0347
[swift]: https://research.google/pubs/swift-delay-is-simple-and-effective-for-congestion-control-in-the-datacenter/
[espresso]: https://research.google/pubs/taking-the-edge-off-with-espresso-scale-reliability-and-programmability-for-global-internet-peering/
[masque]: https://datatracker.ietf.org/doc/html/rfc9484
[gobgp]: https://osrg.github.io/gobgp/
[datum-bgp]: https://github.com/datum-cloud/bgp
[ebpf]: https://ebpf.io/
