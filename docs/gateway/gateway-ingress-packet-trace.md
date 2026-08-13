## Packet Trace

This sequence diagram walks one ingress TCP flow through
`galactic-gateway`'s edge XDP Full-NAT datapath end to end: an external
client hitting a VIP, through the gateway node's `edge_nat` XDP program
(`internal/plumbing/ebpf/edgeprog/edgenat.c`), across the SRv6 underlay to
the backend Pod's worker node, and back. `2001:db8::1:8080` is an
illustrative VIP:port, not a value from any config in this repo.

Two things about this datapath are easy to get wrong and matter for
reading the diagram correctly:

- **It is Full-NAT, not plain DNAT.** The gateway rewrites *both* the
  destination (VIP → backend Pod address) and the source (client address →
  the gateway node's own `gw_addr:port`) on the way in. Because of that,
  the backend Pod never learns the real client address — its reply is
  naturally addressed back to the gateway node, which is what lets the
  return path work with zero pod-side or worker-side awareness of NAT.
- **The worker-node decap is one eBPF pass, not a kernel SRv6 feature.**
  There is no kernel `seg6local` route involved (that path was removed in
  an earlier cutover — see
  [ARCHITECTURE-CNI.md](../agents/ARCHITECTURE-CNI.md)). A single TC-BPF
  program, `usid_ingress` (`internal/plumbing/ebpf/prog/usid.c`), matches
  the outer destination against its locator table, strips the outer IPv6
  header, resolves the tenant VRF via a scoped FIB lookup, and redirects
  straight into the Pod's veth (`bpf_redirect_peer()`) — all in the same
  packet pass. The function this program implements is End.DT46
  (dual-stack), not End.DT6 — this codebase's SRv6 type explicitly rejects
  `End.DT6` as unsupported.

```mermaid
sequenceDiagram
    autonumber
    participant Client as External Client
    participant NIC as Gateway Node NIC / XDP (edge_nat)
    participant Map as eBPF Maps (rule_table & conn_table)
    participant Underlay as SRv6 Underlay Fabric
    participant Worker as Worker Node (TC-BPF uSID datapath)
    participant Pod as Tenant Pod

    Note over Client, Pod: --- INBOUND REQUEST PATH ---
    Client->>NIC: Send TCP SYN (Dst: [2001:db8::1]:8080)
    NIC->>Map: Match (proto, VIP, port) against rule_table, miss on conn_table forward key
    Map-->>NIC: rule_table returns backend list, pick one by hash(client tuple), claim a SNAT port in conn_table
    Note over NIC: Full-NAT rewrite:<br/>1. DNAT: Dst IP:port to chosen backend Pod ULA:port<br/>2. SNAT: Src IP:port to this node's gw_addr:allocated port<br/>3. Fix L4 checksum (bpf_csum_diff, no __sk_buff helpers in XDP)<br/>4. Push fresh 40-byte outer IPv6 header (Dst: backend's WorkerNode uSID)
    NIC->>Underlay: XDP_TX encapsulated packet (outer Dst: WorkerNode uSID)
    Underlay->>Worker: Route via IPv6 underlay to the worker's uSID locator
    Worker->>Worker: TC-BPF uSID datapath (usid_ingress) matches locator+VRF Argument, strips outer header, FIB lookup scoped to tenant VRF
    Worker->>Pod: bpf_redirect_peer() delivers inner packet via veth into tenant VRF, one eBPF pass, no separate kernel decap step

    Note over Client, Pod: --- OUTBOUND RETURN PATH ---
    Pod->>Worker: Reply packet (Src: Pod ULA, Dst: gateway node's gw_addr, the only client address the Pod ever sees)
    Worker->>Underlay: Encapsulate return traffic to the gateway node's own uSID (gw_addr)
    Underlay->>NIC: Deliver SRv6 packet back to the gateway node
    NIC->>Map: XDP return branch (edge_nat) looks up conn_table by the reverse 5-tuple
    Note over NIC: Full-NAT reversal:<br/>1. Pop outer SRv6 header<br/>2. Un-SNAT: Src IP:port Pod ULA:port to Public VIP:port<br/>3. Un-DNAT: Dst IP:port gw_addr:port to original Client IP:port<br/>4. Recalculate checksum, resolve L2 next-hop via bpf_fib_lookup
    NIC->>Client: XDP_TX raw TCP reply packet
```

## eBPF Map

This diagram covers the control-plane side: how a `NetworkRule` CRD
becomes `rule_table` rows the datapath above actually reads. The only CRDs
`galactic-gateway`'s reconcilers watch are `NetworkGateway` and
`NetworkRule` (`internal/controller/networkgateway_controller.go`,
`networkrule_controller.go` — `SetupWithManager`); `BGPAdvertisement`/
`BGPRouter` are read, not watched, purely to resolve backend uSIDs
(`internal/controller/usidresolver.go`).

The `rule_table` key deliberately carries **no tenant dimension** —
`(proto, VIP address, VIP port)` alone disambiguates every rule on a node,
because a VIP is globally unique by construction. A `NetworkRule`'s
`vpcRef`/`vpcAttachmentRef` are threaded through for telemetry/audit
labeling only; the datapath itself never consults them.

```mermaid
sequenceDiagram
    autonumber
    participant K8s as Kubernetes API Server
    participant Op as galactic-gateway (NetworkGatewayReconciler)
    participant Map as eBPF Kernel Maps (rule_table / conn_table)
    participant XDP as eBPF XDP Datapath (edge_nat)

    Note over K8s, XDP: --- CONTROL PLANE: MAP POPULATION FLOW ---
    K8s->>Op: Watch event (NetworkGateway, NetworkRule)
    Note over Op: 1. List accepted, non-deleting NetworkRules: extract VIP(s), protocol, port, backend address:port pairs<br/>2. Resolve each backend's SRv6 uSID (usidresolver.go, matched against BGPAdvertisement/BGPRouter CRDs)
    Note over Op: Build rule_table Key:<br/>(proto, VIP address, VIP port), no tenant dimension, a VIP is globally unique by construction
    Note over Op: Build rule_table Value:<br/>backend list [Pod ULA:port + WorkerNode uSID], up to 8 backends
    Op->>Map: bpf_map_update_elem() via edgemap.RuleTable (cilium/ebpf)
    Map-->>Op: Acknowledge map update

    Note over K8s, XDP: --- DATAPATH: RUNTIME LOOKUP FLOW ---
    XDP->>Map: Packet hits the gateway NIC, match (proto, dst port, dst addr) against rule_table
    Map-->>XDP: Returns the backend list, conn_table caches the per-flow translation once one is assigned
```
