# Galactic — C4 Diagrams

C4-model diagrams (PlantUML, rendered from the `.puml` sources in this
directory) of Galactic's applications. See
[docs/agents/ARCHITECTURE-CNI.md](../agents/ARCHITECTURE-CNI.md),
[docs/agents/ARCHITECTURE-ROUTER.md](../agents/ARCHITECTURE-ROUTER.md), and
[docs/agents/ARCHITECTURE-GATEWAY.md](../agents/ARCHITECTURE-GATEWAY.md) for
the prose these diagrams summarize.

**Regenerating:** edit the `.puml` source, then re-render with Docker or
Podman:

```bash
podman run --rm -v "$(pwd)/docs/architecture:/data:Z" docker.io/plantuml/plantuml -tpng "/data/*.puml" "/data/**/*.puml"
```

Commit both the `.puml` source and the regenerated `.png` — GitHub does not
render PlantUML inline.

---

## Level 1 — System Context

Galactic as a single box in its environment: why it exists, not how it's
built internally. It's the shared networking substrate at the center of
Datum Cloud's multi-cloud VPC story — the `Compute` (pod/VM workloads),
`Connectors` (interconnect/multi-site peering), and `Gateways` (ingress
load-balancing) product surfaces all move their traffic over Galactic,
alongside the people/systems that deploy and configure it and the external
systems it depends on (Kubernetes API, the companion VPC operator, the
underlay fabric, iBGP peers).

![System Context](./context.png)

## Level 2 — Container: the three deployable applications

The three separately-built, separately-deployed applications — the
`galactic-veth` CNI chain, `galactic-router`, and `galactic-gateway` — plus
the kernel eBPF datapaths each one drives and the CRDs that connect them.
`galactic-gateway` is deployed as its own single-container DaemonSet on
gateway-role (`edge`) nodes; `galactic-router` runs there too, as its own
independent DaemonSet (the same one that runs on `compute` nodes), not
co-located in the same pod. The diagram shows them co-located on the node
but connected by no direct RPC — a crash in one does not take down the
other.

![Containers](./containers.png)

## Level 3 — Component: one diagram per binary

Internals of the three binaries this repo builds — `galactic-cni`'s six-binary
CNI chain, `galactic-router`'s BGP/EVPN control plane, and `fabric-router`'s
FRR underlay DaemonSet — each own document going one level deeper than the
Container diagram above. All three converge on the same theme: how the host's
Linux kernel routing table (and, for the SRv6 tenant path, the TC-BPF
datapath's own pinned eBPF map standing in for it) gets built — see
[docs/host-routing-table-construction.md](../host-routing-table-construction.md)
for the sequence diagram that ties these three together end to end.

![galactic-cni components](./components/galactic-cni-components.png)

![galactic-router components](./components/galactic-router-components.png)

![fabric-router components](./components/fabric-router-components.png)

---

## Source files

| Diagram                | Source                                                        |
| ----------------------- | -------------------------------------------------------------- |
| System Context           | [`context.puml`](./context.puml)                               |
| Container                | [`containers.puml`](./containers.puml)                          |
| Component — galactic-cni | [`components/galactic-cni.puml`](./components/galactic-cni.puml) |
| Component — galactic-router | [`components/galactic-router.puml`](./components/galactic-router.puml) |
| Component — fabric-router | [`components/fabric-router.puml`](./components/fabric-router.puml) |
