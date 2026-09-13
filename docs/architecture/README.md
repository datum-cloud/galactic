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

## Level 2 — Container: the four deployable applications

The four separately-built, separately-deployed applications — the
`galactic-veth` CNI chain, `galactic-router`, `galactic-gateway`, and
`galactic-nat` — plus the kernel eBPF datapaths each one drives and the
CRDs that connect them. `galactic-gateway` is deployed as its own
single-container DaemonSet on gateway-role (`edge`) nodes; `galactic-router`
runs there too, as its own independent DaemonSet (the same one that runs on
`compute` nodes), not co-located in the same pod. `galactic-nat` is the
`compute`-node equivalent: its own single-container DaemonSet running
unconditionally on every compute node, alongside — again not co-located
with — that same `galactic-router` DaemonSet. The diagram shows each pairing
co-located on the node but connected by no direct RPC — a crash in one does
not take down the other; both `galactic-gateway` and `galactic-nat`
publish their own BGP reachability by writing a `BGPAdvertisement` CRD that
the co-located `galactic-router`'s embedded GoBGP picks up and advertises,
not by speaking BGP themselves.

![Containers](./containers.png)

---

## Source files

| Diagram                | Source                                                        |
| ----------------------- | -------------------------------------------------------------- |
| System Context           | [`context.puml`](./context.puml)                               |
| Container                | [`containers.puml`](./containers.puml)                          |
