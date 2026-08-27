# Galactic CNI Docs

Entry point for everything documenting the `galactic-cni` plugin chain —
how attachments are configured, how ADD/DEL/CHECK/STATUS flow through the
chain, and how orphaned state gets garbage collected. For the chain's own
layout, entry points, and module reference, see
[docs/agents/ARCHITECTURE-CNI.md](../agents/ARCHITECTURE-CNI.md) instead —
these pages assume that context and go deep on configuration and runtime
behavior.

## Start here

**Operators** deploying or running the `galactic-cni` DaemonSet:

- [Environment Variables & Runtime Configuration](environment-variables.md)
  — every `GALACTIC_CNI_*`/`GALACTIC_IPAM_*` env var, the static per-node
  conflist's `HostConf` fields, resolution precedence, and log verbosity.

**Developers** authoring `NetworkAttachmentDefinition` conflists:

- [Conflist Field Reference](conflist-reference.md) — every field each
  chain binary's own JSON stanza accepts: master plugin fields, IPAM
  delegation modes, `galactic-route` terminations, and `galactic-bgp`'s
  EndpointSlice publish behavior.
- [Conflist Examples](conflist-examples.md) — worked, copy-pasteable
  conflists for every IPAM mode, terminations, and tap/VM workloads.

**Everyone** — [CNI Configuration](configuration.md) covers the chain's
shape: which binary runs first, when `galactic-route` is included, and why
`galactic-bgp` isn't optional in practice.

## Sequence diagrams

- [ADD / DEL Sequence Diagrams](cni-cmd-sequence.md) — Mermaid diagrams of
  the attach and detach path across all three chain stages.
- [GC Sequence Diagrams](gc-cmd-sequence.md) — the orphaned-CRD/kernel-VRF
  sweep `galactic-router` runs, and the eBPF `vrf_table` sweep
  `galactic-cni`'s `run` container runs independently.
