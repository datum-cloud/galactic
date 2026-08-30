# CNI Configuration

Part of the [CNI docs](README.md) — see that index for the full,
audience-organized map of this directory.

The galactic CNI plugin chain is configured through the CNI JSON conflist passed
by Multus (or any CNI manager), plus node-local settings resolved at runtime from
the static conflist, environment variables, and (for `galactic-veth`/`galactic-tap`/
`galactic-bgp`, as a last resort) the Kubernetes API. This page covers the
chain's shape; every field and env var is documented in one of the focused
pages linked below.

> Last verified: 2026-08-27 against the current working tree of `internal/cni/`,
> `internal/cnitap/`, `internal/cniipam/`, `internal/cnibgp/`, `internal/cniroute/`,
> and `internal/installer/installer.go`.

## Chain structure

Each `NetworkAttachmentDefinition` (or other Multus-driven config) supplies a
full CNI conflist — a `"plugins"` array, not a single plugin object — because
BGP/SRv6/eBPF publish now runs as its own chained binary rather than inline
inside the master plugin. A real-world attachment's conflist has this shape:

```json
{
  "cniVersion": "1.0.0",
  "name": "private",
  "plugins": [
    { "type": "galactic-veth", "...": "..." },
    { "type": "galactic-route", "...": "..." },
    { "type": "galactic-bgp", "...": "..." }
  ]
}
```

- **`galactic-veth`** (veth, containers) or **`galactic-tap`** (tap, VM
  workloads) — always first. Creates the VRF and host-side interface,
  annotates the NAD, delegates IPAM (if an `"ipam"` block is present) and
  — `galactic-veth` only — host-device (to move the guest veth into the
  container netns), configures the host gateway, and prints the CNI
  result.
- **`galactic-route`** — optional; include only when the attachment has
  `terminations` to install. Installs each as a VRF-table route, then
  passes `prevResult` through unchanged.
- **`galactic-bgp`** — publishes `BGPVRFInstance`/`BGPAdvertisement` and
  (when this node's `BGPRouter` has SRv6 configured) the eBPF uSID
  datapath's `vrf_table` registration. Learns everything it needs
  (interface kind, allocated addresses) from `prevResult` alone. In
  practice this stage is not optional — without it the attachment is
  never BGP-advertised and stays unreachable from other nodes. The
  conflist itself is still authored outside this repo (the companion
  operator, cross-repo), but the master plugin (`galactic-veth`/
  `galactic-tap`) fetches its own attachment's `NetworkAttachmentDefinition`
  and fails ADD before creating any kernel state if `galactic-bgp` is
  missing from its `plugins` list — see `internal/hostconf.VerifyChainIncludes`
  and `internal/nadpatch.VerifyChainComplete`
  ([#331](https://github.com/datum-cloud/galactic/issues/331)).

Every binary's own JSON stanza carries only the fields that binary itself
reads (`vpc`/`vpcattachment` are duplicated across every stanza; nothing
else is). See [docs/cni-cmd-sequence.md](cni-cmd-sequence.md) for the
full ADD/DEL sequence across all three stages.

## Where to go next

- Operators tuning the `galactic-cni` DaemonSet: [Environment Variables & Runtime Configuration](environment-variables.md).
- Developers authoring conflists: [Conflist Field Reference](conflist-reference.md) and [Conflist Examples](conflist-examples.md).
- Sequence diagrams and the full architecture reference: see [docs/cni/README.md](README.md).
