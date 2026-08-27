# CNI Conflist Field Reference

Every field each binary's own JSON stanza accepts in a `NetworkAttachmentDefinition`'s
`spec.config` (or an equivalent standalone conflist) — what a **developer**
sets when authoring an attachment. For the node-local `GALACTIC_CNI_*` env
vars and `HostConf` fields an **operator** tunes on the `galactic-cni`
DaemonSet instead, see [Environment Variables & Runtime Configuration](environment-variables.md).
For worked, copy-pasteable conflists, see [Conflist Examples](conflist-examples.md).
Start at [docs/cni/README.md](README.md) if you landed here directly.

> Last verified: 2026-08-27 against the current working tree of
> `internal/cni/`, `internal/cnitap/`, `internal/cniipam/`,
> `internal/cnibgp/`, and `internal/cniroute/`.

Recall from [Chain structure](configuration.md#chain-structure): each
attachment's conflist carries a `"plugins"` array — `galactic-veth`/
`galactic-tap` first, an optional `galactic-route`, then `galactic-bgp`.
Every binary's own JSON stanza carries only the fields that binary itself
reads (`vpc`/`vpcattachment` are duplicated across every stanza; nothing
else is).

## Master Plugin Fields (`galactic-veth` / `galactic-tap`)

| Field           | Required | Type     | Description                                                                                                                                                                                                          |
| --------------- | -------- | -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `vpc`           | **Yes**  | `string` | Base62-encoded VPC identifier (48-bit value). Used to derive VRF names, interface names, and BGP route targets.                                                                                                      |
| `vpcattachment` | **Yes**  | `string` | Base62-encoded VPC attachment identifier (16-bit value). Paired with `vpc` for deterministic VRF/BGP naming.                                                                                                         |
| `mtu`           | No       | `int`    | MTU for the host-side interface. For `galactic-veth` this applies to both veth endpoints; for `galactic-tap` it applies to the tap interface.                                                                        |
| `namespace`     | No       | `string` | Kubernetes namespace used for NAD lookup (and, for `galactic-bgp`'s own stanza, `BGPRouter`/BGP CRD lookup). Resolution order: this field → `GALACTIC_CNI_NAMESPACE` env → `HostConf.Namespace` → `galactic-system`. |
| `ipam`          | No       | `IPAM`   | IPAM delegation block (see [IPAM Fields](#ipam-fields) below). Presence alone decides whether IPAM runs at all — no env var or sibling field can trigger or suppress it.                                             |

Standard CNI fields (`cniVersion`, `name`, `dns`, `runtimeConfig`) are also
supported via the embedded `types.PluginConf`. Both binaries declare support
for the full CNI spec range (`version.All`, from `github.com/containernetworking/cni`
v1.3.0 in `go.mod`) and return CNI Result `1.0.0` (`type100`).

Despite that broad declared range, `cniVersion` must be `"1.0.0"` or `"1.1.0"`
in practice: `galactic-bgp`, chained after the master plugin, reconstructs
`prevResult` via `type100.NewResult` (`internal/cnibgp/prevresult.go`), which
only accepts a Result whose own `cniVersion` field is exactly one of those two
values — the master plugin echoes the conflist's `cniVersion` straight into
its printed Result, so an older value (e.g. `"0.4.0"`) makes `galactic-bgp`'s
ADD fail for every attachment in the chain. Every example in
[Conflist Examples](conflist-examples.md) already uses `"1.0.0"`; keep it
that way for any config authored outside those examples.

There is no `interface_type` field anymore: which binary you invoke *is* the
interface type. `galactic-veth` always creates a veth pair; `galactic-tap`
always creates a tap device. There is likewise no `terminations` field on
either master plugin's own stanza anymore — that field now lives entirely on
`galactic-route`'s own stanza (see
[Termination Fields](#termination-fields-galactic-route) below).

### `galactic-veth` (veth)

Creates a veth pair: one endpoint stays in the host namespace (named
`G<vpc, zero-padded to 9><vpcattachment, zero-padded to 3>H`, e.g. `G0000000010010H`)
and the other is moved into the container via the host-device CNI plugin
(renamed to the `CNI_IFNAME` value, typically `eth0`). The guest interface
receives an IP address from IPAM (if configured) and a default route via the
pool gateway.

### `galactic-tap` (tap)

Creates a tap interface in the host namespace (same naming pattern as the veth
host endpoint: `G<vpc9><vpcattachment3>H`) and enslaves it to the VRF. No
interface is moved into a container — the tap fd is managed directly by the
guest VM hypervisor (Kata, Firecracker, kraftlet/Unikraft), so this binary
never delegates to host-device and never configures a guest netns. It still
runs IPAM (if `"ipam"` is present) and configures the host gateway exactly as
`galactic-veth` does; the CNI result carries a single interface (the host tap,
empty sandbox) since there's no guest-side interface entry.

The IPv4 gateway address on the host tap is a `/25`, not the `/32` used
everywhere else (veth's host/guest gateways, and the pod's own address in both
modes). VM guests expect the gateway to look like a real subnet rather than a
bare host route. Because a wider mask would normally make the kernel
auto-install a connected route for the whole `/25` in the VRF table — exactly
the subnet-router-anycast hazard the `/32` choice exists to avoid elsewhere —
the address is added with `IFA_F_NOPREFIXROUTE`, which suppresses that
auto-created route. The explicit pod-subnet `/32` route `hostgw.ConfigureHostGateway`
installs remains the only route governing delivery to the VM's address.

## IPAM Fields

`"ipam"`'s `type` names the **delegated binary** (per the CNI IPAM delegation
protocol, `github.com/containernetworking/plugins/pkg/ipam.ExecAdd`/`ExecDel`/
`ExecCheck`) — currently only `galactic-ipam` exists, so this is always
`"galactic-ipam"` in practice. It is not a pool-vs-static mode selector: mode
is decided entirely by which of the fields below are present.

| Field              | Required | Type        | Description                                                                                                                                                                                                                                                                                                           |
| ------------------ | -------- | ----------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `type`             | **Yes**  | `string`    | Names the delegated CNI IPAM binary. Always `"galactic-ipam"` today.                                                                                                                                                                                                                                                  |
| `addresses`        | No       | `[]Address` | Addresses decided outside `galactic-ipam` (`address`, `gateway`). Presence selects the [addresses path](#ipam-addresses) below, which assigns exactly these — both families, prefix length preserved — and allocates, stores and releases nothing. Rejected if combined with `static_ip`/`ipv6_subnet`/`ipv4_subnet`. |
| `static_ip`        | No       | `string`    | A single IPv6 address to assign, with a `/64` mask and no IPv4. The legacy single-address path, superseded by `addresses`; mutually exclusive in practice with the subnet fields.                                                                                                                                     |
| `ipv6_subnet`      | No       | `string`    | Region IPv6 pool CIDR; endpoints allocate a `/96` from it by default.                                                                                                                                                                                                                                                 |
| `ipv4_subnet`      | No       | `string`    | Site IPv4 pool CIDR; endpoints allocate a `/32` host address from it.                                                                                                                                                                                                                                                 |
| `address_families` | No       | `[]string`  | Restricts allocation to the listed families, narrowing whichever of `ipv6_subnet`/`ipv4_subnet` are configured on this attachment (never widens beyond them). Omit for no restriction — allocate from every pool configured. Rejects a config that excludes every configured pool.                                    |
| `routes`           | No       | `[]Route`   | Declared on the `IPAM` struct (`dst`, `gw`) but not read by any current allocation path — vestigial. Every path publishes a default route per configured family instead.                                                                                                                                              |

Whether IPAM runs at all is decided **solely** by `"ipam"` block presence in
the master plugin's own stanza — no environment variable can trigger or
suppress that (see [`GALACTIC_IPAM_ENABLE_LOCAL_IPAM`](environment-variables.md#galactic_ipam_enable_local_ipam)
in the environment variables doc, which only fills a default when the block
is present but under-specified). Once delegated to, `addresses` presence
selects the addresses path; otherwise `static_ip` presence selects the
static path; otherwise `ipv6_subnet`/`ipv4_subnet` (either alone, or both)
select the pool path. Mixing `addresses` with any of the others is a config
error, not a precedence question. See `internal/cniipam`'s package doc
comment for the full explicit contract.

### IPAM `addresses`

The path for addresses this attachment did not choose. Datum's networking
layer decides an interface's addresses before the workload is scheduled — an
IPv6 endpoint block (typically a `/96`), optionally an IPv4 `/32`, each with a
gateway — and this path configures exactly those:

- **Prefix length is preserved as given.** A `/96` stays a `/96`; nothing is
  re-masked. This is the difference from `static_ip`, which forces `/64`.
- **Both families.** At most one address per family, either alone or both.
- **Gateways are honoured** per address, and must be the same family as the
  address they accompany.
- **Nothing is allocated and nothing is persisted**, so no pool CIDR is
  involved and `address_families` has no effect (as with `static_ip`).

Each entry takes:

| Field     | Required | Type     | Description                                                                                                                                              |
| --------- | -------- | -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `address` | **Yes**  | `string` | The address in CIDR form. An explicit prefix length is required. An IPv4 entry must be a `/32` — the data plane models an IPv4 endpoint as a host route. |
| `gateway` | No       | `string` | Next-hop for this address's family. Need not be inside the address's own prefix.                                                                         |

`galactic-ipam` keeps no record of these addresses — the system that decided
them is their source of truth. As with `static_ip`, they are validated once at
ADD and never stored, so DEL has nothing to release and CHECK always passes
(there is nothing on-node for a delegated IPAM plugin to verify: the master
plugin owns interface configuration, and on the tap path the guest configures
itself). A retried ADD is idempotent because nothing is written. Only the pool
path writes allocation state to `internal/cni/ipam.DefaultLockDir`.

### IPAM `static_ip`

Validates and assigns a single IPv6 address with a `/64` mask. No IPv4 address
is ever allocated alongside it — static IPAM is a single fixed address, not a
dual-stack pool. Use [`addresses`](#ipam-addresses) instead for an address
decided upstream: it preserves the prefix length it was given and supports
both families.

### Pool IPAM via `ipv6_subnet`/`ipv4_subnet`

This is the NAD-driven path most VPC attachments use (`allocatePool` in
`internal/cniipam/allocate.go`, backed by `internal/cni/ipam`'s pool
allocators). Either field alone is sufficient — neither depends on the other
being set:

- **IPv6-only:** set `ipv6_subnet`, omit `ipv4_subnet`. Allocates a `/96`
  subnet from the region pool; no IPv4 address is allocated.
- **IPv4-only:** set `ipv4_subnet`, omit `ipv6_subnet`. Allocates a `/32` host
  address from the site pool; no IPv6 subnet is allocated, and the resulting
  `BGPAdvertisement` carries only the IPv4 `/32` prefix.
- **Dual-stack:** set both. Allocates from each pool independently; the
  `BGPAdvertisement` carries both prefixes and the CNI result carries both
  `IPConfig`/route entries.

Allocation state persists in on-disk marker files under `galactic-ipam`'s own
lock directory (`internal/cni/ipam.DefaultLockDir`, flock-guarded, keyed by
containerID — both address families). `galactic-ipam` never needs a
Kubernetes client for this: `cmdDel` looks up and removes its own
containerID's marker file directly, with no dependency on a `BGPAdvertisement`
CRD annotation (that coupling existed before this allocator gained its own
persistence and has since been removed).

When neither `ipv6_subnet` nor `ipv4_subnet` is set and `GALACTIC_IPAM_ENABLE_LOCAL_IPAM`
is enabled, allocation falls back to the built-in default IPv6 pool CIDR (see
[`GALACTIC_IPAM_ENABLE_LOCAL_IPAM`](environment-variables.md#galactic_ipam_enable_local_ipam)
in the environment variables doc) — this fallback is IPv6-only; there is no
default IPv4 pool.

## Termination Fields (`galactic-route`)

`galactic-route`'s own stanza carries only `vpc`, `vpcattachment`, and
`terminations` — no `namespace` field, since this binary has no Kubernetes
dependency at all. Include this stanza in the chain only for attachments that
actually need static routes; it's the one stage in the chain that's genuinely
optional.

Each entry in `terminations` has:

| Field     | Required | Type     | Description                                                                                |
| --------- | -------- | -------- | ------------------------------------------------------------------------------------------ |
| `network` | **Yes**  | `string` | CIDR prefix for a static route (e.g. `"fd00::/48"`).                                       |
| `via`     | No       | `string` | Next-hop gateway IP. If omitted, a link-local route is installed via the host-side device. |

Used in `cmdAdd` to install routes into the VRF table for each termination
entry, via the host-side interface name derived from `(vpc, vpcAttachment)`
alone — identical whether the preceding master plugin was `galactic-veth` or
`galactic-tap`. `cmdDel` is a no-op: like every other shared, per-attachment
resource in the chain, termination routes may still be in use by another pod/VM
on the same attachment, so cleanup is left to `galactic-router`'s GC controller.

## BGP Publish Fields (`galactic-bgp`)

`galactic-bgp`'s own stanza carries only `vpc`, `vpcattachment`, and
`namespace` — nothing else. It learns which interface kind was created and
what addresses were allocated entirely from `prevResult` (the accumulated
result of every preceding plugin in the chain), never from its own config or
a kernel call.

### EndpointSlice publish (HTTP ingress backend discovery)

Alongside the `BGPVRFInstance`/`BGPAdvertisement` CRDs, `galactic-bgp`
publishes one `discoveryv1.EndpointSlice` per pod — named after the pod, in
the pod's own namespace — whenever the attachment has an IPv6 address to
carry (i.e. `ipam` is configured on the master plugin's stanza; a tap/VM
attachment with no `ipam` block, same as a veth attachment with none, has
nothing to publish and is skipped, not an error). This is the mechanism the
HTTP ingress extension server (datum-cloud/enhancements#854/#796) discovers
VPC backends through — no backing `Service` object exists to key a
Service-generated `EndpointSlice` off of.

IPv6-only: a dual-stack pod's IPv4 address is not published. The
EndpointSlice carries:

- `spec.endpoints[].addresses`: the pod's allocated IPv6 address.
- Label `galactic.datum.net/tenant-id`: `TenantIdentifier(vpc, vpcattachment)`
  — the discovery mechanism (annotations aren't selectable in a k8s
  `List`/`Watch`).
- Annotation `galactic.datum.net/tenant-id`: the same value, for
  human-readable detail.
- Annotation `galactic.datum.net/srv6-sid`: the computed SRv6 uSID
  (`internal/plumbing/srv6.ComputeSID`) routing to this pod's VRF — absent
  when this node's `BGPRouter` has no `srv6Locator`/`nodeID` configured.
- `metadata.ownerReferences`: the owning Pod, so the Kubernetes garbage
  collector reclaims it if this plugin's own DEL is never run (a
  force-deleted pod). CNI DEL deletes it explicitly and unconditionally on
  the normal path — unlike the BGP CRDs, an EndpointSlice is 1:1 with
  exactly one pod and is never shared with a sibling attachment, so DEL
  deleting it immediately is safe.

CHECK verifies the EndpointSlice still exists with the expected address and
annotations.

Both the pod's name and its namespace are parsed from `K8S_POD_NAME`/
`K8S_POD_NAMESPACE` in `CNI_ARGS` (`internal/nadpatch.ParsePodName`/
`ParsePodNamespace`) — Multus always sets both for a real pod-scoped
invocation, but a standalone/manual invocation (e.g. one that skips the CNI
runtime, as some `tests/e2e` cases do) must set `CNI_ARGS` itself or ADD
fails outright and CHECK reports an error.
