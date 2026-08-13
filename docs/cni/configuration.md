# CNI Configuration

The galactic CNI plugin chain is configured through the CNI JSON conflist passed
by Multus (or any CNI manager), plus node-local settings resolved at runtime from
the static conflist, environment variables, and (for `galactic-veth`/`galactic-tap`/
`galactic-bgp`, as a last resort) the Kubernetes API.

> Last verified: 2026-08-08 against the current working tree of `internal/cni/`,
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
  never BGP-advertised and stays unreachable from other nodes — but
  nothing enforces its presence at the CNI-config level; that's the
  conflist author's responsibility (the companion operator, cross-repo,
  out of scope here).

Every binary's own JSON stanza carries only the fields that binary itself
reads (`vpc`/`vpcattachment` are duplicated across every stanza; nothing
else is). See [docs/cni-cmd-sequence.md](../cni-cmd-sequence.md) for the
full ADD/DEL sequence across all three stages.

## Runtime Configuration

There is no `--node-name` or similar CLI flag on any plugin's own invocation.
Instead, each binary's own `parseConf()` resolves node-level settings on every
ADD/DEL/CHECK/STATUS call, reading (in order) the CNI config JSON, environment
variables, and a `HostConf` block parsed out of the conflist at `--conf-file`
(default `/etc/cni/net.d/10-galactic.conflist` — this is the one *static*,
node-level conflist every binary shares; not the per-attachment `plugins[]`
conflist described above). `HostConf` is written by the `galactic-cni init`
subcommand (`internal/installer.Bootstrap`) — `galactic-cni` is a separate
installer binary, never itself a CNI plugin, whose `init`/`run` subcommands
run as the CNI DaemonSet's init and long-running containers respectively —
see [docs/agents/ARCHITECTURE-CNI.md](../agents/ARCHITECTURE-CNI.md#known-constraints)
for how the DaemonSet stages it.

`galactic-ipam` and `galactic-route` have no Kubernetes dependency at all, so
they resolve only `LogFile`/`LogLevel` from `HostConf` — never `NodeName` or
`Kubeconfig`, and never fall back to the Kubernetes API.

### `HostConf` fields (written into the conflist by `galactic-cni init`)

| Field        | Description                                                                                                                      |
| ------------ | -------------------------------------------------------------------------------------------------------------------------------- |
| `NodeName`   | The Kubernetes node name the installer bootstrapped on.                                                                          |
| `Kubeconfig` | Path to the kubeconfig `Bootstrap`/`Run` maintain (`/var/lib/galactic/kubeconfig` by default).                                   |
| `Namespace`  | Kubernetes namespace for BGP CRDs (`galactic-system` by default).                                                                |
| `LogFile`    | Path the plugin logs to (`/var/log/galactic/galactic-cni.log` by default, shared across every binary in the chain).              |
| `LogLevel`   | Verbosity of plugin logging: `debug`, `info`, `warn`, or `error` (`info` by default). See [Log verbosity](#log-verbosity) below. |

### Resolution precedence

| Setting    | Precedence (highest first)                                                                                                                                                                                                       | Default (if nothing resolves)        | Resolved by                                       |
| ---------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------- | -------------------------------------------------- |
| Node name  | `GALACTIC_CNI_NODE_NAME` env → `NODE_NAME` env → `HostConf.NodeName` → auto-detect via the Kubernetes API (`detectNodeNameFromAPI`: lists Nodes, matches local interface addresses against `status.addresses[].type=InternalIP`) | _(error: "node name is required")_    | `galactic-veth`, `galactic-tap`, `galactic-bgp` |
| Kubeconfig | `GALACTIC_CNI_KUBECONFIG` env → `HostConf.Kubeconfig`                                                                                                                                                                             | `/var/lib/galactic/kubeconfig`         | `galactic-veth`, `galactic-tap`, `galactic-bgp` |
| Namespace  | `namespace` field in the CNI config JSON → `GALACTIC_CNI_NAMESPACE` env → `HostConf.Namespace`                                                                                                                                    | `galactic-system`                     | `galactic-veth`, `galactic-tap`, `galactic-bgp` |
| Log file   | `GALACTIC_CNI_LOG_FILE` env → `HostConf.LogFile`                                                                                                                                                                                  | `/var/log/galactic/galactic-cni.log`  | every binary in the chain                          |
| Log level  | `GALACTIC_CNI_LOG_LEVEL` env → `HostConf.LogLevel`                                                                                                                                                                                | `info`                                | every binary in the chain                          |

`GALACTIC_CNI_*` env var names are shared as-is across every binary that
resolves node-level settings — there's no per-binary prefix for these, since
they're the same physical node's settings regardless of which chain binary
reads them (unlike `GALACTIC_IPAM_ENABLE_LOCAL_IPAM` below, which is a
domain-specific knob belonging entirely to `galactic-ipam`).

The resolved node name is re-exported as the `NODE_NAME` process environment
variable and the resolved kubeconfig as `KUBECONFIG` (`galactic-veth`/
`galactic-tap`/`galactic-bgp` only), since other code in those packages
reads those directly. Auto-detection exists to tolerate environments (e.g.
Kind-based e2e) where the conflist's hostPath mount isn't populated yet.

### Log verbosity

Each binary's own `setupLogging()` builds a JSON `slog` handler at the
resolved level. Since every CNI invocation is a fresh, short-lived process,
this level is re-resolved on every ADD/DEL/CHECK/STATUS call, in every
binary — there's no persistent daemon to reconfigure at runtime, and every
binary shares the same log file by default so a single chain invocation's
log lines interleave in call order.

| Level             | What's logged                                                                                                                                                                        |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `debug`           | Everything: per-resource milestones (VRF/interface/route/IPAM ready, BGP CRDs applied, kernel-level operations) in addition to `info` and above. Use this when troubleshooting a specific ADD/DEL failure. |
| `info` (default)  | One line per operation marking start and outcome (`ADD: starting` / `ADD: BGP state published`, `DEL: starting` / `DEL: skipping shared resource cleanup`, `CHECK: starting` / `CHECK: passed`/`failed`, `STATUS: ready`), plus all `warn`/`error` events. |
| `warn`            | Recoverable anomalies only: stale-state repairs, k8s API retries.                                                                                                                    |
| `error`           | Failures only.                                                                                                                                                                       |

An unrecognized `log_level` value does not fail the CNI operation — it logs a
warning and falls back to `info`.

### `GALACTIC_IPAM_ENABLE_LOCAL_IPAM`

Read only by `galactic-ipam` (`internal/config/ipam.go`) — renamed from the
historical `GALACTIC_CNI_ENABLE_LOCAL_IPAM`, which no longer exists at all.
The old name could manufacture an `"ipam"` block out of thin air even when
the master plugin's own config had none; the new one can't; it only fills
in a default IPv6 pool CIDR when an `"ipam"` block is present but specifies
neither `static_ip` nor a subnet:

| Parameter     | Default                                  |
| ------------- | ----------------------------------------- |
| Pool CIDR     | `fd00:10:ff01::/64`                       |
| Subnet length | `/96`                                     |
| Gateway       | First usable address in the pool (`::1`)  |

Whether IPAM runs at all is decided **solely** by whether `"ipam"` is present
in the master plugin's own stanza — no environment variable, on either side
of this rename, can trigger or suppress that decision. See [IPAM Fields](#ipam-fields)
below and `internal/cniipam`'s package doc comment for the full explicit
contract.

**Type:** bool
**Default:** `false`

## Master Plugin Fields (`galactic-veth` / `galactic-tap`)

| Field           | Required | Type     | Description                                                                                                                                                                                |
| --------------- | -------- | -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `vpc`           | **Yes**  | `string` | Base62-encoded VPC identifier (48-bit value). Used to derive VRF names, interface names, and BGP route targets.                                                                            |
| `vpcattachment` | **Yes**  | `string` | Base62-encoded VPC attachment identifier (16-bit value). Paired with `vpc` for deterministic VRF/BGP naming.                                                                                |
| `mtu`           | No       | `int`    | MTU for the host-side interface. For `galactic-veth` this applies to both veth endpoints; for `galactic-tap` it applies to the tap interface.                                            |
| `namespace`     | No       | `string` | Kubernetes namespace used for NAD lookup (and, for `galactic-bgp`'s own stanza, `BGPRouter`/BGP CRD lookup). Resolution order: this field → `GALACTIC_CNI_NAMESPACE` env → `HostConf.Namespace` → `galactic-system`. |
| `ipam`          | No       | `IPAM`   | IPAM delegation block (see [IPAM Fields](#ipam-fields) below). Presence alone decides whether IPAM runs at all — no env var or sibling field can trigger or suppress it.                    |

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
ADD fail for every attachment in the chain. Every config in this doc already
uses `"1.0.0"`; keep it that way for any config authored outside these
examples.

There is no `interface_type` field anymore: which binary you invoke *is* the
interface type. `galactic-veth` always creates a veth pair; `galactic-tap`
always creates a tap device. There is likewise no `terminations` field on
either master plugin's own stanza anymore — that field now lives entirely on
`galactic-route`'s own stanza (see [Termination Fields](#termination-fields)
below).

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

| Field              | Required | Type       | Description                                                                                                          |
| ------------------ | -------- | ---------- | ---------------------------------------------------------------------------------------------------------------------- |
| `type`             | **Yes**  | `string`   | Names the delegated CNI IPAM binary. Always `"galactic-ipam"` today.                                                  |
| `static_ip`        | No       | `string`   | A single IPv6 address to assign. Presence selects the static allocation path (below); mutually exclusive in practice with the subnet fields. |
| `ipv6_subnet`      | No       | `string`   | Region IPv6 pool CIDR; endpoints allocate a `/96` from it by default.                                                 |
| `ipv4_subnet`      | No       | `string`   | Site IPv4 pool CIDR; endpoints allocate a `/32` host address from it.                                                 |
| `address_families` | No       | `[]string` | Families to record as in-use: any of `"ipv6"`, `"ipv4"`. Defaults to `["ipv6"]`. Validated at parse time — keep this consistent with which of `ipv6_subnet`/`ipv4_subnet` are set. |
| `routes`           | No       | `[]Route`  | Declared on the `IPAM` struct (`dst`, `gw`) but not read by any current allocation path — vestigial.                 |
| `addresses`        | No       | `[]Address`| Declared on the `IPAM` struct (`address`) but not read by any current allocation path — vestigial.                    |

Whether IPAM runs at all is decided **solely** by `"ipam"` block presence in
the master plugin's own stanza — no environment variable can trigger or
suppress that (see [`GALACTIC_IPAM_ENABLE_LOCAL_IPAM`](#galactic_ipam_enable_local_ipam)
above, which only fills a default when the block is present but
under-specified). Once delegated to, `static_ip` presence selects the static
path; otherwise `ipv6_subnet`/`ipv4_subnet` (either alone, or both) select the
pool path. See `internal/cniipam`'s package doc comment for the full explicit
contract.

### IPAM `static_ip`

Validates and assigns a single IPv6 address with a `/64` mask. No IPv4 address
is ever allocated alongside it — static IPAM is a single fixed address, not a
dual-stack pool.

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
[`GALACTIC_IPAM_ENABLE_LOCAL_IPAM`](#galactic_ipam_enable_local_ipam) above) —
this fallback is IPv6-only; there is no default IPv4 pool.

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

## Example Configurations

Every example below is a full conflist (a `NetworkAttachmentDefinition`'s
`spec.config`, or an equivalent standalone conflist file) — not a single
plugin object — per [Chain structure](#chain-structure) above.

### Minimal configuration (overlay)

```json
{
  "cniVersion": "1.0.0",
  "name": "galactic",
  "plugins": [
    { "type": "galactic-veth", "vpc": "1", "vpcattachment": "1" },
    { "type": "galactic-bgp", "vpc": "1", "vpcattachment": "1" }
  ]
}
```

Omits `namespace` (defaults to `galactic-system`), `ipam`, and a
`galactic-route` stage. Without `GALACTIC_IPAM_ENABLE_LOCAL_IPAM` set, no IP
address is assigned to the guest interface.

### Pool IPAM, IPv6-only (testvpc)

```json
{
  "cniVersion": "1.0.0",
  "name": "testvpc",
  "plugins": [
    {
      "type": "galactic-veth",
      "vpc": "10",
      "vpcattachment": "10",
      "namespace": "galactic-system",
      "ipam": {
        "type": "galactic-ipam",
        "ipv6_subnet": "fd00:10:ff02::/48",
        "address_families": ["ipv6"]
      }
    },
    { "type": "galactic-bgp", "vpc": "10", "vpcattachment": "10", "namespace": "galactic-system" }
  ]
}
```

### Pool IPAM, dual-stack

```json
{
  "cniVersion": "1.0.0",
  "name": "vpc21",
  "plugins": [
    {
      "type": "galactic-veth",
      "vpc": "21",
      "vpcattachment": "21",
      "namespace": "galactic-system",
      "ipam": {
        "type": "galactic-ipam",
        "ipv6_subnet": "fd00:10:ff03::/48",
        "ipv4_subnet": "172.21.1.0/24",
        "address_families": ["ipv6", "ipv4"]
      }
    },
    { "type": "galactic-bgp", "vpc": "21", "vpcattachment": "21", "namespace": "galactic-system" }
  ]
}
```

Allocates from both pools independently; the `BGPAdvertisement` carries both
the IPv6 `/96` and IPv4 `/32` prefixes.

### Pool IPAM, IPv4-only (tap)

```json
{
  "cniVersion": "1.0.0",
  "name": "vpc20",
  "plugins": [
    {
      "type": "galactic-tap",
      "vpc": "20",
      "vpcattachment": "20",
      "namespace": "galactic-system",
      "ipam": {
        "type": "galactic-ipam",
        "ipv4_subnet": "172.20.1.0/24",
        "address_families": ["ipv4"]
      }
    },
    { "type": "galactic-bgp", "vpc": "20", "vpcattachment": "20", "namespace": "galactic-system" }
  ]
}
```

`ipv4_subnet` alone opts the config into pool IPAM with no IPv6 allocation at
all; the resulting `BGPAdvertisement` carries only the IPv4 `/32` prefix.

### Static IP configuration

```json
{
  "cniVersion": "1.0.0",
  "name": "galactic",
  "plugins": [
    {
      "type": "galactic-veth",
      "vpc": "1",
      "vpcattachment": "1",
      "ipam": { "type": "galactic-ipam", "static_ip": "fd00:1::1" }
    },
    { "type": "galactic-bgp", "vpc": "1", "vpcattachment": "1" }
  ]
}
```

### Configuration with terminations

`terminations` goes in `galactic-route`'s own stanza of the conflist's
`plugins` array, not the master plugin's:

```json
{
  "cniVersion": "1.0.0",
  "name": "galactic",
  "plugins": [
    {
      "type": "galactic-veth",
      "vpc": "1",
      "vpcattachment": "1",
      "ipam": { "type": "galactic-ipam", "ipv6_subnet": "fd00:1:ff01::/48" }
    },
    {
      "type": "galactic-route",
      "vpc": "1",
      "vpcattachment": "1",
      "terminations": [
        { "network": "fd00::/48", "via": "fe80::1" },
        { "network": "fd01::/48" }
      ]
    },
    { "type": "galactic-bgp", "vpc": "1", "vpcattachment": "1" }
  ]
}
```

The first termination installs a specific next-hop route; the second installs
an on-link route via the host-side device. `galactic-route` runs between the
master plugin and `galactic-bgp`.

### Tap interface configuration (VM workloads)

```json
{
  "cniVersion": "1.0.0",
  "name": "galactic-tap",
  "plugins": [
    {
      "type": "galactic-tap",
      "vpc": "1",
      "vpcattachment": "1",
      "mtu": 9000,
      "ipam": { "type": "galactic-ipam", "ipv6_subnet": "fd00:10:ff03::/48" }
    },
    { "type": "galactic-bgp", "vpc": "1", "vpcattachment": "1" }
  ]
}
```

`galactic-tap` creates a tap interface in the host namespace, enslaves it
to the VRF, and applies forwarding sysctls. It then runs IPAM (allocating the
subnet shown above) and configures the host gateway exactly as `galactic-veth`
does — see [`galactic-tap` (tap)](#galactic-tap-tap) above. Only
host-device delegation and guest-netns configuration are skipped; the guest VM
still configures its own IP addresses independently once the hypervisor
(Kata, Firecracker, kraftlet/Unikraft) opens the tap fd at runtime.
