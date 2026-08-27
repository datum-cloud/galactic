# CNI Environment Variables & Runtime Configuration

Node-local settings for the `galactic-cni` DaemonSet — everything an
**operator** tunes without touching a `NetworkAttachmentDefinition`. For the
per-attachment conflist fields a **developer** sets when authoring a NAD, see
[Conflist Field Reference](conflist-reference.md) instead. Start at
[docs/cni/README.md](README.md) if you landed here directly.

> Last verified: 2026-08-27 against the current working tree of
> `internal/cni/`, `internal/cnitap/`, `internal/cnibgp/`,
> `internal/installer/installer.go`, `internal/config/cni.go`,
> `internal/config/ipam.go`, `internal/hostconf/`, and
> `internal/plumbing/ebpf/attach/`.

There is no `--node-name` or similar CLI flag on any plugin's own invocation.
Instead, each binary's own `parseConf()` resolves node-level settings on every
ADD/DEL/CHECK/STATUS call, reading (in order) the CNI config JSON, environment
variables, and a `HostConf` block parsed out of the conflist at `--conf-file`
(default `/etc/cni/net.d/10-galactic.conflist` — this is the one *static*,
node-level conflist every binary shares; not the per-attachment `plugins[]`
conflist described in the [Conflist Field Reference](conflist-reference.md)).
`HostConf` is written by the `galactic-cni init` subcommand
(`internal/installer.Bootstrap`) — `galactic-cni` is a separate installer
binary, never itself a CNI plugin, whose `init`/`run` subcommands run as the
CNI DaemonSet's init and long-running containers respectively — see
[docs/agents/ARCHITECTURE-CNI.md](../agents/ARCHITECTURE-CNI.md#known-constraints)
for how the DaemonSet stages it.

`galactic-ipam` and `galactic-route` have no Kubernetes dependency at all, so
they resolve only `LogFile`/`LogLevel` from `HostConf` — never `NodeName` or
`Kubeconfig`, and never fall back to the Kubernetes API.

## `HostConf` fields (written into the conflist by `galactic-cni init`)

| Field            | Description                                                                                                                                                                                                                                                                                                                          |
| ---------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `NodeName`       | The Kubernetes node name the installer bootstrapped on.                                                                                                                                                                                                                                                                              |
| `Kubeconfig`     | Path to the kubeconfig `Bootstrap`/`Run` maintain (`/var/lib/galactic/kubeconfig` by default).                                                                                                                                                                                                                                       |
| `Namespace`      | Kubernetes namespace for BGP CRDs (`galactic-system` by default).                                                                                                                                                                                                                                                                    |
| `LogFile`        | Path the plugin logs to (`/var/log/galactic/galactic-cni.log` by default, shared across every binary in the chain).                                                                                                                                                                                                                  |
| `LogLevel`       | Verbosity of plugin logging: `debug`, `info`, `warn`, or `error` (`info` by default). See [Log verbosity](#log-verbosity) below.                                                                                                                                                                                                     |
| `NAT66ShardSIDs` | Comma-separated list of every live `galactic-nat66` shard's `Status.ShardSID`, resolved once by `galactic-cni init` from `GALACTIC_CNI_NAT66_SHARD_SIDS` and written here so a per-pod CNI invocation can read it. See [`GALACTIC_CNI_NAT66_SHARD_SIDS`](#galactic_cni_nat66_shard_sids) below.                                      |
| `EBPFInterfaces` | Comma-separated interface list the eBPF uSID datapath attaches its ingress hook to, resolved once by `galactic-cni init` (env override or auto-detection) and written here for the same reason as `NAT66ShardSIDs`. See [`GALACTIC_CNI_EBPF_INTERFACES`](#galactic_cni_ebpf_interfaces-and-galactic_cni_ebpf_filter_priority) below. |

## Resolution precedence

| Setting              | Precedence (highest first)                                                                                                                                                                                                       | Default (if nothing resolves)        | Resolved by                                     |
| -------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------ | ----------------------------------------------- |
| Node name            | `GALACTIC_CNI_NODE_NAME` env → `NODE_NAME` env → `HostConf.NodeName` → auto-detect via the Kubernetes API (`detectNodeNameFromAPI`: lists Nodes, matches local interface addresses against `status.addresses[].type=InternalIP`) | _(error: "node name is required")_   | `galactic-veth`, `galactic-tap`, `galactic-bgp` |
| Kubeconfig           | `GALACTIC_CNI_KUBECONFIG` env → `HostConf.Kubeconfig` → (if still unresolved) `GALACTIC_CNI_KUBERNETES_CONFIG` env (legacy alias) → `HostConf.Kubeconfig`                                                                        | `/var/lib/galactic/kubeconfig`       | `galactic-veth`, `galactic-tap`, `galactic-bgp` |
| Namespace            | `namespace` field in the CNI config JSON → `GALACTIC_CNI_NAMESPACE` env → `HostConf.Namespace`                                                                                                                                   | `galactic-system`                    | `galactic-veth`, `galactic-tap`, `galactic-bgp` |
| Log file             | `GALACTIC_CNI_LOG_FILE` env → `HostConf.LogFile`                                                                                                                                                                                 | `/var/log/galactic/galactic-cni.log` | every binary in the chain                       |
| Log level            | `GALACTIC_CNI_LOG_LEVEL` env → `HostConf.LogLevel`                                                                                                                                                                               | `info`                               | every binary in the chain                       |
| NAT66 shard SIDs     | `GALACTIC_CNI_NAT66_SHARD_SIDS` env (`galactic-cni init`/`run` only) → `HostConf.NAT66ShardSIDs`                                                                                                                                 | _(empty: no shard configured)_       | `galactic-cni init`, `galactic-bgp`             |
| eBPF interfaces      | `GALACTIC_CNI_EBPF_INTERFACES` env → `HostConf.EBPFInterfaces` (bridged back into the env var for `galactic-bgp`'s own process, see below) → auto-detect (interface(s) carrying the default IPv6 route)                          | _(auto-detected)_                    | `galactic-cni init`/`run`, `galactic-bgp`       |
| eBPF filter priority | `GALACTIC_CNI_EBPF_FILTER_PRIORITY` env (plain `os.Getenv`, no `HostConf`/conflist tier)                                                                                                                                         | `1`                                  | `galactic-cni init`/`run`                       |

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

## Log verbosity

Each binary's own `setupLogging()` builds a JSON `slog` handler at the
resolved level. Since every CNI invocation is a fresh, short-lived process,
this level is re-resolved on every ADD/DEL/CHECK/STATUS call, in every
binary — there's no persistent daemon to reconfigure at runtime, and every
binary shares the same log file by default so a single chain invocation's
log lines interleave in call order.

| Level            | What's logged                                                                                                                                                                                                                                              |
| ---------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `debug`          | Everything: per-resource milestones (VRF/interface/route/IPAM ready, BGP CRDs applied, kernel-level operations) in addition to `info` and above. Use this when troubleshooting a specific ADD/DEL failure.                                                 |
| `info` (default) | One line per operation marking start and outcome (`ADD: starting` / `ADD: BGP state published`, `DEL: starting` / `DEL: skipping shared resource cleanup`, `CHECK: starting` / `CHECK: passed`/`failed`, `STATUS: ready`), plus all `warn`/`error` events. |
| `warn`           | Recoverable anomalies only: stale-state repairs, k8s API retries.                                                                                                                                                                                          |
| `error`          | Failures only.                                                                                                                                                                                                                                             |

An unrecognized `log_level` value does not fail the CNI operation — it logs a
warning and falls back to `info`.

## `GALACTIC_CNI_EBPF_INTERFACES` and `GALACTIC_CNI_EBPF_FILTER_PRIORITY`

Both configure the eBPF uSID datapath's TC-BPF ingress hook
(`internal/plumbing/ebpf/attach`), not IPAM/BGP — related to, but distinct
from, [#458](https://github.com/datum-cloud/galactic/issues/458)'s proposal
to promote `GALACTIC_CNI_EBPF_INTERFACES` to a per-node `BGPRouter.spec`
field; as of this writing it is still env-only.

- **`GALACTIC_CNI_EBPF_INTERFACES`** — comma-separated list of interface
  names (whitespace trimmed, duplicates/empties removed) to attach the
  ingress hook to. When set, `attach.ResolveInterfaces` uses this list
  directly and skips auto-detection entirely. When unset, the
  interface(s) carrying the default IPv6 route are auto-detected. Either
  way, any resolved interface that is itself a Linux bonding master is
  expanded to include its slave interfaces, since ingress classification
  happens on the slaves, not the master. This is the explicit override
  for multi-homed nodes where auto-detection is ambiguous — see
  [#456](https://github.com/datum-cloud/galactic/pull/456)/[#457](https://github.com/datum-cloud/galactic/pull/457)
  for the auto-detect/bond-slave-expansion fixes that made it a should-have
  rather than a must-have on every cluster.

  This one is not resolved through the plain env-var-only precedence used
  above: `galactic-cni init` (`Bootstrap`) resolves it once, in its own
  real pod environment, and writes the result into `HostConf.EBPFInterfaces`
  in the static per-node conflist. A per-pod `galactic-bgp` invocation never
  sees the env var directly (a CNI plugin's exec environment carries none
  of the DaemonSet pod's env) — it reads `HostConf.EBPFInterfaces` instead
  and bridges it back into `GALACTIC_CNI_EBPF_INTERFACES` on its own process
  before calling `attach.ResolveInterfaces`/the `srv6` package's node-address
  resolution, so both paths converge on the same interface list. An
  operator who sets the env var directly on a CNI plugin's own exec
  environment (not just the DaemonSet container's) is never overridden.

  **Type:** comma-separated string · **Default:** _(auto-detected)_

- **`GALACTIC_CNI_EBPF_FILTER_PRIORITY`** — overrides the `tc` priority the
  ingress filter attaches at. Cilium also runs its own tc/bpf programs on
  the same native-device ingress hook, and the default has not been
  validated against every Cilium version/datapath mode for a collision;
  override if a deployment's Cilium install needs this filter at a
  different priority to run in the intended order relative to Cilium's
  own. An invalid (non-`uint16`) value logs a warning and falls back to
  the default rather than failing.

  **Type:** `uint16` · **Default:** `1` (highest/lowest-numbered priority
  `tc` allows)

## `GALACTIC_CNI_NAT66_SHARD_SIDS`

Comma-separated list of every live `galactic-nat66` shard's
`Status.ShardSID` — the fabric-wide membership list
`internal/plumbing/srv6.EgressDefaultRouteAdd` needs to install a tenant
VRF's default egress route across every shard, since no single Kubernetes
CRD is visible across this multi-cluster fabric's separate clusters/API
servers the way BGP itself is. Same "operator-supplied, no in-cluster
derivation yet" status as `GALACTIC_GATEWAY_SRV6_ADDRESS`.

Resolved the same way as `GALACTIC_CNI_EBPF_INTERFACES` above: `galactic-cni
init` reads it once from its own pod env and writes it into
`HostConf.NAT66ShardSIDs`; `galactic-bgp` (invoked per-pod, not a
long-lived process with configurable env) reads it from there. Unset or
empty means no shard configured yet — a VRF gets no default egress route,
the same behavior as before this mechanism existed, not an error.

**Type:** comma-separated string · **Default:** _(empty — no shard
configured)_

## `GALACTIC_CNI_KUBERNETES_CONFIG`

Legacy alias for `GALACTIC_CNI_KUBECONFIG`. Consulted only if
`GALACTIC_CNI_KUBECONFIG` (env or conflist) leaves `Kubeconfig` still equal
to the compiled-in default (`/var/lib/galactic/kubeconfig`); prefer
`GALACTIC_CNI_KUBECONFIG` in new configuration.

**Type:** string (filesystem path) · **Default:** `/var/lib/galactic/kubeconfig`

## `GALACTIC_IPAM_ENABLE_LOCAL_IPAM`

Read only by `galactic-ipam` (`internal/config/ipam.go`) — renamed from the
historical `GALACTIC_CNI_ENABLE_LOCAL_IPAM`, which no longer exists at all.
The old name could manufacture an `"ipam"` block out of thin air even when
the master plugin's own config had none; the new one can't; it only fills
in a default IPv6 pool CIDR when an `"ipam"` block is present but specifies
neither `static_ip` nor a subnet:

| Parameter     | Default                                  |
| ------------- | ---------------------------------------- |
| Pool CIDR     | `fd00:10:ff01::/64`                      |
| Subnet length | `/96`                                    |
| Gateway       | First usable address in the pool (`::1`) |

Whether IPAM runs at all is decided **solely** by whether `"ipam"` is present
in the master plugin's own stanza — no environment variable, on either side
of this rename, can trigger or suppress that decision. See
[IPAM Fields](conflist-reference.md#ipam-fields) in the Conflist Field
Reference and `internal/cniipam`'s package doc comment for the full explicit
contract.

**Type:** bool
**Default:** `false`
