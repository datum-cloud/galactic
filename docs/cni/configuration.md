# CNI Configuration

`galactic-cni` is configured through the CNI JSON configuration passed by Multus
(or any CNI manager), plus node-local settings resolved at runtime from the
conflist, environment variables, and (as a last resort) the Kubernetes API.

> Last verified: 2026-07-16 against the current working tree of `internal/cni/config.go`
> and `internal/installer/installer.go`.

## Runtime Configuration

There is no `--node-name` or `--enable-local-ipam` CLI flag on the `galactic-cni`
plugin invocation itself. Instead, `parseConf()` (`internal/cni/config.go`) resolves
node name, kubeconfig, namespace, log file, and log level on every ADD/DEL/CHECK/STATUS
call, reading (in order) the CNI config JSON, environment variables, and a `HostConf`
block parsed out of the conflist at `--conf-file` (default
`/etc/cni/net.d/10-galactic.conflist`). `HostConf` is written by the `galactic-cni init`
subcommand (`internal/installer.Bootstrap`), which runs as the CNI DaemonSet's init
container — see [docs/agents/ARCHITECTURE.md](../agents/ARCHITECTURE.md#known-constraints)
for how the DaemonSet stages it.

### `HostConf` fields (written into the conflist by `galactic-cni init`)

| Field        | Description                                                                                                                      |
| ------------ | -------------------------------------------------------------------------------------------------------------------------------- |
| `NodeName`   | The Kubernetes node name the installer bootstrapped on.                                                                          |
| `Kubeconfig` | Path to the kubeconfig `Bootstrap`/`Run` maintain (`/var/lib/galactic/kubeconfig` by default).                                   |
| `Namespace`  | Kubernetes namespace for BGP CRDs (`galactic-system` by default).                                                                |
| `LogFile`    | Path the plugin logs to (`/var/log/galactic/galactic-cni.log` by default).                                                       |
| `LogLevel`   | Verbosity of plugin logging: `debug`, `info`, `warn`, or `error` (`info` by default). See [Log verbosity](#log-verbosity) below. |

### Resolution precedence

| Setting           | Precedence (highest first)                                                                                                                                                                                                       | Default (if nothing resolves)        |
| ----------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------ |
| Node name         | `GALACTIC_CNI_NODE_NAME` env → `NODE_NAME` env → `HostConf.NodeName` → auto-detect via the Kubernetes API (`detectNodeNameFromAPI`: lists Nodes, matches local interface addresses against `status.addresses[].type=InternalIP`) | _(error: "node name is required")_   |
| Kubeconfig        | `GALACTIC_CNI_KUBECONFIG` env → `HostConf.Kubeconfig`                                                                                                                                                                            | `/var/lib/galactic/kubeconfig`       |
| Namespace         | `namespace` field in the CNI config JSON → `GALACTIC_CNI_NAMESPACE` env → `HostConf.Namespace`                                                                                                                                   | `galactic-system`                    |
| Log file          | `GALACTIC_CNI_LOG_FILE` env → `HostConf.LogFile`                                                                                                                                                                                 | `/var/log/galactic/galactic-cni.log` |
| Log level         | `GALACTIC_CNI_LOG_LEVEL` env → `HostConf.LogLevel`                                                                                                                                                                               | `info`                               |
| Enable local IPAM | `GALACTIC_CNI_ENABLE_LOCAL_IPAM` env only (no conflist field, no CLI flag)                                                                                                                                                       | `false`                              |

The resolved node name is re-exported as the `NODE_NAME` process environment variable
and the resolved kubeconfig as `KUBECONFIG`, since other code in `internal/cni` reads
those directly. Auto-detection exists to tolerate environments (e.g. Kind-based e2e)
where the conflist's hostPath mount isn't populated yet.

### Log verbosity

`setupLogging()` (`internal/cni/config.go`) builds a JSON `slog` handler at the
resolved level. Since each CNI invocation is a fresh, short-lived process, this
level is re-resolved on every ADD/DEL/CHECK/STATUS call — there's no persistent
daemon to reconfigure at runtime.

| Level            | What's logged                                                                                                                                                                                                                                                                                          |
| ---------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `debug`          | Everything: per-resource milestones (VRF/interface/route/IPAM ready, BGP CRDs applied, kernel-level veth/tap/route operations) in addition to `info` and above. Use this when troubleshooting a specific ADD/DEL failure.                                                                              |
| `info` (default) | One line per operation marking start and outcome (`ADD: starting` / `ADD: BGP state published`, `DEL: starting` / `DEL: skipping shared resource cleanup`, `CHECK: starting` / `CHECK: passed`/`failed`, `STATUS: probing API server reachability` / `STATUS: ready`), plus all `warn`/`error` events. |
| `warn`           | Recoverable anomalies only: stale-state repairs (leftover veth/tap from a prior failed ADD), iptables-missing fallback, k8s API retries.                                                                                                                                                               |
| `error`          | Failures only.                                                                                                                                                                                                                                                                                         |

An unrecognized `log_level` value does not fail the CNI operation — it logs a
warning and falls back to `info`.

### `GALACTIC_CNI_ENABLE_LOCAL_IPAM`

When enabled, the plugin performs IP allocation using a built-in IPv6 pool
allocator even when no explicit `ipam` block is present in the CNI config.
This is useful for simple deployments that do not need an external IPAM
plugin.

When local IPAM is active but the config does not specify pool parameters,
the following defaults are used:

| Parameter     | Default                                  |
| ------------- | ---------------------------------------- |
| Pool CIDR     | `fd00:10:ff01::/48`                      |
| Subnet length | `/80`                                    |
| Gateway       | First usable address in the pool (`::1`) |

If an explicit `ipam` block is present in the CNI config, it takes precedence
and this environment variable has no effect on the allocation behavior.

**Type:** bool
**Default:** `false`

## CNI Configuration JSON

The CNI configuration is a JSON object passed at pod creation time. It extends
the standard CNI `PluginConf` with Galactic-specific fields.

### Top-Level Fields

| Field            | Required | Type            | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| ---------------- | -------- | --------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `vpc`            | **Yes**  | `string`        | Base62-encoded VPC identifier (48-bit value). Used to derive VRF names, interface names, and BGP route targets.                                                                                                                                                                                                                                                                                                                                                                                           |
| `vpcattachment`  | **Yes**  | `string`        | Base62-encoded VPC attachment identifier (16-bit value). Paired with `vpc` for deterministic VRF/BGP naming.                                                                                                                                                                                                                                                                                                                                                                                              |
| `interface_type` | No       | `string`        | Interface mode: `"veth"` (default, for containers) or `"tap"` (for VMs such as Kata, Firecracker, QEMU). Both modes run IPAM and SRv6/BGP publish; `tap` mode only skips host-device delegation and guest-netns configuration (see the Tap mode section below).                                                                                                                                                                                                                                           |
| `mtu`            | No       | `int`           | MTU for the host-side interface. For `veth` mode this applies to both veth endpoints; for `tap` mode it applies to the tap interface.                                                                                                                                                                                                                                                                                                                                                                     |
| `terminations`   | No       | `[]Termination` | Array of static routes to add on the host side (see Termination sub-fields below).                                                                                                                                                                                                                                                                                                                                                                                                                        |
| `namespace`      | No       | `string`        | Kubernetes namespace used to look up the `BGPRouter` CRD. Resolution order: this field → `GALACTIC_CNI_NAMESPACE` env → `HostConf.Namespace` (conflist) → `galactic-system`. See [Runtime Configuration](#runtime-configuration) above.                                                                                                                                                                                                                                                                   |
| `ipam`           | No*      | `IPAM`          | IP address management configuration (see IPAM sub-fields below). *Required unless `GALACTIC_CNI_ENABLE_LOCAL_IPAM` is set — applies identically in `veth` and `tap` mode. In `tap` mode `cmdAdd` (`internal/cni/ops_add.go`) calls `allocateIPAM` unconditionally (unlike `veth` mode, which checks first), so omitting both `ipam` and `GALACTIC_CNI_ENABLE_LOCAL_IPAM` currently produces a nil-pointer panic in `tap` mode rather than a clean validation error — always set one or the other for tap. |

Standard CNI fields (`cniVersion`, `name`, `dns`, `runtimeConfig`) are also
supported via the embedded `types.PluginConf`.

### Interface Types

#### `veth` (default)

Creates a veth pair: one endpoint stays in the host namespace (named
`G<vpc, zero-padded to 9><vpcattachment, zero-padded to 3>H`, e.g. `G0000000010010H`)
and the other is moved into the container via the host-device CNI plugin
(renamed to the `CNI_IFNAME` value, typically `eth0`). The guest interface
receives an IP address from IPAM and a default route via the pool gateway.

#### `tap`

Creates a tap interface in the host namespace (same naming pattern as the veth
host endpoint: `G<vpc9><vpcattachment3>H`) and enslaves it to the VRF. No
interface is moved into the container — the tap fd is managed directly by the
guest VM hypervisor, so `tap` mode skips host-device delegation and guest-netns
configuration. Unlike an earlier version of this plugin, `tap` mode is **not**
"no IPAM, no BGP": `cmdAdd` calls `allocateIPAM` to allocate a subnet/gateway,
`configureHostGateway` to assign the gateway on the host tap and install the pod
subnet route into the VRF table, includes the resulting `ips`/`routes` in the CNI
result (interface index `0`, the host tap — there is no guest interface entry),
and then `publishBGPStateK8s` to create the SRv6 ingress route and
`BGPVRFInstance`/`BGPAdvertisement` CRDs, exactly as `veth` mode does. The guest
VM still configures its own IP addresses independently (the CNI-allocated
subnet/gateway describe only the host-side BGP-advertised state).

> **Note:** Tap mode is intended for VM-based workloads (Kata, Firecracker,
> QEMU) where the hypervisor opens the tap fd and handles guest networking.

### IPAM Fields

| Field        | Required               | Type     | Description                                                                                                                                                                                                                                                                    |
| ------------ | ---------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `type`       | Conditionally required | `string` | `"pool"` or `"static"`. Determines IP allocation strategy. Required whenever an `ipam` block is present; only defaults to `"pool"` when the entire `ipam` block is omitted and `GALACTIC_CNI_ENABLE_LOCAL_IPAM` is set — an `ipam` block with an empty `type` is a hard error. |
| `pool`       | Conditionally required | `string` | IPv6 CIDR pool (e.g. `"fd00:10:ff01::/48"`) from which subnets are allocated. Required when `type` is `"pool"`.                                                                                                                                                                |
| `gateway`    | No                     | `string` | IPv6 gateway address. If omitted, uses the first usable address in the pool (host bits = 1). Must be within the pool CIDR.                                                                                                                                                     |
| `subnet_len` | No                     | `int`    | Prefix length per allocation. Default is `80` (giving 2^48 addresses per pod subnet). Pool prefix must be <= this value.                                                                                                                                                       |
| `static_ip`  | Conditionally required | `string` | A single IPv6 address to assign when `type` is `"static"`.                                                                                                                                                                                                                     |

#### IPAM `type=pool`

Allocates a `/subnet_len` subnet (default `/80`) from the pool CIDR. Thread-safe
in-memory allocation. Allocations are ephemeral (lost on process restart);
deallocation during `cmdDel` looks up the subnet from a `BGPAdvertisement` CRD
annotation on the host.

#### IPAM `type=static`

Validates and assigns a single IPv6 address with a `/64` mask. No deallocation
needed.

> **Note:** The plugin uses IPv6 only — both the pool allocator and static
> allocator explicitly reject IPv4 addresses.

### Termination Fields

Each entry in the `terminations` array has the following fields:

| Field     | Required | Type     | Description                                                                                |
| --------- | -------- | -------- | ------------------------------------------------------------------------------------------ |
| `network` | **Yes**  | `string` | CIDR prefix for a static route (e.g. `"fd00::/48"`).                                       |
| `via`     | No       | `string` | Next-hop gateway IP. If omitted, a link-local route is installed via the host-side device. |

Used in `cmdAdd` to install routes into the VRF table for each termination
entry. Deleted in `cmdDel` in reverse order.

## Example Configurations

### Minimal configuration (overlay)

```json
{
  "cniVersion": "0.3.1",
  "name": "galactic",
  "type": "galactic-cni",
  "vpc": "1",
  "vpcattachment": "1"
}
```

Omits `namespace` (defaults to `galactic-system`), `ipam`, and `terminations`.
Without `GALACTIC_CNI_ENABLE_LOCAL_IPAM` set, no IP address is assigned to the
guest interface. With `GALACTIC_CNI_ENABLE_LOCAL_IPAM` set, a subnet is allocated
from the built-in pool.

### Full pool-based configuration (testvpc)

```json
{
  "cniVersion": "0.3.1",
  "name": "testvpc",
  "type": "galactic-cni",
  "vpc": "10",
  "vpcattachment": "10",
  "namespace": "galactic-system",
  "ipam": {
    "type": "pool",
    "pool": "fd00:10:ff02::/48",
    "gateway": "fd00:10:ff02::1",
    "subnet_len": 80
  }
}
```

### Static IP configuration

```json
{
  "cniVersion": "0.3.1",
  "name": "galactic",
  "type": "galactic-cni",
  "vpc": "1",
  "vpcattachment": "1",
  "ipam": {
    "type": "static",
    "static_ip": "fd00:1::1"
  }
}
```

### Configuration with terminations

```json
{
  "cniVersion": "0.3.1",
  "name": "galactic",
  "type": "galactic-cni",
  "vpc": "1",
  "vpcattachment": "1",
  "terminations": [
    { "network": "fd00::/48", "via": "fe80::1" },
    { "network": "fd01::/48" }
  ],
  "ipam": {
    "type": "pool",
    "pool": "fd00:1:ff01::/48"
  }
}
```

The first termination installs a specific next-hop route; the second installs
a link-local route via the host-side device.

### Tap interface configuration (VM workloads)

```json
{
  "cniVersion": "0.3.1",
  "name": "galactic-tap",
  "type": "galactic-cni",
  "vpc": "1",
  "vpcattachment": "1",
  "interface_type": "tap",
  "mtu": 9000,
  "ipam": {
    "type": "pool",
    "pool": "fd00:10:ff03::/48"
  }
}
```

Tap mode creates a tap interface in the host namespace, enslaves it to the
VRF, and applies forwarding sysctls. It then runs IPAM (allocating the subnet
shown above) and SRv6/BGP publish exactly as `veth` mode does — see the `tap`
description under Interface Types above. Only host-device delegation and
guest-netns configuration are skipped; the guest VM still configures its own
IP addresses independently once the hypervisor (Kata, Firecracker, QEMU) opens
the tap fd at runtime. The `ipam` block (or `GALACTIC_CNI_ENABLE_LOCAL_IPAM`)
is required here for the same reason it is in `veth` mode.
