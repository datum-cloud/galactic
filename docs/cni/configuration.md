# CNI Configuration

`galactic-cni` is configured through the CNI JSON configuration passed by Multus
(or any CNI manager). Additionally, the binary requires a node name at runtime
via an environment variable or CLI flag.

## Runtime Configuration

The `galactic-cni` binary requires the node name to scope BGP advertisement
CRD creation. It also supports an optional built-in IPAM mode for deployments
that do not configure an explicit `ipam` block in the CNI config.

| Option | Environment Variable | CLI Flag | Default |
|---|---|---|---|
| Node name | `GALACTIC_CNI_NODE_NAME` | `--node-name` | _(required)_ |
| Enable local IPAM | `GALACTIC_CNI_ENABLE_LOCAL_IPAM` | `--enable-local-ipam` | `false` |

### `--node-name` / `GALACTIC_CNI_NODE_NAME`

The Kubernetes node name where the container is running. Used to create the
`BGPAdvertisement` CRD on the correct `BGPRouter`. `NODE_NAME` is also accepted
as a fallback environment variable; the resolved value is re-exported as
`NODE_NAME` before the CNI ADD/DEL logic runs, since that's what it reads
internally.

**Type:** string
**Required:** yes

### `--enable-local-ipam` / `GALACTIC_CNI_ENABLE_LOCAL_IPAM`

When enabled, the plugin performs IP allocation using a built-in IPv6 pool
allocator even when no explicit `ipam` block is present in the CNI config.
This is useful for simple deployments that do not need an external IPAM
plugin.

When local IPAM is active but the config does not specify pool parameters,
the following defaults are used:

| Parameter | Default |
|---|---|
| Pool CIDR | `fd00:10:ff01::/48` |
| Subnet length | `/80` |
| Gateway | First usable address in the pool (`::1`) |

If an explicit `ipam` block is present in the CNI config, it takes precedence
and this flag has no effect on the allocation behavior.

**Type:** bool
**Default:** `false`

## CNI Configuration JSON

The CNI configuration is a JSON object passed at pod creation time. It extends
the standard CNI `PluginConf` with Galactic-specific fields.

### Top-Level Fields

| Field | JSON Key | Required | Type | Description |
|---|---|---|---|---|
| `vpc` | `"vpc"` | **Yes** | `string` | Base62-encoded VPC identifier (48-bit value). Used to derive VRF names, interface names, and BGP route targets. |
| `vpcattachment` | `"vpcattachment"` | **Yes** | `string` | Base62-encoded VPC attachment identifier (16-bit value). Paired with `vpc` for deterministic VRF/BGP naming. |
| `interface_type` | `"interface_type"` | No | `string` | Interface mode: `"veth"` (default, for containers) or `"tap"` (for VMs such as Kata, Firecracker, QEMU). |
| `srv6_sid` | `"srv6_sid"` | No | `string` | A pre-computed USID (a bare `/128` IPv6 address, or an address with an explicit `/128` CIDR suffix) used verbatim as the SRv6 End.DT46 ingress decap SID for this endpoint. When omitted or empty, SRv6 ingress setup is skipped entirely — no encoding of `vpc`/`vpcattachment` into the address happens in the plugin. Ignored in `tap` mode (SRv6/BGP setup is skipped for tap interfaces regardless of this field). |
| `mtu` | `"mtu"` | No | `int` | MTU for the host-side interface. For `veth` mode this applies to both veth endpoints; for `tap` mode it applies to the tap interface. |
| `terminations` | `"terminations"` | No | `[]Termination` | Array of static routes to add on the host side (see Termination sub-fields below). |
| `namespace` | `"namespace"` | No | `string` | Kubernetes namespace used to look up the `BGPRouter` CRD. Defaults to `"default"` if omitted. |
| `ipam` | `"ipam"` | No* | `IPAM` | IP address management configuration (see IPAM sub-fields below). *Required unless `--enable-local-ipam` is set or `interface_type` is `"tap"`. |

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
guest VM hypervisor. IPAM and SRv6/BGP setup are skipped entirely in tap mode;
the VM configures its own networking.

> **Note:** Tap mode is intended for VM-based workloads (Kata, Firecracker,
> QEMU) where the hypervisor opens the tap fd and handles guest networking.

### IPAM Fields

| Field | JSON Key | Required | Type | Description |
|---|---|---|---|---|
| `type` | `"type"` | Conditionally required | `string` | `"pool"` or `"static"`. Determines IP allocation strategy. Required whenever an `ipam` block is present; only defaults to `"pool"` when the entire `ipam` block is omitted and `--enable-local-ipam` is set — an `ipam` block with an empty `type` is a hard error. |
| `pool` | `"pool"` | Conditionally required | `string` | IPv6 CIDR pool (e.g. `"fd00:10:ff01::/48"`) from which subnets are allocated. Required when `type` is `"pool"`. |
| `gateway` | `"gateway"` | No | `string` | IPv6 gateway address. If omitted, uses the first usable address in the pool (host bits = 1). Must be within the pool CIDR. |
| `subnet_len` | `"subnet_len"` | No | `int` | Prefix length per allocation. Default is `80` (giving 2^48 addresses per pod subnet). Pool prefix must be <= this value. |
| `static_ip` | `"static_ip"` | Conditionally required | `string` | A single IPv6 address to assign when `type` is `"static"`. |

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

| Field | JSON Key | Required | Type | Description |
|---|---|---|---|---|
| `network` | `"network"` | **Yes** | `string` | CIDR prefix for a static route (e.g. `"fd00::/48"`). |
| `via` | `"via"` | No | `string` | Next-hop gateway IP. If omitted, a link-local route is installed via the host-side device. |

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
  "vpcattachment": "1",
  "srv6_sid": "2001:db8:ff01::1"
}
```

Omits `namespace` (defaults to `"default"`), `ipam`, and `terminations`.
Without the `--enable-local-ipam` flag, no IP address is assigned to the
guest interface. With `--enable-local-ipam`, a subnet is allocated from the
built-in pool.

### Full pool-based configuration (testvpc)

```json
{
  "cniVersion": "0.3.1",
  "name": "testvpc",
  "type": "galactic-cni",
  "vpc": "10",
  "vpcattachment": "10",
  "namespace": "galactic-system",
  "srv6_sid": "2001:db8:ff02::1",
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
  "srv6_sid": "2001:db8:ff01::1",
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
  "srv6_sid": "2001:db8:ff01::1",
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
  "mtu": 9000
}
```

Tap mode creates a tap interface in the host namespace, enslaves it to the
VRF, and applies forwarding sysctls. No IPAM or SRv6/BGP setup is configured —
the guest VM manages its own IP addresses. The tap fd is opened by the VM
hypervisor (Kata, Firecracker, QEMU) at runtime. An `srv6_sid` field is
accepted here but has no effect, since tap-mode `cmdAdd` returns before the
BGP/SRv6 publish step is ever reached.
