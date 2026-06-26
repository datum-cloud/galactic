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
`BGPAdvertisement` CRD on the correct `BGPRouter`.

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
| `srv6_locator` | `"srv6_locator"` | **Yes** | `string` | IPv6 prefix (e.g. `2001:db8:ff01::/48`). VPC and VPCAttachment identifiers are encoded into the low 64 bits to produce SRv6 endpoints for BGP advertisements. |
| `mtu` | `"mtu"` | No | `int` | MTU for the host-side veth pair. Passed to `veth.Add()`. |
| `terminations` | `"terminations"` | No | `[]Termination` | Array of static routes to add on the host side (see Termination sub-fields below). |
| `namespace` | `"namespace"` | No | `string` | Kubernetes namespace used to look up the `BGPRouter` CRD. Defaults to `"default"` if omitted. |
| `ipam` | `"ipam"` | No* | `IPAM` | IP address management configuration (see IPAM sub-fields below). *Required unless `--enable-local-ipam` is set. |

Standard CNI fields (`cniVersion`, `name`, `dns`, `runtimeConfig`) are also
supported via the embedded `types.PluginConf`.

### IPAM Fields

| Field | JSON Key | Required | Type | Description |
|---|---|---|---|---|
| `type` | `"type"` | **Yes** | `string` | `"pool"` (default) or `"static"`. Determines IP allocation strategy. |
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
  "srv6_locator": "2001:db8:ff01::/48"
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
  "srv6_locator": "2001:db8:ff02::/48",
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
  "srv6_locator": "2001:db8:ff01::/48",
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
  "srv6_locator": "2001:db8:ff01::/48",
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
