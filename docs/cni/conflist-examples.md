# CNI Conflist Examples

Worked, copy-pasteable conflists exercising every IPAM mode, terminations,
and tap/VM workloads. Each field used below is documented in the
[Conflist Field Reference](conflist-reference.md); node-local
`GALACTIC_CNI_*` env vars are documented separately in
[Environment Variables & Runtime Configuration](environment-variables.md).
Start at [docs/cni/README.md](README.md) if you landed here directly.

> Last verified: 2026-08-27 — kept in sync with
> [Conflist Field Reference](conflist-reference.md); see that document's own
> verification note for the source files these examples exercise.

Every example below is a full conflist (a `NetworkAttachmentDefinition`'s
`spec.config`, or an equivalent standalone conflist file) — not a single
plugin object — per [Chain structure](configuration.md#chain-structure).

## Minimal configuration (overlay)

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

## Pool IPAM, IPv6-only (testvpc)

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

## Pool IPAM, dual-stack

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

## Pool IPAM, IPv4-only (tap)

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

## Pre-decided dual-stack addresses (`addresses`)

The shape a `NetworkAttachmentDefinition` takes when the platform has already
allocated this interface's addresses:

```json
{
  "cniVersion": "1.0.0",
  "name": "vpc60",
  "plugins": [
    {
      "type": "galactic-tap",
      "vpc": "60",
      "vpcattachment": "60",
      "namespace": "galactic-system",
      "ipam": {
        "type": "galactic-ipam",
        "addresses": [
          { "address": "fd20:60:ff03:0:1::/96", "gateway": "fd20:60:ff03::1" },
          { "address": "203.0.113.17/32", "gateway": "203.0.113.1" }
        ]
      }
    },
    { "type": "galactic-bgp", "vpc": "60", "vpcattachment": "60", "namespace": "galactic-system" }
  ]
}
```

The guest is configured with `fd20:60:ff03:0:1::/96` and `203.0.113.17/32` —
the exact prefixes given, not a re-derived `/64` and not a pool allocation —
and the resulting `BGPAdvertisement` carries both. Drop either entry for a
single-family attachment.

## Static IP configuration

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

## Configuration with terminations

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

## Tap interface configuration (VM workloads)

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
does — see [`galactic-tap` (tap)](conflist-reference.md#galactic-tap-tap) in
the Conflist Field Reference. Only host-device delegation and guest-netns
configuration are skipped; the guest VM still configures its own IP addresses
independently once the hypervisor (Kata, Firecracker, kraftlet/Unikraft) opens
the tap fd at runtime.
