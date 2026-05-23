# BGP Route Reflector Lab — SRv6 uSID

## Purpose

Validates SRv6 uSID L3VPN between two PE nodes over a redundant transit mesh with
dual route reflectors. FRR carries the eBGP/iBGP underlay on every node. PE nodes run
GoBGP for VPNv4 overlay (L3VPN IPv4 unicast). Two FRR-only route reflectors (`rr1`,
`rr2`) reflect VPNv4 routes between the PEs. SRv6 encap mode is `encap.red`
(SRH-less, single-SID path). Transit nodes form an iBGP full mesh within AS 65100.

## Topology

See `network.drawio.xml` for the full topology diagram.

Eight nodes across three roles:

- **PE** (`pe1`, `pe2`) — edge routers running FRR (eBGP underlay) + GoBGP (VPNv4 overlay). Each connects to one transit node.
- **Transit** (`tr1`–`tr4`) — FRR-only, iBGP full mesh within AS 65100. Carry all underlay reachability and SRv6 data-plane traffic.
- **Control** (`rr1`, `rr2`) — FRR-only VPNv4 route reflectors. Each peers with both PEs as RR clients. Connected to `tr3` and `tr4` respectively.

Underlay path: `pe1 — tr1 — (mesh) — tr2 — pe2`. SRv6 data plane follows the same path.

## Addressing

### Loopbacks and SRv6 locators

| Node | Loopback        | Role      | BGP ASN (underlay) | BGP ASN (overlay) |
|------|-----------------|-----------|--------------------|--------------------|
| pe1  | fc00:0:2::1/48  | edge PE   | 65101              | 65000              |
| pe2  | fc00:0:3::1/48  | edge PE   | 65102              | 65000              |
| tr1  | fc00:0:1::1/128 | transit   | 65100              | —                  |
| tr2  | fc00:0:5::1/128 | transit   | 65100              | —                  |
| tr3  | fc00:0:6::1/128 | transit   | 65100              | —                  |
| tr4  | fc00:0:7::1/128 | transit   | 65100              | —                  |
| rr1  | fc00:0:4::1/128 | control   | 65103 (local-as)   | 65000              |
| rr2  | fc00:0:8::1/128 | control   | 65104 (local-as)   | 65000              |

### SRv6 uSID plan

uSID block: `fc00::/32` — 32-bit block | 16-bit node | 16-bit function

| Node | uDT4 SID (VRF blue) | VPN prefix  |
|------|---------------------|-------------|
| pe1  | fc00:0:2:e000::     | 10.0.0.1/32 |
| pe2  | fc00:0:3:e000::     | 10.0.0.2/32 |

### Link subnets (underlay point-to-point)

| Link         | Subnet              | Node A addr        | Node B addr        |
|--------------|---------------------|--------------------|--------------------|
| pe1 – tr1    | 2001:db8:0:1::/64   | tr1 eth1 ::1       | pe1 eth1 ::2       |
| pe2 – tr2    | 2001:db8:0:2::/64   | tr2 eth1 ::1       | pe2 eth1 ::2       |
| tr1 – tr2    | 2001:db8:0:12::/64  | tr1 eth2 ::1       | tr2 eth2 ::2       |
| tr1 – tr3    | 2001:db8:0:13::/64  | tr1 eth3 ::1       | tr3 eth1 ::3       |
| tr1 – tr4    | 2001:db8:0:14::/64  | tr1 eth4 ::1       | tr4 eth1 ::4       |
| tr2 – tr3    | 2001:db8:0:23::/64  | tr2 eth3 ::2       | tr3 eth2 ::3       |
| tr2 – tr4    | 2001:db8:0:24::/64  | tr2 eth4 ::2       | tr4 eth2 ::4       |
| tr3 – tr4    | 2001:db8:0:34::/64  | tr3 eth3 ::3       | tr4 eth3 ::4       |
| tr3 – rr1    | 2001:db8:0:3::/64   | tr3 eth4 ::1       | rr1 eth1 ::2       |
| tr4 – rr2    | 2001:db8:0:4::/64   | tr4 eth4 ::1       | rr2 eth1 ::2       |

## Lab layout

```text
.
├── network.clab.yaml
├── node_files/
│   ├── pe1/     frr.conf  gobgp.conf  startup.sh
│   ├── pe2/     frr.conf  gobgp.conf  startup.sh
│   ├── tr1/     frr.conf  startup.sh
│   ├── tr2/     frr.conf  startup.sh
│   ├── tr3/     frr.conf  startup.sh
│   ├── tr4/     frr.conf  startup.sh
│   ├── rr1/     frr.conf  startup.sh
│   └── rr2/     frr.conf  startup.sh
├── group_files/
│   ├── common/  hosts  vtysh.conf  startup-lib.sh
│   ├── pe/      daemons
│   ├── transit/ daemons
│   └── control/ daemons
├── containers/
│   └── gobgp-pe/  Dockerfile
├── scripts/
│   └── host-setup.sh
└── Taskfile.yaml
```

## Prerequisites

- ContainerLab ≥ 0.54
- Docker with access to `frrouting/frr:latest`
- Custom `gobgp-pe:latest` image (built locally via `task build`)
- Host kernel ≥ 5.18 for SRv6 `encap.red` support
- `task` and standard Linux utilities

## Quick start

```bash
task build     # build gobgp-pe:latest from containers/gobgp-pe/Dockerfile
task up        # apply host sysctls and deploy lab
task inspect   # show node management addresses
```

## Tasks

| Task                 | Description                                         |
|----------------------|-----------------------------------------------------|
| `build`              | Build the custom `gobgp-pe:latest` image            |
| `up`                 | Apply host sysctls then deploy the lab              |
| `down`               | Destroy the lab and remove state                    |
| `reload`             | Full rebuild — destroy then redeploy                |
| `inspect`            | Show running nodes and management addresses         |
| `graph`              | Generate a draw.io diagram for the current topology |
| `host-setup`         | Apply required host sysctls (IPv6 forwarding etc.)  |
| `clean`              | Destroy the lab, remove state, and delete the image |

## Verification

### Underlay BGP

```bash
# All transit iBGP and PE eBGP sessions — expect Established on all links
docker exec clab-network-tr1 vtysh -c "show bgp ipv6 unicast summary"
docker exec clab-network-tr3 vtysh -c "show bgp ipv6 unicast summary"

# PE should learn all other loopbacks through the transit mesh
docker exec clab-network-pe1 vtysh -c "show bgp ipv6 unicast"
docker exec clab-network-pe1 ip -6 route show

# RR loopbacks should be reachable from both PEs
docker exec clab-network-pe1 ping6 -c3 fc00:0:4::1
docker exec clab-network-pe1 ping6 -c3 fc00:0:8::1
```

### Overlay BGP (route reflectors)

```bash
# Both PEs should be Established as RR clients
docker exec clab-network-rr1 vtysh -c "show bgp ipv4 vpn summary"
docker exec clab-network-rr2 vtysh -c "show bgp ipv4 vpn summary"

# VPN table — expect 10.0.0.1/32 and 10.0.0.2/32 with SRv6 SID next-hops
docker exec clab-network-rr1 vtysh -c "show bgp ipv4 vpn"
```

### Overlay BGP (PEs)

```bash
# Session state from the PE side — expect rr1 and rr2 Established
docker exec clab-network-pe1 gobgp neighbor
docker exec clab-network-pe2 gobgp neighbor

# VRF blue RIB — expect both prefixes with correct SRv6 SID next-hops
docker exec clab-network-pe1 gobgp vrf blue rib
docker exec clab-network-pe2 gobgp vrf blue rib
```

### SRv6 data plane

```bash
# Decap rule — End.DT4 seg6local entry for the local uDT4 SID
docker exec clab-network-pe1 ip -6 route show | grep seg6local

# Encap rule — seg6 encap.red route in VRF blue toward the remote PE
docker exec clab-network-pe1 ip route show table 100 | grep seg6
```

### End-to-end connectivity

```bash
docker exec clab-network-pe1 ip vrf exec blue ping -c3 10.0.0.2
docker exec clab-network-pe2 ip vrf exec blue ping -c3 10.0.0.1
```

## Notes

- PE startup scripts program both control and data planes before FRR starts:
  - VRF blue kernel device + dummy0 for VPN endpoint advertisement
  - `ip -6 route add <local-SID> encap seg6local action End.DT4 vrftable 100` — decap
  - `ip route add <remote-prefix> vrf blue encap seg6 mode encap.red segs <remote-SID>` — encap (SRH-less)
- GoBGP runs on PEs with `port = -1` so FRR owns TCP 179 for the eBGP underlay session in the same namespace.
- GoBGP exposes gRPC on `:50051`; use `gobgp -u <mgmt-ip> neighbor` to connect from outside the container.
- RR nodes (`rr1`, `rr2`) present AS 65103/65104 toward transit via `local-as no-prepend replace-as` while running AS 65000 for the overlay iBGP sessions.
- Both PEs peer with both RRs; there is no inter-RR session. Each RR independently reflects all PE client routes.
- The uSID block is `fc00::/32`. Node IDs occupy bits 33–48; function `0xe000` marks End.DT4 (uDT4).
- `encap.red` eliminates the SRH for single-SID paths; the outer IPv6 DA is the remote uDT4 SID directly.
- End.DT4 `flavors usd,next-csid` are not supported on kernel ≤ 6.19 — plain End.DT4 is used and is functionally equivalent for single-SID paths.

## Known issues / limitations

- No automated test suite; validation is manual via the commands above.
- End.DT4 uSD flavor not supported by kernel 6.19.12 (silently ignored). encap.red is applied.
- Transit iBGP full mesh does not scale beyond ~4 nodes; use route reflectors for larger topologies.
- VRF blue route targets are not enforced (both PEs use RT 65000:100); all VPN prefixes are mutually imported.
