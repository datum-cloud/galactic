# Architecture

> Galactic is the SRv6 data plane for multi-cloud VPC networking, deployed as two
> binaries on each Kubernetes node: a CNI plugin that attaches containers to VPC
> networks, and an agent that manages kernel SRv6 routes and distributes L3VPN BGP
> paths via an embedded GoBGP server.

_Last updated: 2026-06-14_

---

## Overview

Galactic implements VPC isolation and cross-cluster reachability using Linux SRv6.
When a pod is attached to a VPC, the CNI plugin creates the required kernel state
(VRF, veth pair, SRv6 ingress route) and injects L3VPN BGP paths into the
node-local GoBGP daemon. GoBGP distributes those paths to a BGP route reflector,
enabling pods on different nodes or clusters to reach each other via
SRv6-encapsulated traffic.

VPC and VPCAttachment CRDs are owned by a separate companion operator
(`go.miloapis.com/cosmos`). Galactic receives pre-populated identifiers through the
CNI config and acts on them without running its own CRD controllers.

### SRv6 SID encoding

Each container endpoint is assigned a deterministic SRv6 SID:

```
[SRv6 locator prefix (≤64 bits)] | [VPC ID (48 bits)] | [VPCAttachment ID (16 bits)]
```

All nodes in the same VPC derive the same BGP Route Target via `fnv32a(vpcHex)`,
enabling automatic cross-node path import without explicit RT configuration.

---

## Repository Layout

```
galactic/
├── cmd/
│   ├── galactic-cni/    # CNI binary
│   └── galactic-agent/  # Agent binary
├── internal/
│   ├── agent/           # Agent run loop; wires GoBGP, health, metrics, bootstrap
│   ├── bootstrap/       # BGPProvider CR lifecycle (create on start, delete on stop)
│   ├── cni/             # CNI cmdAdd / cmdDel
│   │   ├── route/       # Host-side static routes via netlink
│   │   └── veth/        # veth pair management
│   ├── gobgp/           # Embedded GoBGP server lifecycle
│   ├── metrics/         # Prometheus metrics (galactic_agent_*)
│   └── plumbing/        # Low-level kernel and network primitives
│       ├── intf/        # Interface naming, base62↔hex encoding, SRv6 endpoint encode/decode
│       ├── srv6/        # SRv6 ingress route add/del (END.DT46)
│       ├── sysctl/      # Interface sysctl helpers
│       └── vrf/         # Linux VRF create/delete/lookup
├── deploy/
│   ├── galactic-agent/  # Kustomize: DaemonSet, RBAC, ServiceAccount
│   └── containerlab/    # ContainerLab lab topology and scripts
└── containers/
    └── galactic/        # Production Dockerfile (builds galactic CNI binary)
```

---

## Data Flow

See [docs/cni-sequence.md](docs/cni-sequence.md) for the full CNI ADD/DEL sequence diagram.

See [docs/agent-startup.md](docs/agent-startup.md) for the agent startup sequence diagram.

---

## Components

| Component | Binary | Role |
|-----------|--------|------|
| `internal/agent` | `galactic-agent` | Run loop; wires GoBGP, health, metrics, bootstrap |
| `internal/bootstrap` | `galactic-agent` | BGPProvider CR lifecycle |
| `internal/gobgp` | `galactic-agent` | Embedded GoBGP server |
| `internal/metrics` | `galactic-agent` | Prometheus metrics |
| `internal/cni` | `galactic-cni` | CNI cmdAdd / cmdDel |
| `internal/plumbing/intf` | both | Interface naming, base62↔hex encoding, SRv6 endpoint encode/decode |
| `internal/plumbing/srv6` | both | SRv6 ingress route add/del (END.DT46) |
| `internal/plumbing/vrf` | both | Linux VRF create/delete/lookup |
| `internal/plumbing/sysctl` | both | Interface sysctl helpers |

---

## Key Design Decisions

- **Identifiers in the SID.** VPC (48-bit) and VPCAttachment (16-bit) identifiers are packed into the low 64 bits of the SRv6 SID, making forwarding state fully self-describing without a lookup table.
- **Base62 interface names.** Kernel interface names are Base62-encoded to stay within the 15-character limit (`vrfX-Y`, `galX-Y`). The hex form is used for BGP and SRv6; base62 for kernel interfaces.
- **GoBGP embedded, not sidecar.** GoBGP runs in-process so the agent owns its lifecycle and can gate readiness on BGP availability. Peer and policy config is applied by the cosmos operator via `BGPProvider` / `BGPInstance` / `BGPPeer` CRDs.
- **CNI binary auto-detects mode.** The `galactic-cni` binary runs as both the CNI plugin (when `CNI_COMMAND` is set) and a CLI tool. This avoids shipping two separate binaries on the node.

---

## Known Constraints

- **GoBGP RIB is ephemeral.** All BGP state is in-process memory. On restart, sessions and paths must be re-established. The cosmos operator is responsible for re-applying config.
- **No kernel-path unit tests.** `internal/cni`, `internal/plumbing/srv6`, and `internal/plumbing/vrf` require `CAP_NET_ADMIN` and a real kernel. `internal/plumbing/intf` is fully unit-testable (pure functions only). Coverage comes from the e2e suite (`task ci:e2etest`), which only runs on `main` and release tags.
