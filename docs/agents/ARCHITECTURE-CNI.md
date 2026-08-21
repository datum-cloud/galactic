# Architecture — galactic-cni

> The CNI attach path: a chain of small binaries, staged onto each node by
> the `galactic-cni` installer, that wires containers/VMs into VPC networks
> (VRF, veth/tap, SRv6 uSID datapath registration) and writes
> `BGPAdvertisement`/`BGPVRFInstance` CRDs for `galactic-router` to pick up.

_Last updated: 2026-08-18_

This document covers the CNI side of Galactic only. See
[ARCHITECTURE-ROUTER.md](ARCHITECTURE-ROUTER.md) for the BGP/EVPN control
plane (`galactic-router`) and [ARCHITECTURE-GATEWAY.md](ARCHITECTURE-GATEWAY.md)
for the edge XDP NAT+LB gateway (`galactic-gateway`). This file, together
with those two, supersedes the former monolithic `ARCHITECTURE.md` — see
[AGENTS.md](../../AGENTS.md) for which document to start from for a given
task.

---

## Overview

When a pod or VM is attached to a VPC, a chain of CNI plugins creates the
required kernel state (VRF, veth pair or tap device, host-side routes) and
writes a `BGPAdvertisement` CRD. `galactic-router` (see
[ARCHITECTURE-ROUTER.md](ARCHITECTURE-ROUTER.md)) watches that CRD and
injects the EVPN path into the node-local GoBGP server. `galactic-bgp` also
publishes a per-pod `discoveryv1.EndpointSlice` (when the attachment has an
IPv6 address to carry) — the mechanism the HTTP-ingress extension server
discovers VPC backends through; see
[docs/plans/854-vpc-http-ingress-endpointslice.md](../plans/854-vpc-http-ingress-endpointslice.md)
and [docs/cni/configuration.md](../cni/configuration.md)'s "EndpointSlice
publish" section.

The CNI attach side is a **chain of small binaries**, not one monolithic
plugin: a master plugin (`galactic-veth` for containers, `galactic-tap` for
VM workloads) creates the VRF and host-side interface; an optional
`galactic-route` installs static termination routes; `galactic-bgp` publishes
the BGP/SRv6/eBPF state. IPAM is delegated to a separate `galactic-ipam`
binary via the standard CNI IPAM delegation protocol, not chained. None of
these five binaries are ever installed by hand: `galactic-cni`, a sixth
binary that is never itself a CNI plugin (no NAD ever names it in a `"type"`
field), stages the other five (plus `host-device`) onto the
host from its own `init`/`run` DaemonSet containers. All six ship in the
same `ghcr.io/datum-cloud/galactic-cni` image — see
[Repository Layout](#repository-layout) and
[Module / Package Reference](#module--package-reference) below.

VPC and VPCAttachment CRDs are owned by a separate companion operator
(`go.datum.net/cloud`). Galactic receives pre-populated identifiers through the
CNI config and acts on them.

### SRv6 SID encoding

<!-- TODO(docs): docs/srv6-design.md, referenced here for the full SRv6 design
     (SID encoding/allocation, base62 interface naming, eBPF uSID datapath,
     EVPN Type 5 path construction, worked ContainerLab example), does not
     exist in this repository. Either write it, point this section
     elsewhere, or remove this note — flagged for a human decision. -->

Each attachment endpoint is assigned a /128 USID (Unique Local SID, RFC 8986
Section 3.2). There is no companion-operator-injected `srv6_sid` NAD/config
field: `galactic-bgp` (`internal/cnibgp/bgp.go`'s `registerEBPFDatapath`)
derives the uSID `Block` from the node's `BGPRouter.spec.srv6Locator` via
`uformat.Block`, and registers `locator_table`/`function_table`/`vrf_table`
entries keyed on that `Block` plus this attachment's `Argument` (its
`BGPVRFInstance`'s VRFID) in the eBPF uSID datapath's pinned maps
(`internal/plumbing/ebpf/usidmap`) — no kernel seg6local route is installed
per attachment anymore; the TC-BPF program (`internal/plumbing/ebpf/prog/usid.c`)
is the only ingress/decap path (see Known Constraints below for the cutover
history). If the router lacks either `srv6Locator` or `nodeID`, eBPF
registration is skipped entirely for that attachment (`registerEBPFDatapath`
returns `registered=false`, not an error).

`galactic-router`'s own reconciler independently derives the *same* SID value
from the same inputs (`srv6.ComputeSID`, `internal/plumbing/srv6/usid.go`,
called from `internal/reconcile/reconcile.go`) for the BGP control-plane
side — see [ARCHITECTURE-ROUTER.md](ARCHITECTURE-ROUTER.md) for that half.
The CNI side and the router side compute the same bit layout via separate
code paths (`uformat` is the single source of truth both build on), by
design — see `internal/plumbing/ebpf/doc.go`.

All nodes in the same VPC derive the same BGP Route Target by truncating the
48-bit hex VPC identifier to its low 32 bits (`uint32(v)`), formatted as
`ASN:NN`, enabling automatic cross-node path import without explicit RT
configuration. The RT is also used as the `BGPVRFInstance`'s Route
Distinguisher and import/export Route Target.

---

## Repository Layout

```
galactic/
├── cmd/
│   ├── galactic-cni/        # CNI installer binary (init/run DaemonSet
│   │                        #   subcommands; never itself a CNI plugin)
│   ├── galactic-veth/       # veth master plugin binary
│   ├── galactic-tap/        # tap master plugin binary (VM workloads)
│   ├── galactic-ipam/       # delegated CNI IPAM plugin binary
│   ├── galactic-bgp/        # BGP/SRv6/eBPF publish plugin binary
│   └── galactic-route/      # termination-route plugin binary (optional chain stage)
├── internal/
│   ├── hostconf/            # Shared static-conflist HostConf schema/loader,
│   │                        #   read by every binary in the chain
│   ├── hostgw/              # Host-side gateway address/route configuration,
│   │                        #   called directly by both master plugins
│   ├── crdnames/            # Deterministic BGPVRFInstance/BGPAdvertisement
│   │                        #   CRD name derivation, shared by cnibgp/gc
│   ├── nadpatch/            # NAD annotation patch, shared by cni/cnitap
│   ├── cni/                 # galactic-veth: veth master plugin (cmdAdd/cmdDel/
│   │   │                    #   cmdCheck/cmdStatus, PluginConf parsing, NAD
│   │   │                    #   annotation, host-device delegation)
│   │   ├── ipam/            # Built-in IPv6/IPv4 pool + static IP allocators,
│   │   │                    #   on-disk marker-file persistence
│   │   ├── route/           # Host-side static routes via netlink
│   │   ├── tap/             # Tap interface management (VM workloads)
│   │   └── veth/            # veth pair management
│   ├── cnitap/              # galactic-tap: tap master plugin (mirrors
│   │                        #   internal/cni; no host-device delegation, no
│   │                        #   guest netns)
│   ├── cniipam/              # galactic-ipam: CNI IPAM delegation protocol
│   │                        #   (cmdAdd/cmdDel/cmdCheck/cmdStatus); no k8s
│   │                        #   dependency
│   ├── cnibgp/              # galactic-bgp: BGP/SRv6/eBPF publish plugin;
│   │                        #   learns interface kind + addresses from
│   │                        #   prevResult alone, zero kernel-interface access
│   ├── cniroute/            # galactic-route: termination-route plugin;
│   │                        #   zero Kubernetes dependency
│   ├── installer/           # galactic-cni DaemonSet init/run logic: binary
│   │                        #   staging (all binaries above, one init
│   │                        #   container/image), conflist templating,
│   │                        #   kubeconfig refresh, gRPC health server
│   └── plumbing/            # Low-level kernel and network primitives
│       ├── intf/            # Interface naming, base62↔hex encoding
│       ├── ebpf/             # TC-BPF uSID datapath: preflight, uformat,
│       │                    #   prog (usid.c), attach, usidmap, metrics —
│       │                    #   see internal/plumbing/ebpf/doc.go. (The edge
│       │                    #   gateway's own eBPF datapath — edgeprog,
│       │                    #   edgemap, edgeattach — lives in this same
│       │                    #   umbrella but is out of scope here; see
│       │                    #   ARCHITECTURE-GATEWAY.md.)
│       ├── sysctl/          # Interface sysctl helpers
│       └── vrf/             # Linux VRF create/delete/lookup
├── config/
│   ├── system/              # galactic-system namespace (shared by every component)
│   └── cni/                 # hostNetwork DaemonSet: `init` container stages
│                            #   every chain binary + host-device into
│                            #   /opt/cni/bin and writes the conflist +
│                            #   kubeconfig; `run` container refreshes
│                            #   credentials, manages the eBPF datapath, and
│                            #   serves gRPC health checks
├── deploy/
│   └── containerlab/        # ContainerLab lab topology and scripts
└── containers/
    └── galactic-cni/        # galactic-veth/galactic-tap/-ipam/-bgp/-route
                              #   + host-device image (e2e test and production publish)
```

Production images are published by `.github/workflows/publish.yaml` — see CI/CD below.

---

## Data Flow

See [docs/cni-cmd-sequence.md](../cni/cni-cmd-sequence.md) for the full CNI ADD/DEL sequence diagrams (one unified ADD diagram covering both the veth and tap master-plugin paths, one DEL diagram covering the whole chain), and [docs/architecture/](../architecture/) for C4 context/container/component diagrams of all three Galactic applications, including a component-level diagram of this chain's six binaries.

---

## Components

| Component                  | Binary                                                                   | Role                                                                                                                                      |
| -------------------------- | ------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------- |
| `internal/cni`             | `galactic-veth`                                                          | Veth master plugin: cmdAdd/cmdDel/cmdCheck/cmdStatus, PluginConf parsing, NAD annotation, host-device delegation                          |
| `internal/cnitap`          | `galactic-tap`                                                           | Tap master plugin (mirrors `internal/cni`, no guest netns)                                                                                |
| `internal/cniipam`         | `galactic-ipam`                                                          | Delegated CNI IPAM plugin (no k8s dependency)                                                                                             |
| `internal/cnibgp`          | `galactic-bgp`                                                           | BGP/SRv6/eBPF publish plugin (zero kernel-interface dependency)                                                                           |
| `internal/cniroute`        | `galactic-route`                                                         | Termination-route plugin (no k8s dependency)                                                                                              |
| `internal/installer`       | `galactic-cni`                                                           | DaemonSet `init`/`run` logic: binary staging (every chain binary), conflist/kubeconfig templating, credential refresh, gRPC health server |
| `internal/plumbing/intf`   | every CNI-chain binary                                                   | Interface naming, base62↔hex encoding                                                                                                     |
| `internal/plumbing/ebpf`   | `galactic-cni` (attach/metrics via `run`), `galactic-bgp` (registration) | TC-BPF uSID datapath: preflight, uformat, prog, attach, usidmap, metrics                                                                  |
| `internal/plumbing/vrf`    | every CNI-chain binary                                                   | Linux VRF create/delete/lookup                                                                                                            |
| `internal/plumbing/sysctl` | `galactic-veth`, `galactic-tap`                                          | Interface sysctl helpers                                                                                                                  |

`internal/gc` is the counterpart that reclaims orphaned CRD/VRF/eBPF-entry
state this chain's DEL paths deliberately leave behind — its orphaned-CRD
and kernel-VRF sweep runs inside `galactic-router` (see
[ARCHITECTURE-ROUTER.md](ARCHITECTURE-ROUTER.md)), while its eBPF
`vrf_table` sweep runs inside this component's own `galactic-cni` `run`
container instead, since the pinned map only exists there. See
[docs/gc-cmd-sequence.md](../cni/gc-cmd-sequence.md) for both sweeps' sequence
diagrams and Known Constraints below.

---

## Entry Points

### `cmd/galactic-cni/main.go` — installer

A cobra command (no viper — see External Dependencies below) hosting the two
DaemonSet-lifecycle subcommands (`init`, `run`) that wrap `internal/installer`.
This binary is never itself a CNI plugin — no NAD's `"plugins"` array ever
names it in a `"type"` field, and the container runtime never execs it. Its
only callers are the `galactic-cni` DaemonSet's own `install-cni` init
container and `credential-refresh` long-running container (see Known
Constraints below for the manifest).

- `init` — `--node-name`/`-n` flag (or `GALACTIC_CNI_NODE_NAME`/`NODE_NAME` env),
  calls `installer.Bootstrap(ctx, nodeName)`: stages every binary in the CNI chain
  (`galactic-veth`, `galactic-tap`, `galactic-ipam`, `galactic-bgp`,
  `galactic-route`, `host-device`) onto the host, does a one-shot dual-stack
  node-identity check against the Kubernetes API, and writes `ca.crt`/kubeconfig
  plus the static conflist.
- `run` — `--grpc-health-port` flag (default `5180`), calls `installer.Run(ctx,
  grpcHealthPort)`: serves gRPC health checks, manages the eBPF uSID datapath's
  load/attach lifecycle, and periodically refreshes the kubeconfig token and
  rotates the CNI log file.

`--build-info` and `--version`/`-V` utility flags are also present on the root
command, same as every other binary.

### `cmd/galactic-veth/main.go` — CNI plugin

A cobra command with a single role: the CNI plugin invocation itself (root
command, invoked by the container runtime per the CNI spec). Unlike before the
CNI installer split (see `cmd/galactic-cni/main.go` above), this binary carries
no DaemonSet-lifecycle subcommands at all.

`newRootCommand()` builds a root command with a persistent `--conf-file` flag
(default `cni.DefaultConfFile`, `/etc/cni/net.d/10-galactic.conflist`) plus
`--build-info` and `--version`/`-V` utility flags. There is no `--node-name` or
`--enable-local-ipam` flag on this path — those are resolved entirely inside
`internal/cni` at ADD/DEL/CHECK/STATUS time (see Configuration below). On `RunE`:

1. `PersistentPreRunE` overrides `cni.ConfFile` from `--conf-file` if set.
2. Handle `--build-info`/`--version` and return early if set.
3. If `CNI_COMMAND=VERSION`, encode supported CNI spec versions and return.
4. Otherwise call `cni.RunPlugin()`, which hands control to `skel.PluginMainFuncs`
   (ADD/DEL/CHECK/STATUS read from stdin per the CNI spec); `internal/cni/config.go`'s
   `parseConf()` resolves node name, kubeconfig, namespace, and log file on every
   invocation (conflist → env vars → API auto-detect, in that precedence).

`galactic-veth`'s own ADD creates the VRF, veth pair, and (if `"ipam"` is
present) delegates IPAM and configures the host gateway — it prints its own
CNI result and returns; BGP/SRv6/eBPF publish is `galactic-bgp`'s job,
invoked next by the CNI runtime per conflist order, not by this process.

See [docs/cni-cmd-sequence.md](../cni/cni-cmd-sequence.md) for the full ADD/DEL sequence.

### `cmd/galactic-tap/main.go` — tap master plugin

Mirrors `cmd/galactic-veth/main.go`'s CNI-invocation role exactly (`internal/cnitap.RunPlugin()`)
— both are pure CNI plugins with zero DaemonSet-lifecycle subcommands; that
logic lives solely on the separate `galactic-cni` installer binary, since
there's exactly one init container per node regardless of how many workload
types it serves.
`internal/cnitap` mirrors `internal/cni` (VRF + tap creation, NAD annotation, IPAM
delegation, host gateway configuration) but never delegates to host-device and never
configures a guest netns — the VM hypervisor manages the tap fd directly.

### `cmd/galactic-ipam/main.go` — delegated IPAM plugin

The simplest binary in the chain: no DaemonSet subcommands, no Kubernetes client, no
node-name/kubeconfig resolution. Invoked only via the CNI IPAM delegation protocol
(`github.com/containernetworking/plugins/pkg/ipam.ExecAdd`/`ExecDel`/`ExecCheck`), never
directly from a conflist. `internal/cniipam.RunPlugin()` implements `cmdAdd`/`cmdDel`/
`cmdCheck`/`cmdStatus`; allocation state persists in on-disk marker files under this
node's own filesystem (`internal/cni/ipam.DefaultLockDir`), so `cmdDel` never needs to
read anything back from a CRD.

### `cmd/galactic-bgp/main.go` — BGP/SRv6/eBPF publish plugin

Chained after the master plugin (and, when present, `galactic-route`) per conflist
order, never run standalone. `internal/cnibgp.RunPlugin()` learns everything it needs
— which interface kind was created, what addresses were allocated — from `prevResult`
alone (`RawPrevResult`, not the never-populated typed `PrevResult` field — see
`internal/cnibgp/prevresult.go`), so it has zero kernel-interface dependency of its
own. Unlike `galactic-ipam`/`galactic-route`, it does resolve node name/kubeconfig
(reusing `internal/config.CNIConfig`, the same `GALACTIC_CNI_*` env vars every other
k8s-talking binary in the chain uses) since it talks to the API server for
`BGPVRFInstance`/`BGPAdvertisement` CRUD — via `sigs.k8s.io/controller-runtime/pkg/client`
directly (a bare client, not a manager/reconciler; see External Dependencies).

### `cmd/galactic-route/main.go` — termination-route plugin

Optional chain stage — present only for attachments with `terminations` to install.
`internal/cniroute.RunPlugin()` installs each termination as a VRF-table route via
`internal/cni/route`, deriving the host device name from `(vpc, vpcAttachment)` alone
(identical for a veth or tap master's own host interface, so no interface-kind
inference is needed). No Kubernetes dependency at all.

---

## Configuration

### CNI chain config fields

There is no single `PluginConf` shape anymore — each binary in the chain reads
only the fields its own JSON stanza carries. See
[docs/cni/configuration.md](../cni/configuration.md) for the full per-binary
field tables and seven example conflists; summary:

| Field           | Read by                                                                                                          | Description                                                                                                                                       |
| --------------- | ---------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| `vpc`           | every binary                                                                                                     | Base62-encoded 48-bit VPC identifier                                                                                                              |
| `vpcattachment` | every binary                                                                                                     | Base62-encoded 16-bit VPCAttachment identifier                                                                                                    |
| `namespace`     | `galactic-veth`/`galactic-tap`/`galactic-bgp`                                                                    | Kubernetes namespace for NAD/BGP CRD lookup; resolution order is this field → `GALACTIC_CNI_NAMESPACE` → `HostConf.Namespace` → `galactic-system` |
| `mtu`           | `galactic-veth`/`galactic-tap`                                                                                   | MTU for the host-side interface (veth pair or tap); 0 uses kernel default                                                                         |
| `ipam`          | `galactic-veth`/`galactic-tap` (decides whether to delegate), `galactic-ipam` (reads the block's own sub-fields) | IPAM delegation block; `type` names the delegate binary (`galactic-ipam`). See [docs/cni/configuration.md](../cni/configuration.md#ipam-fields).  |
| `terminations`  | `galactic-route` only                                                                                            | Static routes to install on the host-side interface (`network`, `via`)                                                                            |

There is no `interface_type` field anymore — which binary you invoke *is* the
interface type (`galactic-veth` → veth, `galactic-tap` → tap).

### galactic-veth / galactic-tap / galactic-bgp environment variables

There is no `--node-name`/`--enable-local-ipam` CLI flag on any plugin invocation
path (`--node-name` exists only on the separate `galactic-cni` installer
binary's own `init` subcommand). Each binary's own `parseConf()` resolves the settings below on every
ADD/DEL/CHECK/STATUS call, in the listed precedence, re-exporting the result as a
process env var. `galactic-ipam` and `galactic-route` skip this table entirely —
see [docs/cni/configuration.md](../cni/configuration.md#runtime-configuration).

| Variable                          | Resolution precedence (highest first)                                                                                                                                                           | Default                              | Resolved by                                     |
| --------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------ | ----------------------------------------------- |
| Node name (`NODE_NAME`)           | `GALACTIC_CNI_NODE_NAME` → `NODE_NAME` → `HostConf.NodeName` (conflist) → `detectNodeNameFromAPI()` (matches local interface addrs against Node `InternalIP`)                                   | _(error if still empty)_             | `galactic-veth`, `galactic-tap`, `galactic-bgp` |
| Kubeconfig (`KUBECONFIG`)         | `GALACTIC_CNI_KUBECONFIG` → `HostConf.Kubeconfig` (conflist)                                                                                                                                    | `/var/lib/galactic/kubeconfig`       | `galactic-veth`, `galactic-tap`, `galactic-bgp` |
| Namespace                         | `conf.Namespace` (CNI config JSON) → `GALACTIC_CNI_NAMESPACE` → `HostConf.Namespace` (conflist)                                                                                                 | `galactic-system`                    | `galactic-veth`, `galactic-tap`, `galactic-bgp` |
| Log file                          | `GALACTIC_CNI_LOG_FILE` → `HostConf.LogFile` (conflist)                                                                                                                                         | `/var/log/galactic/galactic-cni.log` | every binary in the chain                       |
| Log level                         | `GALACTIC_CNI_LOG_LEVEL` → `HostConf.LogLevel` (conflist)                                                                                                                                       | `info`                               | every binary in the chain                       |
| `GALACTIC_IPAM_ENABLE_LOCAL_IPAM` | Read directly as an env var by `galactic-ipam` only (`internal/config/ipam.go`); no conflist/CLI-flag equivalent, and it can no longer manufacture an `"ipam"` block that isn't already present | `false`                              | `galactic-ipam` only                            |

`GALACTIC_CNI_ENABLE_LOCAL_IPAM` (the old, master-plugin-side predecessor of the
row above) no longer exists at all — removed along with the dead
`config.CNIGetEnableLocalIPAM()` it backed once IPAM's own env-var handling
moved entirely into `galactic-ipam`.

`HostConf` (`node_name`, `kubeconfig`, `namespace`, `log_file`, `log_level`) is the JSON
shape the `init` installer subcommand writes into the static conflist at
`--conf-file` — the same file every binary in the chain reads (see
`internal/installer/installer.go` and Entry Points above). `log_level`
(`debug`/`info`/`warn`/`error`) controls how much detail each binary's own
`setupLogging()` emits — `info` (the default) logs one line per operation for
start/outcome plus all warnings/errors; `debug` adds per-resource milestones. See
[docs/cni/configuration.md#log-verbosity](../cni/configuration.md#log-verbosity).

### CNI chain ADD result

On a successful ADD, the master plugin (`galactic-veth`/`galactic-tap`)
returns a CNI spec v1.0.0 result with the following structure (veth shown):

```json
{
  "cniVersion": "1.0.0",
  "interfaces": [
    { "name": "G<09-vpc><03-att>H", "mac": "aa:bb:cc:dd:ee:ff", "mtu": 1500, "sandbox": "" },
    { "name": "eth0", "mac": "aa:bb:cc:dd:ee:11", "mtu": 1500, "sandbox": "/proc/<pid>/ns/net" }
  ],
  "ips": [
    { "address": "fd00:10:ff01::1234/80", "gateway": "fd00:10:ff01::1", "interface": 1 }
  ],
  "routes": [
    { "dst": "::/0" }
  ]
}
```

| Field              | Description                                                                                     |
| ------------------ | ----------------------------------------------------------------------------------------------- |
| `interfaces[0]`    | Host-side veth endpoint (`G{vpc}{att}H`); sandbox is empty (host network namespace)             |
| `interfaces[1]`    | Guest-side veth endpoint (`args.IfName`, typically `eth0`); sandbox is the container netns path |
| `ips[0].interface` | Index `1` into `interfaces` — the guest veth carries the pod IP                                 |
| `routes`           | Default route via IPAM gateway (when IPAM is configured)                                        |

The VRF dummy interface (`G{vpc}{att}V`) is **not** reported — it is pre-existing infrastructure created by the `vrf.Add()` plumbing function, not by the CNI attachment itself.

This is the veth-master result. `galactic-tap`'s own result has a single
interface (the host-side tap, empty sandbox, index `0`) — there is no guest
interface entry since the fd is handed off to the VM hypervisor, not moved
into a container netns. Both masters run IPAM identically (if `"ipam"` is
present) and both configure the host gateway (`internal/hostgw`) before
printing their own result — see
[Interface Types](../cni/configuration.md#master-plugin-fields-galactic-veth--galactic-tap)
in the CNI config doc.

The host gateway's IPv4 address is assigned as a `/25` on the host tap (vs.
`/32` everywhere else) so it looks like a real subnet to the VM guest, adding
it with `IFA_F_NOPREFIXROUTE` to suppress the kernel's auto-created connected
route for the wider mask — otherwise this would reintroduce the
subnet-router-anycast hazard that `/32` avoids elsewhere. See
[docs/cni/configuration.md](../cni/configuration.md) for details.

**Every stage after the master plugin passes `prevResult` straight through as
its own result, unchanged** — `galactic-route` and `galactic-bgp` add no
interfaces or IPs of their own. This means the master's own printed result is
the runtime's authoritative CNI result for the whole chain; a successful ADD
response does not by itself guarantee `galactic-bgp` has even run yet, let
alone that the `BGPAdvertisement`/`BGPVRFInstance` CRDs exist (see
[docs/cni-cmd-sequence.md](../cni/cni-cmd-sequence.md)).

On DEL, every binary's result contains only `cniVersion` (empty result). Each
binary's own DEL only cleans up what it itself created *and* is safe to
release immediately for that specific container — IPAM deallocation
(`galactic-ipam`, via its own on-disk marker file) and the guest-netns
flush/host-device DEL (`galactic-veth` only). It does not attempt to unwind
any shared, per-attachment kernel/CRD state — see the `cmdDel` note in
[docs/cni-cmd-sequence.md](../cni/cni-cmd-sequence.md) and Known Constraints below.

---

## Module / Package Reference

| Package                    | Binary                                                               | Responsibility                                                                                                                                                                                                  | Owns state                            |
| -------------------------- | -------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------- |
| `internal/cni`             | galactic-veth                                                        | Veth master plugin: `cmdAdd`/`cmdDel`/`cmdCheck`/`cmdStatus`; PluginConf parsing; NAD annotation; host-device delegation; delegates kernel work to plumbing                                                     | No                                    |
| `internal/hostconf`        | every CNI-chain binary                                               | Shared `HostConf` schema + static-conflist loader, plus API-based node-name auto-detect                                                                                                                         | No                                    |
| `internal/hostgw`          | galactic-veth, galactic-tap                                          | Host-side gateway address/route configuration for a VPC attachment's allocated IPAM addresses                                                                                                                   | No                                    |
| `internal/crdnames`        | galactic-veth, galactic-bgp                                          | Deterministic `BGPVRFInstance`/`BGPAdvertisement`/EndpointSlice CRD name + annotation/label-key derivation (also read by `galactic-router`'s GC — see [ARCHITECTURE-ROUTER.md](ARCHITECTURE-ROUTER.md))         | No                                    |
| `internal/nadpatch`        | galactic-veth, galactic-tap, galactic-bgp                            | NAD annotation patch (host interface name) + pod-name/pod-namespace parsing from `CNI_ARGS`                                                                                                                     | No                                    |
| `internal/cni/ipam`        | galactic-ipam                                                        | IPv6/IPv4 pool allocators + static IP allocator; on-disk marker-file persistence (flock-guarded, keyed by containerID)                                                                                          | Yes (pool allocations + marker files) |
| `internal/cni/route`       | galactic-route                                                       | Host-side static route add/delete via netlink                                                                                                                                                                   | No                                    |
| `internal/cni/tap`         | galactic-tap                                                         | Tap interface create/delete for VM workloads (Kata, Firecracker, kraftlet/Unikraft)                                                                                                                             | No                                    |
| `internal/cni/veth`        | galactic-veth                                                        | veth pair create/delete                                                                                                                                                                                         | No                                    |
| `internal/cnitap`          | galactic-tap                                                         | Tap master plugin (mirrors `internal/cni`; no host-device delegation, no guest netns)                                                                                                                           | No                                    |
| `internal/cniipam`         | galactic-ipam                                                        | CNI IPAM delegation protocol (`cmdAdd`/`cmdDel`/`cmdCheck`/`cmdStatus`); explicit `"ipam"`-block contract; no k8s dependency                                                                                    | No                                    |
| `internal/cnibgp`          | galactic-bgp                                                         | BGP/SRv6/eBPF publish: SID/Argument allocation + collision detection, `registerEBPFDatapath`/`unregisterEBPFDatapath`, `BGPVRFInstance`/`BGPAdvertisement` CRUD with retry, per-pod EndpointSlice publish/delete/CHECK for HTTP-ingress backend discovery (`endpointslice.go`); learns everything from `prevResult` | No                                    |
| `internal/cniroute`        | galactic-route                                                       | Termination-route plugin: installs/rolls-back VRF-table routes; no k8s dependency                                                                                                                               | No                                    |
| `internal/installer`       | galactic-cni                                                         | DaemonSet `init`/`run` support: binary staging (every chain binary), node-identity check, conflist/kubeconfig templating, credential refresh ticker, log rotation, eBPF datapath lifecycle, gRPC health server  | No                                    |
| `internal/plumbing/intf`   | every CNI-chain binary                                               | Deterministic interface naming (`G{vpc9}{att3}V/H/G`); base62↔hex encoding                                                                                                                                      | No                                    |
| `internal/plumbing/ebpf`   | galactic-cni (attach/metrics via `run`), galactic-bgp (registration) | TC-BPF uSID datapath: kernel preflight, uFMT bit-layout codec, compiled program + bindings, load/pin/attach lifecycle, map read/write API, Prometheus metrics                                                   | Yes (pinned BPF maps)                 |
| `internal/plumbing/vrf`    | every CNI-chain binary                                               | Linux VRF create/delete/lookup via netlink                                                                                                                                                                      | No                                    |
| `internal/plumbing/sysctl` | galactic-veth, galactic-tap                                          | Per-interface sysctl helpers                                                                                                                                                                                    | No                                    |

---

## External Dependencies

| Dependency                               | Version               | Purpose                                                                                                                                                                                                                                                    |
| ---------------------------------------- | --------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `go.datum.net/network`                   | bumped frequently     | BGP CRD API types (`BGPAdvertisement`, `BGPVRFInstance`) — `galactic-bgp` writes these via a bare `sigs.k8s.io/controller-runtime/pkg/client.Client`, no manager/reconciler                                                                                |
| `sigs.k8s.io/controller-runtime`         | v0.24.1               | `pkg/client` only for `galactic-bgp`/`galactic-cni`'s installer (CRD CRUD, node lookup) — neither runs a manager or reconciler; that usage lives entirely in `galactic-router`/`galactic-gateway`, see the other two architecture docs                     |
| `github.com/spf13/cobra`                 | v1.10.2               | CLI command/flag handling for every binary                                                                                                                                                                                                                 |
| `github.com/containernetworking/cni`     | v1.3.0                | CNI plugin spec, skel, invoke                                                                                                                                                                                                                              |
| `github.com/containernetworking/plugins` | v1.9.1                | `pkg/ipam.ExecAdd`/`ExecDel`/`ExecCheck` (real IPAM delegation to `galactic-ipam`, used by `galactic-veth`/`galactic-tap`); `host-device` plugin, delegated to by `galactic-veth` for moving the guest veth into the pod netns                             |
| `github.com/vishvananda/netlink`         | pinned pseudo-version | Linux netlink: VRF, veth, SRv6 routes                                                                                                                                                                                                                      |
| `github.com/kenshaw/baseconv`            | v0.1.1                | Base62↔hex conversion for interface names                                                                                                                                                                                                                  |
| `github.com/lorenzosaino/go-sysctl`      | v0.3.1                | Interface sysctl helpers                                                                                                                                                                                                                                   |
| `github.com/coreos/go-iptables`          | v0.8.0                | iptables manipulation (CNI path)                                                                                                                                                                                                                           |
| `github.com/cilium/ebpf`                 | v0.22.0               | TC-BPF uSID datapath load/attach/map bindings (`internal/plumbing/ebpf`) — a sibling `edgeprog`/`edgemap`/`edgeattach` set under the same package lives here too but belongs to `galactic-gateway`, see [ARCHITECTURE-GATEWAY.md](ARCHITECTURE-GATEWAY.md) |
| `google.golang.org/grpc`                 | v1.82.0               | gRPC health server (`galactic-cni`'s `run` subcommand, default `:5180`)                                                                                                                                                                                    |
| `k8s.io/api`, `k8s.io/client-go`         | v0.36.0               | Kubernetes client, Node API types                                                                                                                                                                                                                          |

Note: unlike `galactic-router`/`galactic-gateway`, no CNI-chain binary imports
`github.com/spf13/viper` — each resolves its own config from conflist/env/API
auto-detect directly (see Configuration above).

---

## Key Design Decisions

- **USID per endpoint, computed independently on both the CNI and BGP-control-plane sides.** Each (VPC, VPCAttachment) pair is assigned a unique /128 USID from the owning `BGPRouter`'s `srv6Locator` + `nodeID` plus this attachment's VRFID — there is no config-supplied SID field. `galactic-bgp` registers the eBPF uSID datapath's map entries for it (`internal/cnibgp/bgp.go`'s `registerEBPFDatapath`); `galactic-router` independently derives the same value for the BGP Prefix-SID path attribute (see [ARCHITECTURE-ROUTER.md](ARCHITECTURE-ROUTER.md)). See [SRv6 SID encoding](#srv6-sid-encoding) above. VPC identity is not encoded in the SID itself — VPC scoping comes from the BGPVRFInstance's route target instead.
- **Base62 interface names.** Kernel interface names use the format `G{9-char-vpc-base62}{3-char-att-base62}{suffix}` (suffix: `V` = VRF, `H` = host veth/tap, `G` = guest veth pre-move), fitting in the 15-character kernel limit. The hex form is used for BGP route targets; base62 for kernel interfaces.
- **VRF/route-target model via BGPVRFInstance.** `galactic-bgp` creates a `BGPVRFInstance` (RouteDistinguisher + import/export Route Targets, all set to the derived RT) before the `BGPAdvertisement`; `galactic-router`'s GoBGP runtime applies VRFs before originating EVPN paths.
- **CRD-driven config, no sidecar gRPC.** `galactic-bgp` writes `BGPVRFInstance`/`BGPAdvertisement` CRDs directly via a bare controller-runtime client; `galactic-router`'s reconciler picks them up. No in-node gRPC calls between any of the CNI-chain binaries and `galactic-router`.
- **DEL is intentionally minimal everywhere in the CNI chain; GC reclaims shared state asynchronously.** Every binary's own `cmdDel` only cleans up what it itself created *and* is safe to release immediately per-container: IPAM deallocation via `galactic-ipam`'s own on-disk marker file; guest-netns flush/host-device DEL in `galactic-veth`; and, in both `galactic-veth`/`galactic-tap`, deleting this attachment's own host/guest veth pair or tap device outright, since that interface is private to one attachment and no sibling pod/VM can ever depend on it. None of them delete the VRF, routes, the eBPF `vrf_table` entry, or `BGPAdvertisement`/`BGPVRFInstance` CRDs — those are keyed by `(vpc, vpcAttachment)` or `(vpc, node)` and may be shared/reused by another pod/VM (deleting them in DEL would race with a concurrent ADD during restarts). `galactic-router`'s GC controller (see [ARCHITECTURE-ROUTER.md](ARCHITECTURE-ROUTER.md)) reclaims orphaned CRDs, stale kernel VRFs, and stale eBPF entries once no live container still references them — see [docs/cni/gc-cmd-sequence.md](../cni/gc-cmd-sequence.md) for why the host veth/tap interface has no GC path of its own at all.
- **`galactic-cni`'s install DaemonSet is a Go installer, not a shell script.** See Known Constraints below.

---

## Testing

| Layer   | Command          | Framework        | Scope                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| ------- | ---------------- | ---------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Unit    | `task test:unit` | `go test -race`  | `internal/cni`, `internal/cnitap`, `internal/cniipam`, `internal/cnibgp`, `internal/cniroute` (`buildResult`/`buildVethResult`, `parseConf`, `routeTarget`, `inferFromPrevResult` — each package's own `cmdAdd`/`cmdDel`/`cmdCheck`/`cmdStatus`), `internal/{hostconf,hostgw,crdnames,nadpatch}`, `internal/cni/{ipam,route,tap,veth}`, `internal/installer` (`installer_test.go` — `Bootstrap`/`Run` with mocked k8s client and netlink/host paths), `internal/plumbing/ebpf`, `internal/plumbing/intf` |
| E2E     | `task test:e2e`  | Kind + `go test` | `galactic-tap`'s own ADD (VRF + tap + IPAM delegation), kernel capability checks, CNI VERSION report. Does **not** exercise `galactic-route` or `galactic-bgp` (no BGPRouter fixture in the e2e suite) — see Known Constraints below.                                                                                                                                                                                                                                                                    |
| CI full | `task ci`        | all of the above | lint → build → test:unit → test:e2e                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |

`internal/plumbing/vrf` has no unit tests — it requires `CAP_NET_ADMIN` and a real kernel. `internal/cni/route` (wrapped by `internal/cniroute`) also has no unit tests of its own. `internal/plumbing/intf` is pure-function and fully unit-testable.

---

## CI/CD

**Pipeline:** `.github/workflows/ci.yaml` — see [ARCHITECTURE-ROUTER.md](ARCHITECTURE-ROUTER.md#cicd) for the shared tier structure; this section covers only the CNI-specific build/publish artifacts.

**Publish pipeline:** `.github/workflows/publish.yaml`'s `publish-galactic-cni-image` job builds and pushes `ghcr.io/datum-cloud/galactic-cni`; `publish-kustomize-bundles` (which `needs` every per-binary image job, including the router and gateway ones) stamps that real tag into `config/galactic-cni` when it pushes `config/` as the `ghcr.io/datum-cloud/galactic-kustomize` OCI Kustomize bundle.

**Container image:**
- `containers/galactic-cni/Dockerfile` — multi-stage build (golang builder → distroless → final Alpine stage for `iproute2`/`nsenter`); builds `galactic-cni` (the installer), `galactic-veth`, `galactic-tap`, `galactic-ipam`, `galactic-bgp`, `galactic-route`, and the delegated `host-device` CNI plugin binary, `ENTRYPOINT ["/galactic-cni"]`. Used both by `task test:e2e` (`scripts/ci.sh e2etest` builds it, tags `galactic-cni:e2e`, `kind load`s it into the ephemeral e2e cluster) and by `publish.yaml` (pushed as `ghcr.io/datum-cloud/galactic-cni`). Both the init container (`/galactic-cni init`) and the long-running container (`/galactic-cni run`) run this same image; the DaemonSet no longer shells out to an `install.sh` script, so the Alpine/`iproute2` final stage exists purely for e2e test needs (kernel `ip`/`nsenter` operations exercised via `task test:e2e`) rather than anything the installer subcommands require. Reusing the e2e-tested artifact for publish is preferred over maintaining a second, untested variant.

**History:** the original `.github/workflows/release.yaml` built and pushed a single `ghcr.io/datum-cloud/galactic:{version,major.minor,major,sha}` image from a shared `containers/galactic/Dockerfile`, but that image only ever built `galactic-cni` while `config/galactic-router/base/daemonset.yaml` ran `command: [/galactic-router]` against it — the image advertised a binary it never built. Both were removed; per-binary Dockerfiles and `publish.yaml` (see [ARCHITECTURE-ROUTER.md](ARCHITECTURE-ROUTER.md#cicd)) fix this.

---

## Known Constraints

- **No binary's `cmdDel` tears down shared kernel/CRD state.** By design (see Key Design Decisions above) — cleanup of the VRF, routes, the eBPF `vrf_table` entry, and BGP CRDs is deferred to `galactic-router`'s asynchronous GC controller, not performed synchronously in any chain binary's `cmdDel`. The per-attachment host veth/tap interface is the one exception: it is private, not shared, so `cmdDel` deletes it directly instead of deferring it.
- **`internal/plumbing/vrf` and `internal/cni/route` have no unit tests.** `vrf` requires `CAP_NET_ADMIN` and a real kernel; `route` (wrapped by `internal/cniroute`, which does have its own tests) was never backfilled with tests of its own when the CNI plugin-chain split moved its caller out of `internal/cni`. `internal/plumbing/intf` is fully unit-testable (pure functions only). Kernel-path coverage otherwise comes from the e2e suite (`task test:e2e`).
- **The e2e suite doesn't cover `galactic-route` or `galactic-bgp`.** `TestCNITapInterface` (`tests/e2e/e2e_test.go`) only drives `galactic-tap`'s own ADD — verifying BGP/SRv6/eBPF publish end-to-end would need a `BGPRouter` CRD fixture and additional RBAC the test doesn't set up. This gap predates the CNI plugin-chain split too: the monolithic `galactic-cni` this replaced was never e2e-verified past its own CNI result shape either.
- **`galactic-cni`'s install DaemonSet is a Go installer, not a shell script.** `config/galactic-cni/configmap.yaml`/`install.sh` were deleted; `config/galactic-cni/daemonset.yaml` now runs `hostNetwork: true` with an `install-cni` init container (`command: ["/galactic-cni", "init"]`, calling `installer.Bootstrap`) and a `credential-refresh` main container (`command: ["/galactic-cni", "run"]`, calling `installer.Run`), both on the same image (see CI/CD above). `Bootstrap` writes every binary in the CNI chain to `/opt/cni/bin`, the static conflist to `/etc/cni/net.d/10-galactic.conflist`, and `ca.crt`/kubeconfig to `/var/lib/galactic` (chosen over `/etc/galactic` specifically so it lands under `/var`, the one path immutable-root distros like Talos allow hostPath writes to without a host-level `extraMounts` entry); `Run` refreshes the kubeconfig token every 300s and rotates the CNI log once it exceeds 10MB. `/opt/cni/bin` is fixed by the CNI/kubelet plugin-discovery convention and can't be relocated by this DaemonSet alone — on Talos it needs its own `extraMounts` entry in the machine config if it isn't writable by default. The `run` container also serves gRPC health checks on port `5180` (`livenessProbe`/`readinessProbe` in the DaemonSet spec), and `config/galactic-cni/rbac.yaml` grants `get` on `nodes` for `Bootstrap`'s node-identity check.
- **The uSID TC-BPF datapath (`internal/plumbing/ebpf/prog/usid.c`) doesn't generate PMTUD ICMPv6 errors.** When `bpf_fib_lookup()` returns `BPF_FIB_LKUP_RET_FRAG_NEEDED` (egress route's MTU is smaller than the inner packet), the program counts `DROP_REASON_FIB_FRAG_NEEDED` and silently drops (`TC_ACT_SHOT`) rather than sending an ICMPv6 Packet Too Big back to the original sender — unlike the static-route `SEG6_LOCAL_ACTION_END_DT46` path this datapath replaces, where the kernel's own IPv6 stack emits that ICMP message. Accepted as a known cost of the TC-BPF cutover for this milestone; generating ICMPv6 PTB from the datapath itself is unscheduled future work, not planned for a specific milestone yet. The edge gateway's own XDP program has the identical gap for its own FIB lookup — see [ARCHITECTURE-GATEWAY.md](ARCHITECTURE-GATEWAY.md#known-constraints).

---

## For Claude

**Where to start for each concern:**

| Concern                                                                     | Start here                                                                                                                   |
| --------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| CNI master-plugin attach/detach flow (veth)                                 | `internal/cni/ops_add.go:cmdAdd`, `internal/cni/ops_del.go:cmdDel` (`internal/cni/cni.go` only holds `RunPlugin`)            |
| CNI master-plugin attach/detach flow (tap)                                  | `internal/cnitap/ops_add.go:cmdAdd`, `internal/cnitap/ops_del.go:cmdDel` (mirrors `internal/cni`)                            |
| CNI runtime config resolution (conflist/env/API auto-detect)                | `internal/cni/config.go:parseConf`, `loadHostConf`, `internal/hostconf.DetectNodeNameFromAPI`                                |
| IPAM delegation (master plugin side)                                        | `internal/cni/result.go:configureIPAM` (`ipam.ExecAdd`), `internal/cni/ops_del.go:cmdDel` (`ipam.ExecDel`)                   |
| IPAM delegation protocol (delegate side)                                    | `internal/cniipam/ops.go:cmdAdd`/`cmdDel`, `internal/cniipam/allocate.go`                                                    |
| Termination-route chain stage                                               | `internal/cniroute/ops_add.go:cmdAdd`, `internal/cni/route/route.go`                                                         |
| BGP CRD publish (VRF + advertisement) + eBPF registration                   | `internal/cnibgp/bgp.go:publishBGPState`, `registerEBPFDatapath`; entry point `internal/cnibgp/ops_add.go:cmdAdd`            |
| How `galactic-bgp`/`galactic-route` learn state without touching the kernel | `internal/cnibgp/prevresult.go:inferFromPrevResult` (reads `RawPrevResult`, not the dead `PrevResult` field)                 |
| Host gateway address/route configuration (shared by both master plugins)    | `internal/hostgw/hostgw.go:ConfigureHostGateway`                                                                             |
| CNI DaemonSet install/refresh                                               | `internal/installer/installer.go:Bootstrap` (init container), `internal/installer/installer.go:Run` (long-running container) |
| Interface naming / base62 encoding                                          | `internal/plumbing/intf/intf.go`                                                                                             |

**Stable vs. frequently changed:**
- Stable: `internal/plumbing/` (pure kernel primitives)
- Active: none of this chain's packages have carried an "active" tag historically — most churn in this codebase lands in `internal/reconcile`/`internal/gc`/`internal/runtime/gobgp` (see [ARCHITECTURE-ROUTER.md](ARCHITECTURE-ROUTER.md)) or `internal/gateway`/`internal/plumbing/ebpf/edgeprog` (see [ARCHITECTURE-GATEWAY.md](ARCHITECTURE-GATEWAY.md))

**Non-obvious patterns:**
- The master plugin's ADD result is the runtime's authoritative CNI result for the whole chain — `galactic-route`/`galactic-bgp` (chained after it) both pass `prevResult` straight through unchanged. A successful ADD response does not by itself guarantee `galactic-bgp` has even run yet, let alone that the BGP CRDs exist. What it does guarantee: the master plugin (`galactic-veth`/`galactic-tap`) fetches its own attachment's `NetworkAttachmentDefinition` before creating any kernel state and fails ADD if `galactic-bgp` is missing from its conflist's `plugins` list (`internal/hostconf.VerifyChainIncludes`, `internal/nadpatch.VerifyChainComplete`) — a stale/hand-edited conflist that drops the entry entirely can no longer attach successfully with no path to its VPC ([#331](https://github.com/datum-cloud/galactic/issues/331)). This is presence-only, not position-aware: it does not confirm `galactic-bgp` actually ran, only that the conflist names it.
- `types.PluginConf.PrevResult` (from `containernetworking/cni/pkg/types`) has JSON tag `"-"` and is **never populated** by plain `json.Unmarshal`; only the sibling `RawPrevResult map[string]interface{}` field actually receives the previous plugin's result. A pre-existing quirk of that library, not specific to this codebase — every CNI-chain package that reads prevResult (`internal/cni/ops_check.go`, `internal/cnibgp/prevresult.go`, `internal/cniroute/ops_add.go`) reads `RawPrevResult` for this reason.
- No binary's `cmdDel` deletes the VRF, routes, the eBPF `vrf_table` entry, or `BGPAdvertisement`/`BGPVRFInstance` CRDs — each binary's own DEL only handles its own per-container bookkeeping (IPAM deallocation, guest-netns/host-device cleanup, and deleting this attachment's own private host veth/tap interface outright). Shared-resource cleanup is entirely the GC controller's job (`internal/gc`, part of `galactic-router` — see [ARCHITECTURE-ROUTER.md](ARCHITECTURE-ROUTER.md)), to avoid racing a concurrent ADD during pod restarts.
- Production images are published by `.github/workflows/publish.yaml` as separate per-binary images, not one shared image — see CI/CD above. `galactic-cni`'s own image carries all five CNI-chain binaries plus `host-device`, not just `galactic-cni` itself.
