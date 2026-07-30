# Architecture

> Galactic is the SRv6 data plane for multi-cloud VPC networking, deployed as three
> binaries: a per-node CNI plugin that attaches containers to VPC networks, a
> per-node router that reconciles BGP CRDs and drives an embedded GoBGP server to
> distribute EVPN (L2VPN/EVPN AFI/SAFI) paths between nodes, and a cluster-wide
> mutating admission webhook that provisions VPC attachments for pods on CREATE.

_Last updated: 2026-07-30_

---

## Overview

Galactic implements VPC isolation and cross-cluster reachability using Linux SRv6.
When a pod carrying the `galactic.datumapis.com/vpc=<vpc-name>` annotation is
created, `galactic-webhook` allocates a VPCAttachment ID for it, creates a
`NetworkAttachmentDefinition` (NAD) pointing `galactic-cni` at that VPC +
VPCAttachment pair, and patches the pod to attach via that NAD (Multus). When
the pod is scheduled, `galactic-cni` creates the required kernel state (VRF,
veth pair, SRv6 ingress route), creates the `VPCAttachment` CR itself (Spec and
Status), and writes a `BGPAdvertisement` CRD. `galactic-router` watches that CRD
and injects the EVPN path into the node-local GoBGP server. GoBGP distributes
the path to a BGP route reflector, enabling pods on different nodes or clusters
to reach each other via SRv6-encapsulated traffic.

The `VPC` CRD is owned by a separate companion operator (`go.datum.net/cloud`,
types-only — no controller exists there). `VPCAttachment` and NAD provisioning,
previously assumed to belong to that companion operator, are now owned by
Galactic itself: `galactic-webhook` creates the NAD (and allocates the
VPCAttachment ID baked into it); `galactic-cni` creates the `VPCAttachment` CR
and writes its status, at the same point it already creates
`BGPVRFInstance`/`BGPAdvertisement`. See `.local/plan-vpc-nad-webhook-plan.md`
for the full design rationale, including why the webhook creates only the NAD
and not the VPCAttachment CR itself. `galactic-router` reconciles BGP CRDs
(`go.datum.net/network`) directly — no gRPC sidecar, no provider CRD lifecycle.

### SRv6 SID encoding

<!-- TODO(docs): docs/srv6-design.md, referenced here for the full SRv6 design
     (SID encoding/allocation, base62 interface naming, kernel seg6local/seg6
     route programming, EVPN Type 5 path construction, worked ContainerLab
     example), does not exist in this repository. Either write it, point this
     section elsewhere, or remove this note — flagged for a human decision. -->

Each container endpoint is assigned a /128 USID (Unique Local SID, RFC 8986 Section 3.2).
There is no longer a companion-operator-injected `srv6_sid` NAD/config field: the CNI
itself computes the SID in `resolveSRv6SID` (`internal/cni/bgp.go`) from the node's
`BGPRouter.spec.srv6Locator` + `spec.nodeID` plus this attachment's VRFID (`srv6.ComputeSID`,
`internal/plumbing/srv6/usid.go`), using the End.DT46 function. If the router lacks either
`srv6Locator` or `nodeID`, SID resolution — and SRv6 ingress setup — is skipped entirely for
that attachment. The CNI installs an END.DT46 decap route for the computed /128 and
advertises it as the EVPN Type 5 GWIPAddress.

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
│   ├── galactic-cni/        # CNI binary
│   ├── galactic-router/     # Router binary (controller-runtime reconciler)
│   └── galactic-webhook/    # Mutating admission webhook binary
├── internal/
│   ├── webhook/             # PodMutator admission.Handler: VPCAttachment ID
│   │                        #   allocation (via NAD labels) + NAD creation +
│   │                        #   pod patch. Creates NADs only — see internal/cni's
│   │                        #   applyVPCAttachment for VPCAttachment CR creation.
│   ├── controller/          # controller-runtime reconcilers (BGPRouter, BGPPeer,
│   │                        #   BGPAdvertisement, BGPVRFInstance, BGPPolicy, Secret,
│   │                        #   Node, GC); field index registration; status helpers
│   ├── reconcile/           # CRD → DesiredRouter translation (node/role checks,
│   │                        #   secret resolution, IPv6 next-hop from Node)
│   ├── runtime/             # RouterRuntime interface + RuntimeManager
│   │   ├── gobgp/           # GoBGP RouterRuntime (tenant mode)
│   │   └── frr/             # FRR RouterRuntime stub (fabric mode)
│   ├── model/               # DesiredRouter and family; re-exports BGP API enums
│   ├── hash/                # SHA-256 change detection over DesiredRouter
│   ├── metadata/            # Build-time version info (Version, GitCommit, etc.)
│   ├── gc/                  # Orphaned BGPAdvertisement/BGPVRFInstance/VPCAttachment
│   │                        #   CRD, orphaned NAD, and stale kernel VRF cleanup,
│   │                        #   driven by the GC controller
│   ├── cni/                 # CNI cmdAdd / cmdDel / cmdCheck, PluginConf parsing,
│   │                        #   BGP CRD publish, VPCAttachment CR create+status
│   │                        #   (vpcattachment.go), built-in IPAM wiring
│   │   ├── ipam/            # Built-in IPv6 pool + static IP allocators
│   │   ├── route/           # Host-side static routes via netlink
│   │   ├── tap/             # Tap interface management (VM workloads)
│   │   └── veth/            # veth pair management
│   ├── installer/           # galactic-cni DaemonSet init/run logic: binary
│   │                        #   staging, conflist templating, kubeconfig
│   │                        #   refresh, gRPC health server
│   └── plumbing/            # Low-level kernel and network primitives
│       ├── intf/            # Interface naming, base62↔hex encoding
│       ├── srv6/            # SRv6 ingress route add/del (END.DT46)
│       ├── sysctl/          # Interface sysctl helpers
│       └── vrf/             # Linux VRF create/delete/lookup
├── config/                  # Kustomize-composed; `kubectl apply -k config/` deploys everything
│   ├── system/              # galactic-system namespace (shared by both components)
│   ├── router/              # Shared RBAC/ServiceAccount, plus:
│   │   ├── base/            #   common DaemonSet spec
│   │   ├── tenant/          #   per-node role: base + node affinity excluding control-plane
│   │   │                    #     and tenant-control nodes
│   │   └── tenant-control/  #   route-reflector role: base + GALACTIC_ROUTER_REFLECTOR=true,
│   │                        #     opt-in via the galactic.datumapis.com/node=control node label
│   ├── cni/                 # hostNetwork DaemonSet: `init` container stages
│   │                        #   galactic-cni/host-device into /opt/cni/bin
│   │                        #   and writes the conflist + kubeconfig; `run`
│   │                        #   container refreshes credentials and serves
│   │                        #   gRPC health checks
│   └── webhook/             # HA Deployment (2 replicas) + Service +
│                            #   MutatingWebhookConfiguration + cert-manager
│                            #   self-signed Issuer/Certificate for TLS
├── deploy/
│   └── containerlab/        # ContainerLab lab topology and scripts
└── containers/
    ├── galactic-cni/        # galactic-cni + host-device image (e2e test and production publish)
    ├── galactic-router/     # galactic-router production image
    └── galactic-webhook/    # galactic-webhook image (not yet wired into task test:e2e or publish.yaml)
```

Production images for `galactic-cni`/`galactic-router` are published by
`.github/workflows/publish.yaml` — see CI/CD below. `galactic-webhook`'s
Dockerfile exists but isn't yet wired into either `task test:e2e` or the
publish pipeline — see Known Constraints.

---

## Data Flow

See [docs/cni-cmd-sequence.md](../cni-cmd-sequence.md) for the full CNI ADD/DEL sequence diagrams (veth ADD, tap ADD, shared DEL).

See [docs/agent-startup.md](../agent-startup.md) for the router startup sequence diagram.

**Pod → VPC attachment, end to end:**

1. Pod CREATE with `galactic.datumapis.com/vpc=<vpc-name>` reaches
   `galactic-webhook`. It validates the VPC exists, allocates a free 16-bit
   VPCAttachment ID (scanning existing NADs labeled for that VPC — not the
   `VPCAttachment` CRD, which doesn't exist yet at this point), creates a
   deterministically-named NAD (`<vpc-base62>-<vpcattachment-base62>`) with
   the CNI conflist embedded, and patches the pod's
   `k8s.v1.cni.cncf.io/networks` annotation plus a reinvocation-guard
   annotation.
2. Once scheduled, Multus resolves the NAD and invokes `galactic-cni`'s ADD
   with that conflist. `galactic-cni` creates the VRF/veth/SRv6 kernel state,
   then — at the same point it creates `BGPVRFInstance`/`BGPAdvertisement` —
   creates the `VPCAttachment` CR (Spec from real IPAM-allocated addresses)
   and writes its Status (`Node`, `ContainerID`, `PodName`, interface names,
   `PodSubnet`).
3. `galactic-router` watches `BGPAdvertisement`/`BGPVRFInstance` and injects
   the EVPN path into GoBGP, same as before this feature existed.
4. Cleanup: the GC controller reclaims NADs no live pod still references, and
   `VPCAttachment` CRs whose `Status.PodName` no longer exists — see
   `internal/gc`'s `CollectOrphanedNADs`/`CollectOrphanedVPCAttachments`.

---

## Components

| Component | Binary | Role |
|-----------|--------|------|
| `internal/controller` | `galactic-router` | controller-runtime reconcilers; field index registration; CRD status helpers |
| `internal/reconcile` | `galactic-router` | CRD → DesiredRouter translation |
| `internal/runtime/gobgp` | `galactic-router` | Embedded GoBGP server (`--mode=tenant`) |
| `internal/runtime/frr` | `galactic-router` | FRR stub (`--mode=fabric`) — returns "not implemented" for every method |
| `internal/model` | `galactic-router` | Internal BGP model types |
| `internal/hash` | `galactic-router` | Change detection |
| `internal/metadata` | both | Build-time version info stamped via `-ldflags` |
| `internal/gc` | `galactic-router` | Orphaned CRD/VRF cleanup, driven by the GC controller's ticker |
| `internal/cni` | `galactic-cni` | CNI cmdAdd / cmdDel / cmdCheck; BGP CRD publish; VPCAttachment CR create+status (`vpcattachment.go`) |
| `internal/webhook` | `galactic-webhook` | Mutating admission webhook: VPCAttachment ID allocation, NAD creation, pod patch |
| `internal/cni/ipam` | `galactic-cni` | Built-in IPv6 pool + static allocators |
| `internal/cni/tap` | `galactic-cni` | Tap interface create/delete (VM workloads) |
| `internal/installer` | `galactic-cni` | DaemonSet `init`/`run` logic: binary staging, conflist/kubeconfig templating, credential refresh, gRPC health server |
| `internal/plumbing/intf` | both | Interface naming, base62↔hex encoding |
| `internal/plumbing/srv6` | both | SRv6 ingress route add/del (END.DT46) |
| `internal/plumbing/vrf` | both | Linux VRF create/delete/lookup |
| `internal/plumbing/sysctl` | both | Interface sysctl helpers |

---

## Entry Points

### `cmd/galactic-cni/main.go` — CNI plugin

A cobra command (no viper — see External Dependencies below) with three roles under
one binary: the CNI plugin invocation itself (root command, invoked by the container
runtime per the CNI spec), and two DaemonSet-lifecycle subcommands (`init`, `run`) that
wrap `internal/installer`.

`newRootCommand()` builds a root command with a persistent `--conf-file` flag
(default `cni.DefaultConfFile`, `/etc/cni/net.d/10-galactic.conflist`) plus
`--build-info` and `--version`/`-V` utility flags. There is no `--node-name` or
`--enable-local-ipam` flag on this path anymore — those are resolved entirely inside
`internal/cni` at ADD/DEL/CHECK/STATUS time (see Configuration below). On `RunE`:

1. `PersistentPreRunE` overrides `cni.ConfFile` from `--conf-file` if set.
2. Handle `--build-info`/`--version` and return early if set.
3. If `CNI_COMMAND=VERSION`, encode supported CNI spec versions and return.
4. Otherwise call `cni.RunPlugin()`, which hands control to `skel.PluginMainFuncs`
   (ADD/DEL/CHECK/STATUS read from stdin per the CNI spec); `internal/cni/config.go`'s
   `parseConf()` resolves node name, kubeconfig, namespace, and log file on every
   invocation (conflist → env vars → API auto-detect, in that precedence).

Two subcommands support the DaemonSet (see Known Constraints below for the manifest):

- `init` — `--node-name`/`-n` flag (or `GALACTIC_CNI_NODE_NAME`/`NODE_NAME` env),
  calls `installer.Bootstrap(ctx, nodeName)`: stages the `galactic-cni`/`host-device`
  binaries onto the host, does a one-shot dual-stack node-identity check against the
  Kubernetes API, and writes `ca.crt`/kubeconfig plus the static conflist.
- `run` — `--grpc-health-port` flag (default `5180`), calls `installer.Run(ctx,
  grpcHealthPort)`: serves gRPC health checks and periodically refreshes the
  kubeconfig token and rotates the CNI log file.

See [docs/cni-cmd-sequence.md](../cni-cmd-sequence.md) for the full ADD/DEL sequence.

### `cmd/galactic-router/main.go` / `root.go` — Router daemon

`main.go` is a 3-line wrapper around `newRootCommand().Execute()`; all startup logic
lives in `root.go`'s `runCmd`:

1. Validate config (`--node-name` and `--mode` required; `--mode` must be `transit`,
   `fabric`, or `tenant`). Env vars: `GALACTIC_ROUTER_NODE_NAME`,
   `GALACTIC_ROUTER_ROUTER_MODE`, plus optional `GALACTIC_ROUTER_BGP_LISTEN_PORT`,
   `GALACTIC_ROUTER_BGP_LOCAL_ADDRESS`, `GALACTIC_ROUTER_METRICS_PORT`,
   `GALACTIC_ROUTER_GRPC_HEALTH_PORT`, `GALACTIC_ROUTER_GC_NAMESPACE`,
   `GALACTIC_ROUTER_GC_INTERVAL`, `GALACTIC_ROUTER_REFLECTOR`.
2. Select `RuntimeFactory`: `tenant` → GoBGP, `fabric` → FRR stub, `transit` → returns
   an error ("not yet supported").
3. Build controller-runtime manager (metrics on configurable port, default `:8080`;
   no HTTP health endpoint).
4. Start gRPC health server on a configurable port (default `:5000`).
5. RBAC pre-flight: `checkWatchPermissions` (in `main.go`) issues a
   `SelfSubjectAccessReview` for every watched resource type and logs an actionable
   error if watch RBAC is missing (informer caches would otherwise silently never sync).
6. Register field indexes: BGPPeer→secret, BGPPeer→router, BGPPolicy→router,
   BGPAdvertisement→router, BGPVRFInstance→router, BGPRouter→node.
7. Register eight controllers: BGPRouter, BGPPeer, BGPAdvertisement, BGPVRFInstance,
   BGPPolicy, Secret, Node, and GC (the GC controller also starts a ticker goroutine
   that waits for cache sync, then runs on `--gc-interval`, default 5m).
8. `mgr.Start(ctx)` — blocks until the signal-handler context is cancelled.

### `cmd/galactic-webhook/main.go` / `root.go` — Mutating admission webhook

`main.go` is a 3-line wrapper around `newRootCommand().Execute()`, mirroring
`galactic-router`'s split; all startup logic lives in `root.go`'s `runCmd`:

1. Build a controller-runtime manager with `webhook.NewServer(webhook.Options{
   Port: cfg.Port, CertDir: cfg.CertDir})` (default port `9443`, cert dir
   `/etc/webhook/certs` — populated by the cert-manager-issued Secret, see
   `config/webhook/certificate.yaml`).
2. Register a cache-sync-gated readyz check (`mgr.GetCache().WaitForCacheSync`)
   — a cold cache means the ID allocator can't see existing NADs and would
   double-allocate — plus a plain `healthz.Ping` healthz check, both served on
   `--health-port` (default `8081`).
3. Construct `internal/webhook.PodMutator{Client: mgr.GetClient(), Decoder:
   admission.NewDecoder(scheme), NADDefaults: {MTU: cfg.MTU, InterfaceType:
   cfg.InterfaceType}}` and register it at `/mutate-v1-pod-vpc-attachment`.
4. `mgr.Start(ctx)` — blocks until the signal-handler context is cancelled.

Env vars: `GALACTIC_WEBHOOK_PORT`, `GALACTIC_WEBHOOK_METRICS_PORT`,
`GALACTIC_WEBHOOK_HEALTH_PORT`, `GALACTIC_WEBHOOK_CERT_DIR`,
`GALACTIC_WEBHOOK_MTU`, `GALACTIC_WEBHOOK_INTERFACE_TYPE` (`internal/config/webhook.go`).

`PodMutator.Handle` (`internal/webhook/pod_mutator.go`) is the pure `Pod in →
Pod/patch out or Deny` logic:

1. Decode the admitted Pod.
2. Reinvocation guard: if `galactic.datumapis.com/vpc-attachment-ref` is
   already set, allow unpatched (already processed).
3. If `galactic.datumapis.com/vpc` is unset, allow unpatched (silent no-op).
4. If `pod.Spec.HostNetwork`, allow unpatched (VPC attach doesn't apply).
5. `Get` the named `VPC`; deny if not found or `Status.VPC` is still empty.
6. On dry-run, allow unpatched — never create real objects.
7. `createNAD` (`internal/webhook/pod_mutator.go`): allocate a free
   VPCAttachment ID (`AllocateVPCAttachmentID`, `allocate.go` — scans NADs
   labeled for this VPC, not the `VPCAttachment` CRD) and create the NAD
   (`buildNAD`, `nad.go`), retrying up to 5 times on an `AlreadyExists`
   collision.
8. Patch the pod: parse-merge `k8s.v1.cni.cncf.io/networks` (preserving any
   existing entries) and set the reinvocation-guard annotation, then return
   `admission.PatchResponseFromRaw`.

---

## Configuration

### galactic-router environment variables

| Variable                            | Required | Default            | Description                                                             |
|-------------------------------------|----------|--------------------|--------------------------------------------------------------------------|
| `GALACTIC_ROUTER_NODE_NAME`         | Yes      | —                  | Kubernetes node name; filters which BGPRouter CRDs this instance owns   |
| `GALACTIC_ROUTER_ROUTER_MODE`       | Yes      | —                  | `transit` (unsupported stub), `fabric` (FRR stub), or `tenant` (GoBGP)  |
| `GALACTIC_ROUTER_REFLECTOR`         | No       | `false`            | Enable route reflector mode; only valid for `fabric`/`tenant`          |
| `GALACTIC_ROUTER_BGP_LISTEN_PORT`   | No       | `179`              | BGP TCP listen port; `-1` disables inbound connections (outbound-only)  |
| `GALACTIC_ROUTER_BGP_LOCAL_ADDRESS` | No       | —                  | Source address for outgoing BGP TCP connections (numbered underlay use) |
| `GALACTIC_ROUTER_METRICS_PORT`      | No       | `8080`             | controller-runtime Prometheus metrics port                             |
| `GALACTIC_ROUTER_GRPC_HEALTH_PORT`  | No       | `5000`             | gRPC health check port (liveness/readiness probes)                     |
| `GALACTIC_ROUTER_GC_NAMESPACE`      | No       | `galactic-system`  | Namespace the GC controller scans for orphaned CRDs                    |
| `GALACTIC_ROUTER_GC_INTERVAL`       | No       | `5m`               | GC controller sweep interval                                           |

See [docs/router/configuration.md](../router/configuration.md) for the full reference, including CLI flags and precedence.

### galactic-cni CNI config fields (`PluginConf`)

| Field           | Type     | Description                                                             |
|-----------------|----------|-------------------------------------------------------------------------|
| `vpc`           | string   | Base62-encoded 48-bit VPC identifier                                    |
| `vpc_name`      | string   | VPC CR's Kubernetes object name (distinct from `vpc` above); optional — when empty, `galactic-cni` skips VPCAttachment CR creation. Set by `galactic-webhook` when it builds the NAD. |
| `vpcattachment` | string   | Base62-encoded 16-bit VPCAttachment identifier                          |
| `interface_type`| string   | `veth` (default) or `tap`; tap mode omits guest-side/host-device config but still runs IPAM and SRv6/BGP publish (see the ADD result section below) |
| `namespace`     | string   | Kubernetes namespace for BGP CRDs; resolution order is this field → `GALACTIC_CNI_NAMESPACE` → `HostConf.Namespace` (from the conflist) → `DefaultNamespace` (`galactic-system`) |
| `mtu`           | int      | MTU for the host-side interface (veth pair or tap); 0 uses kernel default |
| `terminations`  | array    | Static routes to install on the host-side interface (`network`, `via`) |
| `ipam`          | object   | Built-in IPv6 pool/static allocator config (Galactic has no external IPAM delegation); used identically in `veth` and `tap` mode — `tap`'s `cmdAdd` calls `allocateIPAM()` unconditionally, so omitting this without `GALACTIC_CNI_ENABLE_LOCAL_IPAM` set is not safely tolerated in tap mode. See [docs/cni/configuration.md](../cni/configuration.md). |

### galactic-cni environment variables

There is no longer a `--node-name`/`--enable-local-ipam` CLI flag on the plugin
invocation path (those flags now only exist on the `init`/`run` installer
subcommands, and only `init`'s `--node-name` overlaps in purpose). `parseConf()`
(`internal/cni/config.go`) resolves each setting below on every ADD/DEL/CHECK/STATUS
call, in the listed precedence, and re-exports the result as a process env var for
the rest of the invocation:

| Variable                          | Resolution precedence (highest first)                                                                 | Default |
|------------------------------------|--------------------------------------------------------------------------------------------------------|---------|
| Node name (`NODE_NAME`)            | `GALACTIC_CNI_NODE_NAME` → `NODE_NAME` → `HostConf.NodeName` (conflist) → `detectNodeNameFromAPI()` (matches local interface addrs against Node `InternalIP`) | _(error if still empty)_ |
| Kubeconfig (`KUBECONFIG`)          | `GALACTIC_CNI_KUBECONFIG` → `HostConf.Kubeconfig` (conflist)                                            | `/var/lib/galactic/kubeconfig` |
| Namespace                          | `conf.Namespace` (CNI config JSON) → `GALACTIC_CNI_NAMESPACE` → `HostConf.Namespace` (conflist)         | `galactic-system` |
| Log file                           | `GALACTIC_CNI_LOG_FILE` → `HostConf.LogFile` (conflist)                                                 | `/var/log/galactic/galactic-cni.log` |
| Log level                          | `GALACTIC_CNI_LOG_LEVEL` → `HostConf.LogLevel` (conflist)                                               | `info` |
| `GALACTIC_CNI_ENABLE_LOCAL_IPAM`  | Read directly as an env var in `parseConf()` (no conflist or CLI-flag equivalent)                       | `false` |

`HostConf` (`node_name`, `kubeconfig`, `namespace`, `log_file`, `log_level`) is the JSON
shape the `init` installer subcommand writes into the `galactic-cni`-typed plugin entry
of the conflist at `--conf-file` (see `internal/installer/installer.go` and
Entry Points above). `log_level` (`debug`/`info`/`warn`/`error`) controls how much detail
`setupLogging()` emits — `info` (the default) logs one line per operation for
start/outcome plus all warnings/errors; `debug` adds per-resource milestones. See
[docs/cni/configuration.md#log-verbosity](../cni/configuration.md#log-verbosity).

### galactic-cni ADD result

On a successful ADD, the plugin returns a CNI spec v1.0.0 result with the following structure:

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

| Field | Description |
|-------|-------------|
| `interfaces[0]` | Host-side veth endpoint (`G{vpc}{att}H`); sandbox is empty (host network namespace) |
| `interfaces[1]` | Guest-side veth endpoint (`args.IfName`, typically `eth0`); sandbox is the container netns path |
| `ips[0].interface` | Index `1` into `interfaces` — the guest veth carries the pod IP |
| `routes` | Default route via IPAM gateway (when IPAM is configured) |

The VRF dummy interface (`G{vpc}{att}V`) is **not** reported — it is pre-existing infrastructure created by the `vrf.Add()` plumbing function, not by the CNI attachment itself.

This is the `veth`-mode result. In `tap` mode the result has a single interface (the
host-side tap, empty sandbox, index `0`) — there is no guest interface entry since the fd
is handed off to the VM hypervisor, not moved into a container netns. Tap mode is **not**
"no IPAM, no BGP": `cmdAdd` (`internal/cni/ops_add.go`) calls `allocateIPAM()` to allocate
a subnet/gateway and `configureHostGateway()` to assign it on the host tap, includes the
resulting `ips`/`routes` in the tap result (`buildTapResult`, interface index `0`), and then
calls `publishBGPStateK8s()` to create the SRv6 ingress route and
`BGPVRFInstance`/`BGPAdvertisement` CRDs — the same BGP publish step veth mode uses. The
only things tap mode skips are host-device delegation and guest-netns configuration, since
there is no container network namespace to move an interface into.

`configureHostGateway()` assigns the IPv4 gateway as a `/25` on the host tap (vs. `/32`
everywhere else) so it looks like a real subnet to the VM guest, adding it with
`IFA_F_NOPREFIXROUTE` to suppress the kernel's auto-created connected route for the wider
mask — otherwise this would reintroduce the subnet-router-anycast hazard that `/32` avoids
elsewhere. See [docs/cni/configuration.md](../cni/configuration.md) for details.

The result is printed to Multus **before** SRv6 ingress setup and BGP CRD publish run
(see [docs/cni-cmd-sequence.md](../cni-cmd-sequence.md)) — a successful ADD response does not
guarantee the BGPAdvertisement/BGPVRFInstance CRDs exist yet.

On DEL, the result contains only `cniVersion` (empty result; DEL only deallocates the
pod's IPAM bookkeeping and does not attempt to unwind kernel/CRD state — see the
`cmdDel` note in [docs/cni-cmd-sequence.md](../cni-cmd-sequence.md) and Known Constraints below).

---

## Module / Package Reference

| Package                       | Binary          | Responsibility                                                                                      | Owns state |
|-------------------------------|-----------------|-----------------------------------------------------------------------------------------------------|------------|
| `internal/controller`         | galactic-router | controller-runtime reconcilers (BGPRouter, BGPPeer, BGPAdvertisement, BGPVRFInstance, BGPPolicy, Node, Secret, GC); field index registration; CRD status helpers | No         |
| `internal/reconcile`          | galactic-router | Translates BGPRouter + related CRDs into `model.DesiredRouter`; enforces node/role filtering, timer validation, AFI validation | No         |
| `internal/runtime`            | galactic-router | `RouterRuntime` interface; `RuntimeManager` (keyed map of live runtimes, double-checked lock create) | Yes (runtime map) |
| `internal/runtime/gobgp`      | galactic-router | Embeds GoBGP v4; lazy-starts on first Apply; handles peer/VRF/EVPN-path/policy add/update/delete; tracks established timestamps | Yes (per-router) |
| `internal/runtime/frr`        | galactic-router | FRR stub — returns "not implemented" for every method                                               | No         |
| `internal/model`              | both            | `DesiredRouter`, `DesiredPeer`, `DesiredAdvertisement`, `DesiredPolicy`, `DesiredVRFInstance`, `RuntimeStatus`; re-exports BGP API enums | No         |
| `internal/hash`               | galactic-router | SHA-256 fingerprint of `DesiredRouter` for no-op suppression                                        | No         |
| `internal/metadata`           | both            | Build-time vars (`Version`, `GitCommit`, `GitTreeState`, `BuildDate`) stamped via `-ldflags`         | No         |
| `internal/gc`                 | galactic-router | Collects orphaned `BGPAdvertisement`/`BGPVRFInstance`/`VPCAttachment` CRDs, orphaned NADs (reference-counted via the Multus networks annotation), and stale kernel VRFs; invoked by the GC controller's ticker | No |
| `internal/cni`                | galactic-cni    | `cmdAdd` / `cmdDel` / `cmdCheck`; CNI PluginConf parsing; BGPVRFInstance/BGPAdvertisement lifecycle; VPCAttachment CR create+status (`vpcattachment.go`); delegates kernel work to plumbing | No |
| `internal/webhook`            | galactic-webhook| `PodMutator` mutating admission handler: VPCAttachment ID allocation (`allocate.go`, scans NAD labels), NAD construction (`nad.go`), pod patch (`pod_mutator.go`) | No |
| `internal/cni/ipam`           | galactic-cni    | Built-in IPv6 pool allocator (in-memory, ephemeral) and static IP allocator                          | Yes (pool allocations) |
| `internal/cni/route`          | galactic-cni    | Host-side static route add/delete via netlink                                                        | No         |
| `internal/cni/tap`            | galactic-cni    | Tap interface create/delete for VM workloads (Kata, Firecracker, QEMU)                                | No         |
| `internal/cni/veth`           | galactic-cni    | veth pair create/delete                                                                               | No         |
| `internal/installer`          | galactic-cni    | DaemonSet `init`/`run` support: binary staging, node-identity check, conflist/kubeconfig templating, credential refresh ticker, log rotation, gRPC health server | No |
| `internal/plumbing/intf`      | both            | Deterministic interface naming (`G{vpc9}{att3}V/H/G`); base62↔hex encoding | No |
| `internal/plumbing/srv6`      | galactic-cni    | SRv6 END.DT46 ingress route add/delete via netlink                                                   | No         |
| `internal/plumbing/vrf`       | galactic-cni    | Linux VRF create/delete/lookup via netlink                                                           | No         |
| `internal/plumbing/sysctl`    | galactic-cni    | Per-interface sysctl helpers                                                                          | No         |

---

## External Dependencies

| Dependency                              | Version  | Purpose                                                  |
|-----------------------------------------|----------|----------------------------------------------------------|
| `github.com/osrg/gobgp/v4`             | v4.7.0   | Embedded BGP server (tenant mode)                        |
| `go.datum.net/network`                  | bumped frequently | BGP CRD API types (BGPRouter, BGPPeer, BGPAdvertisement, BGPPolicy, BGPVRFInstance) |
| `go.datum.net/cloud`                    | pinned pseudo-version | `VPC`/`VPCAttachment` API types; types-only, no controller — imported by both `internal/cni` (creates/updates `VPCAttachment`) and `internal/webhook` (reads `VPC`) |
| `sigs.k8s.io/controller-runtime`       | v0.24.1  | Reconciler framework, manager, field indexes, webhook server/admission |
| `github.com/spf13/cobra`               | v1.10.2  | CLI command/flag handling for all three binaries         |
| `github.com/spf13/viper`               | v1.21.0  | Config resolution (flags/env/defaults) for `galactic-router`/`galactic-webhook`; `galactic-cni` resolves config itself (conflist/env/API auto-detect in `internal/cni/config.go`) and does not import viper |
| `github.com/containernetworking/cni`   | v1.3.0   | CNI plugin spec, skel, invoke                            |
| `github.com/containernetworking/plugins` | v1.9.1 | `host-device` plugin, delegated to for moving the guest veth into the pod netns |
| `github.com/vishvananda/netlink`        | pinned pseudo-version | Linux netlink: VRF, veth, SRv6 routes           |
| `github.com/kenshaw/baseconv`           | v0.1.1   | Base62↔hex conversion for interface names               |
| `github.com/lorenzosaino/go-sysctl`    | v0.3.1   | Interface sysctl helpers                                 |
| `github.com/coreos/go-iptables`         | v0.8.0   | iptables manipulation (CNI path)                         |
| `google.golang.org/grpc`               | v1.82.0  | gRPC health server (default :5000)                       |
| `k8s.io/api`, `k8s.io/client-go`       | v0.36.0  | Kubernetes client, Node/Secret API types                 |

---

## Key Design Decisions

- **USID per endpoint, router-side computation.** Each (VPC, VPCAttachment) pair is assigned a unique /128 USID computed entirely by the CNI (`resolveSRv6SID`/`srv6.ComputeSID`) from the owning `BGPRouter`'s `srv6Locator` + `nodeID` plus this attachment's VRFID — there is no config-supplied SID field. The CNI installs an END.DT46 decap route for that /128. VPC identity is not encoded in the SID itself — VPC scoping comes from the BGPVRFInstance's route target instead.
- **Base62 interface names.** Kernel interface names use the format `G{9-char-vpc-base62}{3-char-att-base62}{suffix}` (suffix: `V` = VRF, `H` = host veth/tap, `G` = guest veth pre-move), fitting in the 15-character kernel limit. The hex form is used for BGP route targets; base62 for kernel interfaces.
- **GoBGP embedded, lazy-started.** GoBGP runs in-process (`--mode=tenant` only) and starts only when the first `BGPRouter` is reconciled for that router; `Apply` re-runs on every subsequent reconcile too (subject to hash-based no-op suppression), re-applying peers/VRFs/EVPN/policies each time. `listenPort` defaults to `179`; `-1` (outbound-only) is an operator choice for specific deployments, not the codebase default. ASN or RouterID changes trigger a full `Reconfigure` (fresh `BgpServer` — `StopBgp` is not called because it permanently terminates the v4 Serve loop).
- **Overlay BGP port.** galactic-router peers connect outbound on port `1790` by default (configurable per-peer via `BGPPeer.spec.remotePort`). Port `179` is occupied by the underlay FRR `bgpd` on every node, so the overlay uses a non-conflicting port. The `BGPPeer` CRD defaults `remotePort` to `179` (the IANA BGP port); galactic-router overrides this to `1790` when the field is unset, so existing CRDs without an explicit value continue to work. Set `remotePort: 179` explicitly when peering with external BGP speakers that listen on the standard port.
- **VRF/route-target model via BGPVRFInstance.** The CNI creates a `BGPVRFInstance` (RouteDistinguisher + import/export Route Targets, all set to the derived RT) before the `BGPAdvertisement`; `galactic-router`'s GoBGP runtime applies VRFs (`applyVRFs`) before originating EVPN paths (`applyEVPN`).
- **CRD-driven config, no sidecar gRPC.** `galactic-router` watches BGP CRDs directly via controller-runtime. The CNI writes `BGPVRFInstance`/`BGPAdvertisement` CRDs; the router reconciler picks them up. No in-node gRPC calls between the two binaries.
- **Hash-based no-op suppression.** SHA-256 over the sorted `DesiredRouter` prevents redundant GoBGP Apply calls on every CRD event.
- **RuntimeFactory pattern.** `--mode=tenant` (`GALACTIC_ROUTER_ROUTER_MODE=tenant`) selects GoBGP; `--mode=fabric` selects the FRR stub; `--mode=transit` is accepted by validation but returns an error at startup (not yet implemented). The mode is selected at startup; no controller changes are needed to add a new mode.
- **DEL is intentionally minimal; GC reclaims shared state asynchronously.** `cmdDel` only deallocates the pod's IPAM bookkeeping — it does not delete the VRF, veth/tap, routes, SRv6 ingress route, or `BGPAdvertisement`/`BGPVRFInstance` CRDs, because those are keyed by `(vpc, vpcAttachment)` and may be shared/reused by another pod (deleting them in DEL would race with a concurrent ADD during pod restarts). `galactic-router`'s GC controller (ticker-driven, default every 5m) reclaims orphaned CRDs and stale kernel VRFs once no live container still references them.
- **gRPC health, configurable port.** Liveness and readiness probes use the gRPC health protocol (`google.golang.org/grpc/health`) on a configurable port (default `5000`). No HTTP health endpoint.

---

## Testing

| Layer      | Command          | Framework           | Scope                                                                |
|------------|------------------|---------------------|------------------------------------------------------------------------|
| Unit       | `task test:unit` | `go test -race`     | `internal/cni` (`cni_test.go`, `bgp_test.go`, `netns_test.go`, `vpcattachment_test.go` — `buildResult`, `parseConf`, `routeTarget`, `lookupBGPRouter`, `applyVPCAttachment`), `internal/cni/{ipam,tap,veth}`, `internal/installer` (`installer_test.go` — `Bootstrap`/`Run` with mocked k8s client and netlink/host paths), `internal/plumbing/srv6`, `internal/gc` (incl. `orphans_test.go` — NAD reference-counting, VPCAttachment `Status.PodName` checks), `internal/webhook` (`allocate_test.go`, `nad_test.go`, `pod_mutator_test.go` — fake-client `PodMutator.Handle` coverage), `internal/reconcile`, `internal/controller`, `internal/plumbing/intf`, `internal/metadata`, `internal/runtime/gobgp` (partial), `internal/runtime/frr` |
| E2E        | `task test:e2e`  | Kind + `go test`    | Full BGPRouter lifecycle in a Kind cluster; builds and loads image; `TestCNIVPCAttachmentCreation` (`tests/e2e/e2e_test.go`) exercises `applyVPCAttachment` end-to-end against a real `VPCAttachment` CRD (installed from `datum-cloud/cloud`, same pattern as the BGP CRDs) and a VPC fixture (`scripts/ci.sh`). Does **not** yet cover `galactic-webhook` — see Known Constraints. |
| CI full    | `task ci`        | all of the above    | lint → build → test:unit → test:e2e                                  |

`internal/plumbing/vrf` has no unit tests — it requires `CAP_NET_ADMIN` and a real kernel. `internal/cni` and `internal/plumbing/srv6` now have unit coverage for their pure-logic paths (this used to not be the case). `internal/plumbing/intf` is pure-function and fully unit-testable.

---

## CI/CD

**Pipeline:** `.github/workflows/ci.yaml`

Runs on every PR and push to `main`. Two tiers:

- **Tier 1 (parallel):** `lint` (golangci-lint v2.12.2 + yamlfmt), `test-unit` (race detector + codecov upload), `build`
- **Tier 2 (sequential):** `test-e2e` — blocked on all Tier 1 jobs passing

**Publish pipeline:** `.github/workflows/publish.yaml`, modeled on the `compute` repo's. Runs on every push and on published releases, via reusable `datum-cloud/actions` workflows: `publish-galactic-cni-image` and `publish-galactic-router-image` each build and push their own image (`ghcr.io/datum-cloud/galactic-cni`, `ghcr.io/datum-cloud/galactic-router`), and `publish-kustomize-bundles` (which `needs` both image jobs) pushes `config/` as an OCI Kustomize bundle (`ghcr.io/datum-cloud/galactic-kustomize`), using the `images` input (`datum-cloud/actions` v1.20.0+) to stamp each job's real published tag into `config/cni` and `config/router/base` respectively — the bundle ships with matching versioned image references, not `:latest`. This replaces the old single-image `.github/workflows/release.yaml` (removed — see history below) with two per-binary images, matching the split `deploy/containerlab/` already used for local dev.

**Container images:**
- `containers/galactic-cni/Dockerfile` — multi-stage build (golang builder → distroless → final Alpine stage for `iproute2`/`nsenter`); builds `galactic-cni` plus the delegated `host-device` CNI plugin binary, `ENTRYPOINT ["/galactic-cni"]`. Used both by `task test:e2e` (`scripts/ci.sh e2etest` builds it, tags `galactic-cni:e2e`, `kind load`s it into the ephemeral e2e cluster) and by `publish.yaml` (pushed as `ghcr.io/datum-cloud/galactic-cni`). Both the init container (`/galactic-cni init`) and the long-running container (`/galactic-cni run`) run this same image; the DaemonSet no longer shells out to an `install.sh` script, so the Alpine/`iproute2` final stage exists purely for e2e test needs (kernel `ip`/`nsenter` operations exercised via `task test:e2e`) rather than anything the installer subcommands require. Reusing the e2e-tested artifact for publish is preferred over maintaining a second, untested variant.
- `containers/galactic-router/Dockerfile` — golang builder → `gcr.io/distroless/static:nonroot`, `ENTRYPOINT ["/galactic-router"]`. No shell or CLI tools: `galactic-router` drives VRF/SRv6/route/BGP state entirely through the netlink and GoBGP Go libraries, never shells out. Pushed by `publish.yaml` as `ghcr.io/datum-cloud/galactic-router`.

**History:** the original `.github/workflows/release.yaml` built and pushed a single `ghcr.io/datum-cloud/galactic:{version,major.minor,major,sha}` image from a shared `containers/galactic/Dockerfile`, but that image only ever built `galactic-cni` while `config/router/base/daemonset.yaml` ran `command: [/galactic-router]` against it — the image advertised a binary it never built. Both were removed. `publish.yaml` and the two per-binary Dockerfiles above fix this by building each binary into its own image, so `config/cni/daemonset.yaml` and `config/router/base/daemonset.yaml` now reference `ghcr.io/datum-cloud/galactic-cni:latest` and `ghcr.io/datum-cloud/galactic-router:latest` respectively — matching images, matching binaries.

---

## Known Constraints

- **GoBGP RIB is ephemeral.** All BGP state is in-process memory. On restart, sessions and paths must be re-established from CRD state; controller-runtime's reconcile loop handles this automatically.
- **EVPN Type 5 is implemented, not deferred.** `internal/runtime/gobgp/paths.go`'s `buildEVPNPaths` builds real `EVPNIPPrefixRoute` NLRIs, deriving the Route Distinguisher from `routerID + ":0"` (not from the CRD). The `BGPVRFInstance` CRD carries its own explicit `RouteDistinguisher` and import/export Route Targets (see Key Design Decisions above), applied via `internal/runtime/gobgp/runtime.go`'s `applyVRFs`. There is no `ErrMissingRouteDistinguisher` or similar rejection path in the current code.
- **`cmdDel` does not tear down shared kernel/CRD state.** By design (see Key Design Decisions above) — cleanup of VRF, veth/tap, routes, SRv6 ingress, and BGP CRDs is deferred to `galactic-router`'s asynchronous GC controller, not performed synchronously in `cmdDel`.
- **`internal/plumbing/vrf` has no unit tests.** It requires `CAP_NET_ADMIN` and a real kernel. `internal/cni` and `internal/plumbing/srv6` do now have unit coverage for their pure-logic paths. `internal/plumbing/intf` is fully unit-testable (pure functions only). Kernel-path coverage otherwise comes from the e2e suite (`task test:e2e`).
- **`--mode=transit` is unimplemented.** Accepted by CLI/env validation, but `runCmd` returns an error at startup ("mode=transit is not yet supported").
- **`galactic-webhook` is not yet wired into `task test:e2e` or `publish.yaml`.** `containers/galactic-webhook/Dockerfile` and `config/webhook/` exist and `task build`/`task lint`/`task test:unit` all cover it, but there is no chainsaw e2e coverage exercising a real admission flow (would need cert-manager installed in the Kind cluster) and no CI job publishing its image. Unit tests use `sigs.k8s.io/controller-runtime/pkg/client/fake` throughout — see `internal/webhook/*_test.go`.
- **`galactic-cni`'s VPCAttachment integration degrades gracefully, not strictly.** `applyVPCAttachment` (`internal/cni/vpcattachment.go`) silently skips VPCAttachment CR creation when `PluginConf.VPCName` is empty (a NAD not built by `galactic-webhook`) or when there's no IPAM allocation to populate the CRD's required `Spec.Interface.Addresses`/`Status.PodSubnet` fields — existing CNI configs/e2e fixtures that predate this feature keep working unchanged.
- **`VPCAttachmentStatus.ContainerID` requires exactly 46 hex characters; real container IDs are 64.** `truncateContainerID` (`internal/cni/vpcattachment.go`) truncates to fit, mirroring the same accommodation this repo already makes for annotation-key length limits (`annotationContainerIDLen`).
- **`galactic-cni`'s install DaemonSet is a Go installer, not a shell script.** `config/cni/configmap.yaml`/`install.sh` were deleted; `config/cni/daemonset.yaml` now runs `hostNetwork: true` with an `install-cni` init container (`command: ["/galactic-cni", "init"]`, calling `installer.Bootstrap`) and a `credential-refresh` main container (`command: ["/galactic-cni", "run"]`, calling `installer.Run`), both on the same image (see CI/CD above). `Bootstrap` writes the CNI binaries to `/opt/cni/bin`, the static conflist to `/etc/cni/net.d/10-galactic.conflist`, and `ca.crt`/kubeconfig to `/var/lib/galactic` (chosen over `/etc/galactic` specifically so it lands under `/var`, the one path immutable-root distros like Talos allow hostPath writes to without a host-level `extraMounts` entry); `Run` refreshes the kubeconfig token every 300s and rotates the CNI log once it exceeds 10MB. `/opt/cni/bin` is fixed by the CNI/kubelet plugin-discovery convention and can't be relocated by this DaemonSet alone — on Talos it needs its own `extraMounts` entry in the machine config if it isn't writable by default. The `run` container also serves gRPC health checks on port `5180` (`livenessProbe`/`readinessProbe` in the DaemonSet spec), and `config/cni/rbac.yaml` grants `get` on `nodes` for `Bootstrap`'s node-identity check.

---

## For Claude

**Where to start for each concern:**

| Concern                                    | Start here                                                   |
|--------------------------------------------|--------------------------------------------------------------|
| CNI attach/detach flow                     | `internal/cni/ops_add.go:cmdAdd`, `internal/cni/ops_del.go:cmdDel` (`internal/cni/cni.go` only holds `RunPlugin`) |
| CNI runtime config resolution (conflist/env/API auto-detect) | `internal/cni/config.go:parseConf`, `loadHostConf`, `detectNodeNameFromAPI` |
| BGP CRD publish (VRF + advertisement)      | `internal/cni/bgp.go:publishBGPState`                        |
| CNI DaemonSet install/refresh              | `internal/installer/installer.go:Bootstrap` (init container), `internal/installer/installer.go:Run` (long-running container) |
| CRD → BGP translation                      | `internal/reconcile/reconcile.go:BuildDesiredRouter`         |
| BGP runtime application (GoBGP)            | `internal/runtime/gobgp/runtime.go:Apply`                   |
| BGP peer / VRF / advertisement / policy CRUD | `internal/runtime/gobgp/peers.go`, `runtime.go` (`applyVRFs`), `paths.go`, `policies.go` |
| Controller watch graph                     | `internal/controller/bgprouter_controller.go:SetupWithManager` |
| CRD status update logic                    | `internal/controller/status.go`, `bgprouter_controller.go:updateRouterStatus` |
| Orphaned CRD/VRF/VPCAttachment/NAD garbage collection | `internal/controller/gc_controller.go`, `internal/gc/gc.go`, `internal/gc/orphans_test.go` |
| RBAC pre-flight self-check                 | `cmd/galactic-router/main.go:checkWatchPermissions`           |
| Pod → VPC attachment webhook handler        | `internal/webhook/pod_mutator.go:PodMutator.Handle`           |
| VPCAttachment ID allocation                | `internal/webhook/allocate.go:AllocateVPCAttachmentID`        |
| VPCAttachment CR creation + status (CNI side) | `internal/cni/vpcattachment.go:applyVPCAttachment`          |
| Interface naming / base62 encoding         | `internal/plumbing/intf/intf.go`                             |
| Hash-based no-op suppression               | `internal/hash/hash.go`; annotation `galactic.datum.net/config-hash` on BGPRouter |
| GoBGP server lifecycle (start/reconfigure) | `internal/runtime/gobgp/server.go`                          |

**Stable vs. frequently changed:**
- Stable: `internal/plumbing/` (pure kernel primitives), `internal/model/types.go`, `internal/runtime/runtime.go` (interface)
- Active: `internal/controller/` (status conditions, watch graph), `internal/runtime/gobgp/` (EVPN path construction), `internal/reconcile/` (validation rules), `internal/gc/` (GC rules)
- Stub / incomplete: `internal/runtime/frr/` (returns "not implemented" everywhere), `--mode=transit` (rejected at startup)

**Non-obvious patterns:**
- `BGPPeer` and `BGPPolicy` reconcilers do not call Apply themselves — they enqueue their owning `BGPRouter`, which is the only reconciler that calls `RuntimeManager.Apply`. This means touching any associated resource triggers a full router reconcile.
- `SecretReconciler.Reconcile()` is a no-op body — it exists only to register the watch; the real work is done by `secretToRouterRequests` mapping changes to BGPRouter reconcile requests.
- Same for `NodeReconciler` — the reconcile body is empty; the watch mapper `nodeToRouterRequests` does the work.
- `peerStatusRequeue = 30s` periodic requeue keeps BGPPeer session state current because BGP FSM transitions are not Kubernetes events.
- `annotationConfigHash` is persisted on the BGPRouter object (not just in memory) so no-op detection survives pod restarts without re-applying GoBGP config.
- GoBGP `Reconfigure()` calls `old.Stop()` then creates a fresh `BgpServer` — it does NOT call the BGP-level `StopBgp`/`StartBgp` on the old server, avoiding the v4 "Serve loop permanently dead" problem.
- The CNI ADD result is printed to Multus **before** SRv6 ingress setup and BGP CRD publish run (`publishBGPState` is called after `PrintResult` inside `cmdAdd`) — a successful ADD response does not by itself guarantee the BGP CRDs exist yet.
- `cmdDel` never deletes the VRF, veth/tap, routes, SRv6 ingress route, or `BGPAdvertisement`/`BGPVRFInstance` CRDs — only IPAM bookkeeping. Shared-resource cleanup is entirely the GC controller's job (`internal/gc`), to avoid racing a concurrent ADD during pod restarts.
- Production images are published by `.github/workflows/publish.yaml` as two separate per-binary images (`galactic-cni`, `galactic-router`), not one shared image — see CI/CD above.
