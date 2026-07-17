# CNI Package Refactoring Plan

## Current State

`cni.go` is **1287 lines** — a single monolithic file mixing entry points, BGP state management, IPAM orchestration, network namespace operations, CNI result building, and Kubernetes CRD lifecycle.

Existing subpackages (`ipam`, `route`, `tap`, `veth`) already extracted their kernel primitives. The remaining work is to split `cni.go` along the same feature-boundary principle.

`types.go` (37 lines) already exists with `Termination`, `IPAM`, `Route`, `Address` — but `PluginConf`, `ipamResult`, and `HostDevicePluginConf` are still in `cni.go`.

---

## Target File Layout

```
internal/cni/
├── doc.go              ← NEW: package documentation
├── cni.go              ← ENTRY POINT: RunPlugin(), skel.CNIFuncs wiring
├── types.go            ← EXTEND: PluginConf, ipamResult, HostDevicePluginConf, Termination
├── config.go           ← NEW: parseConf, PluginConf JSON tags
├── ops_add.go          ← NEW: cmdAdd
├── ops_del.go          ← NEW: cmdDel
├── ops_check.go        ← NEW: cmdCheck, cmdStatus, helper validators
├── bgp.go              ← NEW: BGP state publishing, CRD CreateOrUpdate, bgpConfig
├── resource.go         ← NEW: resourceTracker, rollback/cleanup
├── netns.go            ← NEW: network namespace helpers (configureInterfaceInNetns, readGuestInterface, cleanupContainerNetns, checkGuestInterface)
├── result.go           ← NEW: buildResult, buildVethResult, buildTapResult, CNI result printing
├── ipam_ops.go         ← NEW: configureIPAM, deallocateIPAM, getAllocatedSubnetFromCRD
└── host_device.go      ← NEW: hostDevice plugin delegation (hostDeviceExecutable, hostDevice)
```

Each new file is ≤200 lines. `cni.go` shrinks to ~30 lines.

---

## File-by-File Breakdown

### `doc.go` (NEW, ~15 lines)

Package-level godoc explaining the CNI plugin's purpose: wires containers into VPC networks (VRF, veth/tap, SRv6 ingress), allocates pod subnets, and publishes BGPAdvertisement CRDs. Mentions the subpackages and the ADD→BGP→router lifecycle.

### `cni.go` (ENTRY POINT, ~30 lines)

**Keep here:**
- `RunPlugin()` — `skel.PluginMainFuncs` wiring
- `init()` — scheme registration
- `SetEnableLocalIPAM()` — CLI flag setter
- Constants only: `cniTimeout`, `ipamTypePool`, `localIPAMDefaultPool`, `localIPAMDefaultSubnetLen`, `interfaceTypeVeth`, `interfaceTypeTap`, `defaultNamespace`

**Move out:** All function bodies. Only type declarations that are referenced from other files stay (`PluginConf` → `types.go`).

### `types.go` (EXTEND, ~60 lines)

**Move here from `cni.go`:**
- `PluginConf` — the CNI config struct
- `ipamResult` — internal IPAM allocation details
- `HostDevicePluginConf` — host-device delegation config

**Already here:** `Termination`, `IPAM`, `Route`, `Address`

### `config.go` (NEW, ~30 lines)

**Move here from `cni.go`:**
- `parseConf()` — JSON unmarshal + validation of `InterfaceType`
- `subnetAnnotationKey()` — annotation key builder for container ID prefix

### `ops_add.go` (NEW, ~120 lines)

**Move here from `cni.go`:**
- `cmdAdd()` — the full ADD lifecycle: parse → VRF → interface → routes → IPAM/result → BGP state

This is the main orchestration function. It calls into:
- `vrf.Add()`, `veth.Add()`, `tap.Add()` (subpackages)
- `route.Add()` (subpackage)
- `buildVethResult()` (result.go)
- `publishBGPState()` (bgp.go)
- `resourceTracker` methods (resource.go)

### `ops_del.go` (NEW, ~100 lines)

**Move here from `cni.go`:**
- `cmdDel()` — best-effort cleanup: IPAM deallocation → CRD delete → host-device → routes → SRv6 → interface → VRF

### `ops_check.go` (NEW, ~100 lines)

**Move here from `cni.go`:**
- `cmdCheck()` — validates VRF, host interface, guest interface, termination routes
- `cmdStatus()` — validates VRF, host interface, API server reachability
- `probeAPIServer()` — lightweight healthz check
- `checkGuestInterface()` — netns interface existence check
- `checkTerminationRoutes()` — VRF route table verification

### `bgp.go` (NEW, ~180 lines)

**Move here from `cni.go`:**
- `bgpConfig` struct
- `lookupBGPRouter()` — find BGPRouter targeting this node
- `newK8sClient()` — Kubernetes client construction
- `bgpVRFInstanceName()` / `bgpAdvertisementName()` — deterministic naming
- `routeTarget()` — ASN:NN route target computation
- `publishBGPState()` — the full BGP state publication: host veth gateway → SRv6 ingress → BGPVRFInstance → BGPAdvertisement CRDs
- `configureHostVethGateway()` — /128 host address + VRF subnet route
- `setupSRv6Ingress()` — End.DT46 SRv6 decap route

### `resource.go` (NEW, ~70 lines)

**Move here from `cni.go`:**
- `resourceTracker` struct — tracks all resources created during cmdAdd
- `resourceTracker.cleanup()` — selective rollback in reverse creation order

### `netns.go` (NEW, ~120 lines)

**Move here from `cni.go`:**
- `configureInterfaceInNetns()` — IP address + default route on guest interface
- `readGuestInterface()` — MAC/MTU from guest netns
- `cleanupContainerNetns()` — remove stale interface from container netns

### `result.go` (NEW, ~80 lines)

**Move here from `cni.go`:**
- `buildResult()` — generic CNI result construction (interfaces + IPs + routes)
- `buildVethResult()` — veth-specific: host-device delegation → IPAM → guest attrs → print
- `buildTapResult()` — tap-specific: single host interface, no IPAM

### `ipam_ops.go` (NEW, ~100 lines)

**Move here from `cni.go`:**
- `configureIPAM()` — dispatch to pool/static allocator, configure guest interface
- `deallocateIPAM()` — read CRD annotation → deallocate from pool
- `getAllocatedSubnetFromCRD()` — lookup BGPAdvertisement annotation

### `host_device.go` (NEW, ~30 lines)

**Move here from `cni.go`:**
- `hostDeviceExecutable()` — path resolution for host-device plugin binary
- `hostDevice()` — invoke CNI host-device plugin via `invoke.ExecPlugin`

---

## What Stays in `cni.go` (the entry point)

Only the CNI framework glue:

```go
func RunPlugin() {
    skel.PluginMainFuncs(...)
}

func init() {
    utilruntime.Must(clientgoscheme.AddToScheme(cniScheme))
    utilruntime.Must(bgpv1alpha1.AddToScheme(cniScheme))
}

func SetEnableLocalIPAM(v bool) {
    enableLocalIPAM = v
}
```

Plus the scheme variable and the constants that other files reference directly.

---

## Migration Order

1. **`doc.go`** — write first, zero risk
2. **`types.go`** — move type declarations, no behavior change
3. **`config.go`** — pure functions, no dependencies
4. **`resource.go`** — struct + cleanup, self-contained
5. **`bgp.go`** — BGP helpers + `publishBGPState`, called by ops_add.go
6. **`result.go`** — result builders, called by ops_add.go
7. **`netns.go`** — netns helpers, called by ops_add.go + ipam_ops.go
8. **`ipam_ops.go`** — IPAM operations, called by ops_del.go
9. **`host_device.go`** — host-device delegation, called by ops_add.go
10. **`ops_check.go`** — cmdCheck + cmdStatus, standalone
11. **`ops_add.go`** — cmdAdd, the big one (calls into everything above)
12. **`ops_del.go`** — cmdDel, calls into resource.go + ipam_ops.go + subpackages
13. **`cni.go`** — strip to entry point, import all new files

Each step is a `go build` gate. No step depends on the next — all new files are written and compiled before cni.go is trimmed.

---

## Design Principles

- **cni.go remains the package entry point** — `RunPlugin()` lives here, callers import `go.datum.net/galactic/internal/cni` and call `cni.RunPlugin()`
- **No circular dependencies** — each file imports only files below it in the dependency chain (ops_* → bgp/result/netns/ipam_ops/host_device → config/resource → types)
- **Subpackages unchanged** — `ipam`, `route`, `tap`, `veth` stay as-is; they already follow the same pattern
- **Test file untouched** — `cni_test.go` imports the package; no test changes needed since the public API (`RunPlugin()`) is unchanged
- **godoc coherence** — each new file has a one-line package comment describing its responsibility
