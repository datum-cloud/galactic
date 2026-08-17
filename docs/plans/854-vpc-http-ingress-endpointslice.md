# Implementation Plan — #854: EndpointSlice publication for VPC HTTP ingress

- **Issue:** [datum-cloud/enhancements#854](https://github.com/datum-cloud/enhancements/issues/854)
- **Parent:** [datum-cloud/enhancements#796](https://github.com/datum-cloud/enhancements/issues/796) — HTTP Ingress for VPC Networks
- **Design doc:** [HTTP Ingress for VPC Networks](https://github.com/datum-cloud/enhancements/blob/main/enhancements/networking/http-ingress-for-vpc-networks.md) (PR [#851](https://github.com/datum-cloud/enhancements/pull/851), resolves [#853](https://github.com/datum-cloud/enhancements/issues/853))
- **Status:** planning only — no implementation started

## Correction to #854's framing

Galactic-cni has already been split into a chained-plugin architecture (commits `c1704f7`/`e33092c`/`725ef87`). `internal/cni` (the master plugin) no longer talks to Kubernetes for BGP state at all — that moved to `internal/cnibgp`, the **last plugin in the chain** (`galactic-cni` → `galactic-ipam` → `galactic-route` → `galactic-bgp`). #854 was written before/around that split and refers to "galactic-cni" generically. All of this work belongs in **`internal/cnibgp`**, because it's the only plugin in the chain with all four required inputs simultaneously in scope: the pod's real allocated address (from `prevResult`), `vpc`/`vpcAttachment`, the SRv6 locator/nodeID (from `BGPRouter`), and the allocated VRFID/Argument.

## 1. Scope recap (resolved state of #854)

- Compute the SID using the **existing, unmodified** mechanism (`srv6.ComputeSID`) — no new SID logic.
- Publish one `discoveryv1.EndpointSlice` per pod, named after the pod, in the pod's own namespace, carrying the pod's address + SID annotation + `(vpc, vpcAttachment)`-derived tenant annotation.
- Remove it immediately and unconditionally on DEL — no grace period, no sequencing with sidecar/extension-server (not a CNI concern).
- CHECK validates it; GC cleans up stragglers.
- Not in scope: Envoy VPC attachment, sidecar VRF/route, extension-server config patching, eBPF decap, cross-namespace `HTTPProxy` reference resolution.

## 2. Where each piece lands

| Concern | Binary | Package | Existing anchor |
|---|---|---|---|
| SID computation | `galactic-bgp` | `internal/cnibgp` | `publishBGPState`, `bgp.go:318-408` |
| EndpointSlice publish (ADD) | `galactic-bgp` | `internal/cnibgp` (new file) | after `bgp.go:373-398` (BGPAdvertisement CreateOrUpdate) |
| EndpointSlice delete (DEL) | `galactic-bgp` | `internal/cnibgp/ops_del.go` | currently a 6-line no-op (`ops_del.go:22-28`) |
| EndpointSlice validate (CHECK) | `galactic-bgp` | `internal/cnibgp/ops_check.go` | after BGPAdvertisement Get (`ops_check.go:64-68`) |
| Naming/annotation vocabulary | both | `internal/cni/crdnames` | already the shared cross-plugin vocab package |
| Pod-name parsing | `galactic-bgp` (new dependency) | `internal/cni/nadpatch` | sibling to existing `ParsePodNamespace` (`nadpatch.go:40-48`) |
| RBAC (publish/delete) | `galactic-bgp`'s SA | `config/galactic-cni/rbac.yaml` | shares the `galactic-cni` SA (`daemonset.yaml:17`) — confirmed |
| GC backstop | `galactic-router` | `internal/gc/gc.go`, `internal/controller/gc_controller.go` | extend `RemoveOrphanedCRDs` (`gc.go:189-231`), not the CNI's eBPF sweep |
| GC RBAC | `galactic-router`'s SA | `config/galactic-router/rbac.yaml` | mirror existing `bgpadvertisements` delete grant (`rbac.yaml:15-19`) |

## 3. Work items, in dependency order

### Phase 1 — Shared vocabulary (`internal/cni/crdnames`)

Add annotation-key constants (SID, tenant identifier) alongside the existing ones (`crdnames.go:20,26,35`), plus a `TenantIdentifier(vpc, vpcAttachment string) string` helper formatted the same way as `BGPVRFInstanceName`/`BGPAdvertisementName` (`crdnames.go:74-83`) so the value is consistent with names used elsewhere, and an `EndpointSliceName(podName string) string` helper (trivial passthrough, but centralizes the convention like everything else in this package does).

Also add a **label** key constant, `galactic.datum.net/tenant-id`, carrying the same `TenantIdentifier(vpc, vpcAttachment)` value as the annotation (see Discovery label, below) — annotations aren't selectable in a k8s `List`/`Watch` call, so the extension server needs this value present as a label, not only an annotation, to find these EndpointSlices at all. Unit tests alongside `crdnames_test.go`.

### Phase 2 — Pod-name parsing

`internal/cnibgp` currently has no notion of pod name (only `internal/cni` parses `K8S_POD_NAMESPACE` via `nadpatch.ParsePodNamespace`). Add a sibling `ParsePodName` to `nadpatch` and import `nadpatch` from `internal/cnibgp` (new import edge — confirm no cycle; `nadpatch` has no dependency back on `cnibgp` today so this should be clean). Tests mirroring `nadpatch_test.go`'s existing fixture style.

### Phase 3 — SID computation in `galactic-bgp`

Import `internal/plumbing/srv6` into `internal/cnibgp` (net-new; today `ComputeSID`'s only caller is `galactic-router`'s `resolveSRv6SID`, `reconcile.go:376-386`). Inside `publishBGPState`'s retry closure, once `vrfID` is allocated (`bgp.go:329`) and `bgp.srv6Locator`/`bgp.nodeID` are in scope (`bgp.go:324`), call `ComputeSID(bgp.srv6Locator, bgp.nodeID, vrfID, bgpv1alpha1.SRv6FunctionEndDT46)`. Reuse the existing "SRv6 not configured, skip silently" sentinel already established at `bgp.go:418-420` (`registerEBPFDatapath`'s guard) — if SRv6 isn't configured on this node, there's nothing to publish, so EndpointSlice publish should skip the same way.

### Phase 4 — EndpointSlice publish (ADD)

New file `internal/cnibgp/endpointslice.go`, structurally mirroring the existing CreateOrUpdate pattern used for BGPVRFInstance/BGPAdvertisement (`bgp.go:341-353`). Inputs: namespace (already parsed for the BGP path), pod name (Phase 2), the pod's address (already available as `ipamResult`, passed into `publishBGPState` per `ops_add.go:69`), the computed SID (Phase 3), and `(vpc, vpcAttachment)`. Wire the call into `cmdAdd` right after `publishBGPState` succeeds, as its own step under the existing `resourceTracker` rollback (`ops_add.go:41-55`) rather than folded inside the BGP retry closure — keeps failure/rollback attribution clear.

Object carries, per pod:
- **Annotations**: SID (`galactic.datum.net/srv6-sid`), tenant identifier (`galactic.datum.net/tenant-id`) — human-readable detail, matches the existing annotation-based pattern used elsewhere in this codebase (e.g. the `galactic.datum.net/netns.<containerID>` annotation GC already reads).
- **Label**: `galactic.datum.net/tenant-id` set to the same `TenantIdentifier(vpc, vpcAttachment)` value — this is the discovery mechanism (see Open Decisions, item 2): its mere presence marks an EndpointSlice as galactic-published (distinguishing it from ordinary Service-backed slices in the same cluster), and its value lets a consumer select/group by tenant, without a backing `Service` object or the standard `kubernetes.io/service-name` label.

**IPv6-only** (see Open Decisions, item 1) — one `EndpointSlice`, `AddressType: IPv6`, carrying the pod's ULA `/96` address. A dual-stack pod's IPv4 address is not published; IPv4 VPC backends are out of scope for this issue.

### Phase 5 — EndpointSlice delete (DEL)

`internal/cnibgp/ops_del.go:22-28` is currently a complete no-op — this is the first real work it does. Parse config, build the k8s client, parse pod name/namespace from `args.Args`, delete by name+namespace, treat NotFound as success (idempotent, per the acceptance criteria). On any other failure, follow the existing convention at `internal/cni/ops_del.go:72-81` — log and continue rather than fail DEL, since a k8s API hiccup during pod teardown shouldn't block the pod from actually going away; GC is the backstop.

### Phase 6 — CHECK validation

`internal/cnibgp/ops_check.go`: after the existing BGPAdvertisement Get (`:64-68`), Get the EndpointSlice by `crdnames.EndpointSliceName(podName)`, compare its address against the current IPAM/prevResult address and its annotations against freshly recomputed expected values, append mismatches into the same `errs` joined at `:81`. Needs pod-name parsing in CHECK's scope too (Phase 2 covers this).

### Phase 7 — RBAC

Add `discovery.k8s.io`/`endpointslices` (get, list, create, update, patch, delete) to `config/galactic-cni/rbac.yaml`. Confirmed: `config/galactic-cni/daemonset.yaml:17` sets a single `serviceAccountName: galactic-cni` for the whole pod — CNI chain plugins aren't separate pods/containers, they're binaries the kubelet execs on the host, all reading the kubeconfig the installer wrote from this one SA. `galactic-bgp` shares it, so this grant is the only RBAC change needed on the CNI side.

### Phase 8 — GC backstop

EndpointSlice cleanup only needs k8s API access — no kernel/eBPF state — so it belongs in **galactic-router's `GCReconciler`** (ticker-driven, `cmd/galactic-router/root.go:212-231`), not the CNI's separate eBPF sweep (`internal/installer`'s `SweepEBPFVRFTable`, which exists specifically because that state is only reachable from inside the CNI's `run` container — see the precedent comment at `gc.go:326-348`). Recommend deleting the stale EndpointSlice as a side effect of the existing `RemoveOrphanedCRDs` pass (`gc.go:189-231`), keyed by the same per-pod netns-liveness signal already computed for BGPAdvertisement orphan detection (`gc.go:497-510`) — a pod's EndpointSlice is stale under exactly the same condition its BGPAdvertisement is. Add `discovery.k8s.io`/`endpointslices` (get, list, watch, delete) to `config/galactic-router/rbac.yaml`, mirroring the existing delete grant already carved out there specifically for this GC reconciler (`rbac.yaml:15-19`).

### Phase 9 — Config & docs

No new CNI config fields — `vpc`/`vpcAttachment`/`namespace` already exist on `internal/cnibgp/types.go:19-24`; pod name comes from `CNI_ARGS`, not the JSON config. Update `docs/cni/configuration.md`'s galactic-bgp section (currently states it "carries only vpc, vpcattachment, and namespace — nothing else," `:283-286`) to document the EndpointSlice side effect and its annotation schema. Touch `docs/agents/ARCHITECTURE.md` if it enumerates per-binary responsibilities.

### Phase 10 — Tests

`crdnames_test.go` (new helpers) → `nadpatch_test.go` (`ParsePodName`, valid/missing/malformed cases) → `bgp_test.go` or a new `endpointslice_test.go` using the existing `fakeClient(objs...)` helper (`bgp_test.go:50`), with `discoveryv1` added to `testScheme` (`bgp_test.go:41-46`) — cover fresh publish, update-in-place, and the SRv6-not-configured skip path → DEL idempotency and best-effort-on-failure tests → CHECK drift-detection tests → extend `gc_test.go`/`gc_ebpf_test.go` for EndpointSlice orphan removal → an e2e case in `tests/e2e/e2e_test.go` asserting the EndpointSlice appears on ADD and disappears on DEL.

## 4. Suggested PR sequencing

1. `crdnames` + `nadpatch.ParsePodName` (small, foundational, reviewable alone)
2. SID computation wiring in `galactic-bgp` (Phase 3) — proves the `ComputeSID` call site and skip-sentinel, no EndpointSlice yet
3. EndpointSlice publish on ADD + RBAC (Phases 4, 7)
4. EndpointSlice DEL + CHECK (Phases 5, 6)
5. GC backstop in `galactic-router` + its RBAC (Phase 8)
6. Docs + e2e (Phase 9, tail of Phase 10)

## 5. Open engineering decisions surfaced while planning

1. **Dual-stack shape — resolved: IPv6-only.** `EndpointSlice.AddressType` is singular per object (unlike the custom `BGPAdvertisement` CRD, which packs both families into one object today, e.g. `docs/cni/configuration.md`'s dual-stack example). This issue publishes a single `AddressType: IPv6` `EndpointSlice` per pod, carrying the pod's ULA `/96` address; a dual-stack pod's IPv4 address is not published. IPv4 VPC backends for HTTP ingress are out of scope here — consistent with the tenant addressing design being IPv6-primary and every example in the ingress design doc using ULA addresses. Publishing an IPv4 `EndpointSlice` alongside it, if ever needed, would be a follow-up issue, not an implicit extension of this one.
2. **Discovery label for the extension server — resolved.** No backing `Service` object, so no `kubernetes.io/service-name` label to key off (deliberately, per the design doc's "not synthesize a second EndpointSlice" point). **Decision: a new label, `galactic.datum.net/tenant-id`, carrying the same value as the `TenantIdentifier(vpc, vpcAttachment)` annotation.** galactic-cni sets this unilaterally as part of Phase 1/4 — it doesn't require the extension server to exist first, but it is the contract that component's future watch/index logic needs to consume. Worth flagging to whoever picks up that work so they don't invent a different key independently.
3. **`galactic-bgp`'s ServiceAccount — resolved.** Single shared `galactic-cni` SA confirmed via `config/galactic-cni/daemonset.yaml:17`; Phase 7 needs no split.
4. **Rollback semantics if EndpointSlice publish fails after BGPAdvertisement already succeeded — resolved.** `publishBGPState`'s writes are all `CreateOrUpdate` keyed by deterministic names; a failure just fails `cmdAdd`, kubelet retries, and the retry's `CreateOrUpdate` calls land on the same already-created objects rather than duplicating them. GC (Phase 8) covers the case where the pod never comes up at all. No new rollback code needed.
