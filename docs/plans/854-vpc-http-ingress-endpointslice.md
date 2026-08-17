# Implementation Plan — #854: EndpointSlice publication for VPC HTTP ingress

- **Issue:** [datum-cloud/enhancements#854](https://github.com/datum-cloud/enhancements/issues/854)
- **Parent:** [datum-cloud/enhancements#796](https://github.com/datum-cloud/enhancements/issues/796) — HTTP Ingress for VPC Networks
- **Design doc:** [HTTP Ingress for VPC Networks](https://github.com/datum-cloud/enhancements/blob/main/enhancements/networking/http-ingress-for-vpc-networks.md) (PR [#851](https://github.com/datum-cloud/enhancements/pull/851), resolves [#853](https://github.com/datum-cloud/enhancements/issues/853))
- **Status:** planning only — no implementation started. Revised 2026-08-13 after a review pass caught drift against the current repo (see the "Revision note" callouts throughout) — most of it stale paths, but two are real design gaps (Phases 4 and 8) worth reading before starting. Revised again 2026-08-17: Open Decision 5 resolved — VM/tap-attached workloads are in scope and are this issue's primary use case, not an implicitly-excluded edge case; Phase 4's nil-`ipamResult` skip already handles this correctly (it's an address-existence check, not a VM exclusion) once confirmed against the current `internal/cnitap`/`internal/cnibgp` code, so no VM-specific implementation work is added by this revision.

## Correction to #854's framing

Galactic-cni has already been split into a chained-plugin architecture. #854 was written before/around that split and refers to "galactic-cni" generically. All of this work belongs in **`internal/cnibgp`** (binary `galactic-bgp`), because it's the only plugin in the chain with all four required inputs simultaneously in scope: the pod's real allocated address (from `prevResult`), `vpc`/`vpcAttachment`, the SRv6 locator/nodeID (from `BGPRouter`), and the allocated VRFID/Argument.

> **Revision note:** the chain topology has moved on further since this framing was first written. It is no longer `galactic-cni → galactic-ipam → galactic-route → galactic-bgp`. Current shape: a **master plugin** creates the VRF and host-side interface — `galactic-veth` for containers or `galactic-tap` for VM workloads — IPAM is **delegated** (not chained) to `galactic-ipam` via the standard CNI IPAM protocol, an optional `galactic-route` installs termination routes, and `galactic-bgp` runs last. `galactic-cni` itself is now purely a host installer/stager (`init`/`run` DaemonSet containers) and is never itself a CNI plugin — no NAD ever names it in a `"type"` field. This matters here because `galactic-bgp` is chain-invoked after **either** master plugin, so this work needs an explicit answer for the `galactic-tap`/VM path — see Open Decision 5.

## 1. Scope recap (resolved state of #854)

- Compute the SID using the **existing, unmodified** mechanism (`srv6.ComputeSID`) — no new SID logic.
- Publish one `discoveryv1.EndpointSlice` per pod, named after the pod, in the pod's own namespace, carrying the pod's address + SID annotation + `(vpc, vpcAttachment)`-derived tenant annotation.
- Remove it immediately and unconditionally on DEL — no grace period, no sequencing with sidecar/extension-server (not a CNI concern).
- CHECK validates it; GC cleans up stragglers.
- Not in scope: Envoy VPC attachment, sidecar VRF/route, extension-server config patching, eBPF decap, cross-namespace `HTTPProxy` reference resolution.

## 2. Where each piece lands

| Concern | Binary | Package | Existing anchor |
|---|---|---|---|
| SID computation | `galactic-bgp` | `internal/cnibgp` | `publishBGPState`, `bgp.go:316-421` |
| EndpointSlice publish (ADD) | `galactic-bgp` | `internal/cnibgp` (new file) | after `publishBGPState` succeeds (`ops_add.go`), **not** folded into its retry closure — see Phase 4's rollback-risk callout |
| EndpointSlice delete (DEL) | `galactic-bgp` | `internal/cnibgp/ops_del.go` | currently a no-op (delegates all cleanup to GC) |
| EndpointSlice validate (CHECK) | `galactic-bgp` | `internal/cnibgp/ops_check.go` | after the existing BGPAdvertisement `Get` |
| Naming/annotation vocabulary | both | `internal/crdnames` | already the shared cross-plugin vocab package (moved out from under `internal/cni`) |
| Pod-name parsing | `galactic-bgp` (new dependency) | `internal/nadpatch` | sibling to existing `ParsePodNamespace` (moved out from under `internal/cni`) |
| RBAC (publish/delete) | `galactic-bgp`'s SA | `config/galactic-cni/rbac.yaml` | shares the `galactic-cni` ClusterRole/SA — confirmed |
| GC / cleanup backstop | `galactic-router` (and/or the k8s garbage collector) | `internal/gc/gc.go` | see Phase 8 — reconsidered, not a simple extension of `RemoveOrphanedCRDs` |
| GC RBAC | `galactic-router`'s SA | `config/galactic-router/rbac.yaml` | mirror existing `bgpadvertisements`/`bgpvrfinstances` delete grant |

> **Revision note:** `internal/cni/crdnames` and `internal/cni/nadpatch` are stale paths — both packages have since moved to top-level leaf packages, `internal/crdnames` and `internal/nadpatch`. No structural change to Phase 1/2's plan, just update imports accordingly. (Also note: `config/cni/` and `config/router/` have since been renamed to `config/galactic-cni/` and `config/galactic-router/` respectively — paths above already reflect the new names.)

## 3. Work items, in dependency order

### Phase 1 — Shared vocabulary (`internal/crdnames`)

Add annotation-key constants (SID, tenant identifier) alongside the existing ones (`AnnotationAllocatedSubnetIPv6`/`IPv4`/`NetNS`), plus a `TenantIdentifier(vpc, vpcAttachment string) string` helper formatted the same way as `BGPVRFInstanceName`/`BGPAdvertisementName` so the value is consistent with names used elsewhere, and an `EndpointSliceName(podName string) string` helper (trivial passthrough, but centralizes the convention like everything else in this package does — see Phase 4's naming-collision note for why "trivial" still needs a defensive check downstream).

Also add a **label** key constant, `galactic.datum.net/tenant-id`, carrying the same `TenantIdentifier(vpc, vpcAttachment)` value as the annotation (see Discovery label, Open Decision 2) — annotations aren't selectable in a k8s `List`/`Watch` call, so the extension server needs this value present as a label, not only an annotation, to find these EndpointSlices at all. Unit tests alongside `crdnames_test.go`.

### Phase 2 — Pod-name parsing

`internal/cnibgp` currently has no notion of pod name (only the master plugins parse `K8S_POD_NAMESPACE` via `nadpatch.ParsePodNamespace`). Add a sibling `ParsePodName` to `internal/nadpatch` and import it from `internal/cnibgp` (new import edge — confirm no cycle; `nadpatch` has no dependency back on `cnibgp` today so this should be clean). Tests mirroring `nadpatch_test.go`'s existing fixture style.

### Phase 3 — SID computation in `galactic-bgp`

Import `internal/plumbing/srv6` into `internal/cnibgp` (net-new; today `ComputeSID`'s only other caller is `galactic-router`'s reconciler). Inside `publishBGPState`'s retry closure, once `vrfID` is allocated and `bgp.srv6Locator`/`bgp.nodeID` are in scope, call `ComputeSID(bgp.srv6Locator, bgp.nodeID, vrfID, bgpv1alpha1.SRv6FunctionEndDT46)`. Reuse the existing "SRv6 not configured, skip silently" sentinel already established by `registerEBPFDatapath`'s guard (`bgp.srv6Locator == "" || bgp.nodeID == 0` → `registered=false, err=nil`) — if SRv6 isn't configured on this node, there's nothing to publish, so EndpointSlice publish should skip the same way.

### Phase 4 — EndpointSlice publish (ADD)

New file `internal/cnibgp/endpointslice.go`, structurally mirroring the existing CreateOrUpdate pattern used for BGPVRFInstance/BGPAdvertisement. Inputs: namespace (already parsed for the BGP path), pod name (Phase 2), the pod's address (already available as `ipamResult`, passed into `publishBGPState`), the computed SID (Phase 3), and `(vpc, vpcAttachment)`.

> **Revision note — implementation detail:** `ipamResult.IPv6Subnet` is a `*net.IPNet` whose `.IP` is the pod's actual single address, assigned to the guest interface with a `/96` mask (it's not a distinct subnet block from the address). The EndpointSlice's `Endpoints[].Addresses` wants the bare address — use `.IP` alone, not the CIDR string.

> **⚠️ Revision note — rollback risk, read before wiring this in.** The original plan called for wiring this call in "right after `publishBGPState` succeeds, as its own step under the existing `resourceTracker` rollback — rather than folded inside the BGP retry closure — keeps failure/rollback attribution clear." That sequencing is unsafe as-is. `publishBGPState` sets `result.advertisementCreated = true` **unconditionally** after any successful `CreateOrUpdate` on the `BGPAdvertisement` — unlike `vrfInstanceCreated`, which correctly gates on `op == OperationResultCreated`. `resourceTracker.cleanup` then deletes the `BGPAdvertisement` unconditionally whenever `advertisementCreated` is true, with no "did I create this or just reuse a live sibling's" distinction. `BGPAdvertisement` objects are reused (updated, not created) across pod churn on the same `vpcAttachment`, so if EndpointSlice publish is a separate downstream step and it fails, the deferred rollback can delete a `BGPAdvertisement` that's still backing a different, live container's route — not just this ADD's own. Pick one before implementing:
> 1. Fix `advertisementCreated` to mirror `vrfInstanceCreated`'s create-only semantics first, or
> 2. Fold EndpointSlice publish inside `publishBGPState`'s own retry closure after all (reverting the "keep it separate" call), or
> 3. Make `resourceTracker.cleanup` never delete a `BGPAdvertisement` it only updated.
>
> This didn't matter before this issue because nothing failure-prone ran between the `CreateOrUpdate` and `cmdAdd` returning; adding a whole new k8s write in between is exactly what turns this from a theoretical crack into a real footgun.

> **Revision note — naming collision.** `EndpointSliceName(podName)` keys `CreateOrUpdate` purely on the pod's name in its own namespace. If any other EndpointSlice (Service-backed or otherwise) ever ends up with that exact name, this code will silently start mutating an object it doesn't own. Add a defensive check — e.g. bail if a pre-existing object at that name/namespace lacks the `tenant-id` label — rather than trusting name uniqueness alone.

> **Revision note — VM/tap and no-IPAM skip (resolved: not a VM-exclusion, an address-existence check).** `ipamResult` is `nil` whenever no `"ipam"` block is configured on the master plugin's stanza — this happens for both `galactic-veth` and `galactic-tap`, and is not tap-specific. Per Open Decision 5, VM/tap attachments are in scope and are this issue's primary use case; a tap stanza with an `"ipam"` block configured gets exactly the same `ipamResult` (the pool-allocated host/VRF-side address, already the same value `publishBGPState` advertises via BGP for that attachment today) that a veth attachment would, so Phase 4's publish path needs no tap-specific branch. The nil-skip only fires for a genuinely address-less attachment — tap with no `"ipam"` block (guest fully self-manages, host has no address to know about) or veth with none configured — same pattern as the SRv6-not-configured sentinel: no address to publish, no EndpointSlice, not an error. Operators running tap-backed VMs as HTTP ingress backends need an `"ipam"` block configured for this issue's EndpointSlice publish (and the existing BGP advertisement) to have anything to carry; note that neither this issue nor the existing BGP path confirms the guest actually bound the pool-allocated address (no DHCP push, no ARP/NDP snooping) — that's a pre-existing property of tap addressing generally, not a gap this issue introduces or is scoped to close.

Object carries, per pod:
- **Annotations**: SID (`galactic.datum.net/srv6-sid`), tenant identifier (`galactic.datum.net/tenant-id`) — human-readable detail, matches the existing annotation-based pattern used elsewhere in this codebase.
- **Label**: `galactic.datum.net/tenant-id` set to the same `TenantIdentifier(vpc, vpcAttachment)` value — this is the discovery mechanism (see Open Decision 2).

**IPv6-only** (see Open Decision 1) — one `EndpointSlice`, `AddressType: IPv6`, carrying the pod's address. A dual-stack pod's IPv4 address is not published; IPv4 VPC backends are out of scope for this issue.

### Phase 5 — EndpointSlice delete (DEL)

`internal/cnibgp/ops_del.go`'s `cmdDel` is currently a complete no-op that defers all cleanup to GC, on the reasoning that the shared BGP CRDs may still be in use by another pod's attachment — this is the first real work it does. Parse config, build the k8s client, parse pod name/namespace from `args.Args`, delete by name+namespace, treat NotFound as success (idempotent, per the acceptance criteria). On any other failure, follow the existing best-effort convention elsewhere in the chain's own DEL paths — log and continue rather than fail DEL, since a k8s API hiccup during pod teardown shouldn't block the pod from actually going away; GC/owner-GC is the backstop (Phase 8).

This is a deliberate, correct divergence from the "DEL is a no-op" pattern the rest of the chain follows: the reasoning behind that pattern (the resource might be shared with a live sibling) doesn't apply here — an EndpointSlice is 1:1 with exactly one pod, never shared.

### Phase 6 — CHECK validation

`internal/cnibgp/ops_check.go`'s `cmdCheck`: after the existing BGPAdvertisement `Get`, `Get` the EndpointSlice by `crdnames.EndpointSliceName(podName)`, compare its address against the current IPAM/prevResult address and its annotations against freshly recomputed expected values, append mismatches into the same joined error. Needs pod-name parsing in CHECK's scope too (Phase 2 covers this).

### Phase 7 — RBAC

Add `discovery.k8s.io`/`endpointslices` (get, list, create, update, patch, delete) to `config/galactic-cni/rbac.yaml`. Confirmed: the CNI DaemonSet sets a single `serviceAccountName: galactic-cni` for the whole pod — CNI chain plugins aren't separate pods/containers, they're binaries the kubelet execs on the host, all reading the kubeconfig the installer wrote from this one SA. `galactic-bgp` shares it, so this grant is the only RBAC change strictly needed on the CNI side for publish/delete/CHECK.

> **Revision note:** if Open Decision 6 lands on the ownerReference approach, this phase also needs a `pods` `get` grant (to look up the owning Pod's UID) — not present in `config/galactic-cni/rbac.yaml` today.

### Phase 8 — Cleanup backstop (reconsidered)

> **Revision note — this phase needed a rethink, not just a path fix.** The original plan was to extend `RemoveOrphanedCRDs` in `internal/gc/gc.go`, "keyed by the same per-pod netns-liveness signal already computed for BGPAdvertisement orphan detection." That signal doesn't exist at pod granularity: `CollectOrphanedCRDs` judges a `BGPAdvertisement` orphaned only once *every* containerID ever recorded on it (across pod churn reusing the same `vpcAttachment`) is dead — it's deliberately vpcAttachment-scoped, not pod-scoped, and there is no persisted pod-name↔containerID mapping anywhere GC could read to ask "is *this specific pod's* EndpointSlice stale." That vpcAttachment-level sharing is also exactly why the BGP CRDs need a kernel-netns heuristic at all: there's no single object they belong to that the k8s garbage collector could key off.
>
> An EndpointSlice doesn't have that problem — it's genuinely 1:1 with one pod. That makes Kubernetes' own garbage collector a better fit than another netns sweep:
>
> **Recommended approach:** during ADD, `Get` the owning Pod (namespace + name, already known) and set `metadata.ownerReferences` on the EndpointSlice to it (same namespace, so the cross-namespace-owner restriction doesn't apply; `blockOwnerDeletion: false` since ordering doesn't matter here). When the Pod object is deleted, the API server's own garbage collector deletes the EndpointSlice automatically — no polling, no kernel-state heuristic, no new RBAC on `galactic-router`'s side at all. Phase 5's explicit delete-on-DEL stays as the fast, deterministic path for the common case; the ownerReference is the backstop for force-deleted/never-DEL'd pods, which is exactly the scenario the original GC-reconciler idea was trying to cover.
>
> **If a backstop independent of Pod-object presence is still wanted** (e.g. to cover a pod stuck in a bad state where the API object lingers but the workload is clearly gone), the fallback is to give the EndpointSlice its own per-container netns/containerID annotation — mirroring `crdnames.AnnotationNetNS`'s convention — so `galactic-router`'s GC reconciler can run an independent, EndpointSlice-scoped sweep shaped like `CollectOrphanedCRDs`, rather than trying to derive per-pod liveness from the BGPAdvertisement's aggregate annotations. This is more moving parts than the ownerReference approach and should only be added if a concrete gap in owner-based GC shows up.
>
> Either way, this phase is now smaller than originally scoped, and doesn't necessarily touch `internal/gc/gc.go`/`config/galactic-router/rbac.yaml` at all if the ownerReference approach fully covers it.

### Phase 9 — Config & docs

No new CNI config fields — `vpc`/`vpcAttachment`/`namespace` already exist on `galactic-bgp`'s own config type; pod name comes from `CNI_ARGS`, not the JSON config. Update `docs/cni/configuration.md`'s galactic-bgp section (currently states its stanza "carries only vpc, vpcattachment, and namespace — nothing else") to document the EndpointSlice side effect and its annotation schema.

> **Revision note:** the old monolithic `docs/agents/ARCHITECTURE.md` has been split into three component-scoped docs. This work touches `docs/agents/ARCHITECTURE-CNI.md` (per-binary responsibilities, module reference) and, if the ownerReference/GC approach in Phase 8 touches `galactic-router`, `docs/agents/ARCHITECTURE-ROUTER.md`'s GC section too.

### Phase 10 — Tests

`crdnames_test.go` (new helpers) → `nadpatch_test.go` (`ParsePodName`, valid/missing/malformed cases) → `bgp_test.go` or a new `endpointslice_test.go` using the existing `fakeClient(objs...)` helper, with `discoveryv1` added to `testScheme` (not present today) — cover fresh publish, update-in-place, the SRv6-not-configured skip path, **and the nil-`ipamResult` skip path** (Phase 4's VM/tap note) → DEL idempotency and best-effort-on-failure tests → CHECK drift-detection tests → the naming-collision defensive check (Phase 4) → ownerReference-GC behavior if that's the Phase 8 approach, else extend `gc_test.go`/`gc_ebpf_test.go` for EndpointSlice orphan removal → an e2e case in `tests/e2e/e2e_test.go` asserting the EndpointSlice appears on ADD and disappears on DEL (and, ideally, on Pod force-delete if ownerReference is used).

## 4. Suggested PR sequencing

1. `crdnames` + `nadpatch.ParsePodName` (small, foundational, reviewable alone)
2. SID computation wiring in `galactic-bgp` (Phase 3) — proves the `ComputeSID` call site and skip-sentinel, no EndpointSlice yet
3. EndpointSlice publish on ADD + RBAC (Phases 4, 7) — **must resolve the rollback-risk and nil-`ipamResult` callouts in Phase 4 before merge**
4. EndpointSlice DEL + CHECK (Phases 5, 6)
5. Cleanup backstop (Phase 8) + any RBAC it ends up needing
6. Docs + e2e (Phase 9, tail of Phase 10)

## 5. Open engineering decisions surfaced while planning

1. **Dual-stack shape — resolved: IPv6-only.** `EndpointSlice.AddressType` is singular per object (unlike the custom `BGPAdvertisement` CRD, which packs both families into one object today). This issue publishes a single `AddressType: IPv6` `EndpointSlice` per pod, carrying the pod's address; a dual-stack pod's IPv4 address is not published. IPv4 VPC backends for HTTP ingress are out of scope here — consistent with the tenant addressing design being IPv6-primary. Publishing an IPv4 `EndpointSlice` alongside it, if ever needed, would be a follow-up issue, not an implicit extension of this one.
2. **Discovery label for the extension server — resolved.** No backing `Service` object, so no `kubernetes.io/service-name` label to key off (deliberately, per the design doc's "not synthesize a second EndpointSlice" point). **Decision: a new label, `galactic.datum.net/tenant-id`, carrying the same value as the `TenantIdentifier(vpc, vpcAttachment)` annotation.** `galactic-bgp` sets this unilaterally as part of Phase 1/4 — it doesn't require the extension server to exist first, but it is the contract that component's future watch/index logic needs to consume. Worth flagging to whoever picks up that work so they don't invent a different key independently.
3. **`galactic-bgp`'s ServiceAccount — resolved.** Single shared `galactic-cni` SA confirmed; Phase 7 needs no split (beyond possibly adding a `pods` `get` grant — see Open Decision 6).
4. **Rollback semantics if EndpointSlice publish fails after BGPAdvertisement already succeeded — revisited, not fully resolved.** The original take ("`publishBGPState`'s writes are all idempotent `CreateOrUpdate`s, a failure just fails `cmdAdd` and retries land on the same objects, no new rollback code needed") is true of `publishBGPState`'s *own* retryable failures, but doesn't cover the case this issue actually introduces: a **separate step after** `publishBGPState` returns successfully, whose failure triggers the *existing* `resourceTracker` rollback. See Phase 4's rollback-risk callout — `advertisementCreated`'s current unconditional semantics mean that rollback path can delete a `BGPAdvertisement` still in use by an unrelated, live attachment. This needs one of the three fixes listed there before Phase 4 ships, not just "no new rollback code needed."
5. **VM/tap-attached workloads — resolved: in scope, and the primary use case.** `galactic-bgp` runs after `galactic-tap` for VM workloads exactly as it does after `galactic-veth`. Confirmed against the current code (`internal/cnitap`, `internal/cnibgp/prevresult.go`): `ipamResult` is nil only when no `"ipam"` block is configured on the master plugin's stanza — this is not tap-specific, and a tap stanza *with* `"ipam"` configured produces the same pool-allocated address `publishBGPState` already advertises via BGP for that attachment. So no VM-specific branch is needed in Phase 4 — the existing nil-skip already does the right thing (skip only when there's genuinely no address to publish), and tap attachments configured with IPAM flow through the normal publish path unchanged. Practical implication: operators running tap-backed VMs as HTTP-ingress backends need an `"ipam"` block on the tap stanza for an EndpointSlice (or a BGP advertisement) to exist at all. Since a VM is a Pod-backed netns exactly like a container attachment (the VM's guest runs inside a Pod's netns; there's no non-Pod-backed case to special-case), EndpointSlice's Pod-endpoint semantics need no rework, and Phase 8's ownerReference-to-Pod GC approach applies unchanged to tap attachments too. One caveat worth calling out to whoever owns the parent design (#796): the pool-allocated address is never confirmed as actually bound inside the guest (no DHCP push, no ARP/NDP snooping in the current chain) — a pre-existing property of tap addressing, not something this issue introduces, but worth being explicit about now that VM/tap is confirmed primary rather than a maybe-later extension.
6. **New — GC mechanism: ownerReference vs. netns-heuristic sweep.** See Phase 8. Recommendation is ownerReference to the Pod as the primary mechanism (idiomatic, no polling, no new `galactic-router` RBAC), with Phase 5's explicit DEL as the fast path and no netns-based backstop unless a concrete gap turns up. Flagging as an open decision rather than folding it silently into Phase 8 because it changes what Phase 7's RBAC and Phase 9's `ARCHITECTURE-ROUTER.md` touch depend on.
