# Implementation Plan — #855: Ingress sidecar for VPC backend connectivity

- **Issue:** [datum-cloud/enhancements#855](https://github.com/datum-cloud/enhancements/issues/855)
- **Parent:** [datum-cloud/enhancements#796](https://github.com/datum-cloud/enhancements/issues/796) — HTTP Ingress for VPC Networks
- **Design doc:** [HTTP Ingress for VPC Networks](https://github.com/datum-cloud/enhancements/blob/main/enhancements/networking/http-ingress-for-vpc-networks.md) (PR [#851](https://github.com/datum-cloud/enhancements/pull/851), resolves [#853](https://github.com/datum-cloud/enhancements/issues/853))
- **Sibling plan:** [#854's implementation plan](https://github.com/datum-cloud/galactic/pull/309) (`docs/plans/854-vpc-http-ingress-endpointslice.md`, open/unmerged) — defines the exact annotation/label contract this plan consumes
- **Status:** planning only — no implementation started

## Correction to #855's framing

#855's acceptance criteria were written before PR #851's design existed and describe the sidecar performing backend health checks and pushing Envoy xDS/EDS updates directly. The accepted design gives it a narrower, purely data-plane job and assigns the xDS-facing work to a separate Envoy Gateway extension server (#856/#857):

| Original #855 AC | Design's actual owner |
|---|---|
| Watch VPCAttachment, react to state changes | Sidecar watches `EndpointSlice`, not `VPCAttachment` |
| Discover VPC backends via Endpoints/EndpointSlices | Same object, but read for VRF/route purposes, not backend discovery |
| Health-check VPC backends | Not in PR #851 at all — no component owns this; open gap, see below |
| Translate backend state into Envoy xDS/EDS | Extension server (#856/#857), not this sidecar |
| Attach/detach VPC network lifecycle | Sidecar, scoped to VRF device + SRv6 route only — pod IP/attachment itself is `galactic-cni` (#854) |
| Prometheus metrics | Sidecar, scoped to VRF/route reconcile state |
| Graceful shutdown detaches before termination | Sidecar |
| Configurable via ConfigMap/CRD | Not required — desired state derives entirely from the `EndpointSlice` watch |

#796's own "a single Envoy Gateway instance attaches to one VPC at a time" goal was also stale against this design and has been corrected on the issue directly (2026-08-08): the shared Envoy Gateway fleet serves **all tenants** concurrently, each disambiguated independently via its own per-tenant VRF on the same node. This plan is written against that corrected scope — the sidecar's reconcile loop is not scoped to a single VPC.

## 1. Scope recap (resolved state of #855)

Per PR #851's Setup/Teardown sections:

1. Watch `EndpointSlice` objects published per pod by `galactic-cni` (#854), selected by the `galactic.datum.net/tenant-id` **label** (annotations aren't selector-capable — see the contract below).
2. Group by that label's value — the `(vpc, vpcAttachment)` tenant identifier — not by individual pod/EndpointSlice. One VRF device and one route serve every pod sharing a network attachment.
3. Per active tenant: ensure a per-tenant Linux VRF device exists, and ensure a subnet-scoped SRv6 encapsulation (`seg6`, ENCAP_RED mode) route toward that tenant's SID is installed in the VRF's table.
4. Per tenant that drops out of desired state: tear down the VRF device + route, subject to a not-yet-designed grace period (see Open Decisions).
5. Runs as a second container in the Envoy Gateway pod, sharing its network namespace — the VRF device it creates is immediately usable by Envoy's own upstream sockets, no extra plumbing.

## 2. Reusable primitives already in this repo

This is not new kernel-programming work — `internal/plumbing/vrf` and `internal/plumbing/srv6` already implement the exact mechanism, built for `galactic-cni`'s own pod-attachment path:

| Function | Package | Role here |
|---|---|---|
| `vrf.Add(vpc, vpcAttachment string) error` | `internal/plumbing/vrf/vrf.go` | Create the per-tenant VRF device; idempotent, already serialized against concurrent callers on the same node |
| `vrf.Delete(vpc, vpcAttachment string) error` | `internal/plumbing/vrf/vrf.go` | Tear it down; idempotent |
| `vrf.TableID(vpc, vpcAttachment string) (uint32, error)` | `internal/plumbing/vrf/vrf.go` | Resolve the kernel routing table ID for the route call below |
| `srv6.RouteEgressAdd(prefix *net.IPNet, gateway net.IP, tableID uint32) error` | `internal/plumbing/srv6/egress.go` | Install the seg6 ENCAP_RED route toward the tenant's SID — already handles the IPv4-vs-IPv6 next-hop Gw/Via distinction that previously caused a silent blackhole |
| `srv6.RouteEgressDel(prefix *net.IPNet, tableID uint32) error` | `internal/plumbing/srv6/egress.go` | Remove it |
| `intf.GenerateInterfaceNameVRF(vpc, vpcAttachment)` | `internal/plumbing/intf/intf.go` | Deterministic VRF device naming — same convention the sidecar and `galactic-cni` both key off |

Per #854's resolved annotation contract (below), the `(vpc, vpcAttachment)` values these functions take arrive on the `EndpointSlice` verbatim — no decoding or translation step. The reconcile loop is concretely: read `(vpc, vpcAttachment)` off the annotation → `vrf.Add` → `vrf.TableID` → `srv6.RouteEgressAdd(prefix, sid, tableID)`, and the mirror in reverse for teardown. This is the single biggest scope-reducer for this issue: it's a thin reconciler wired to existing plumbing, not new VRF/SRv6 management.

**To confirm before relying on this:** `RouteEgressAdd`'s doc comments assume the SID's route is resolved via `netlink.RouteGet` against the node's own default/main-table route — verified true for `galactic-cni` running in a pod netns; needs a quick check that it still holds running from the Envoy pod's netns/node.

## 3. Annotation/label contract (from #854 / galactic PR #309)

- Annotation `galactic.datum.net/srv6-sid` — the SID.
- Annotation `galactic.datum.net/tenant-id` — `TenantIdentifier(vpc, vpcAttachment)`.
- **Label** `galactic.datum.net/tenant-id` — the same value, mirrored as a label specifically so this sidecar can select on it (`List`/`Watch` can't filter by annotation). This is the sidecar's actual discovery mechanism: select by label presence, group by its value.
- One `EndpointSlice` per pod, `AddressType: IPv6` only. No IPv4-family slice to expect for these backends.
- `EndpointSlice`s land in each pod's **own namespace**, not one fixed namespace — the watch/cache must be cluster-scoped.

## 4. Decap side: already exists, not this issue's problem

`internal/plumbing/ebpf` (see its `doc.go`) documents a TC-BPF uSID datapath that already replaced the legacy `seg6local` ingress route model as of 2026-08-02 — this is the "eBPF decapsulation program" PR #851 lists as a dependency. It already does locator/function/VRF-table lookup and decap on the pod's node. Verify compatibility (does it handle traffic originated by an Envoy-node SRv6 encap route the same as EVPN-originated traffic?) but do not build a new decap path for this issue.

## 5. Proposed package layout (galactic repo)

- `cmd/galactic-vrf/main.go` — new binary, following the existing `cmd/galactic-cni`/`cmd/galactic-router` conventions (flag/env parsing, structured logging, `/healthz`).
- `internal/ingresssidecar/` (name TBD) — controller-runtime manager + reconciler:
  - Cluster-scoped watch on `discovery.k8s.io/v1` `EndpointSlice`, label-selected on `galactic.datum.net/tenant-id` (exists).
  - Reconcile key = the label's value; groups multiple `EndpointSlice`s (one per pod) sharing one tenant into a single desired-state entry.
  - Worth reading `internal/controller/bgpvrfinstance_controller.go` (`galactic-router`) first for its desired-state diffing pattern before writing a new one — it already keys off a VRF-scoped identity.
  - Calls `vrf.Add`/`vrf.Delete`/`srv6.RouteEgressAdd`/`RouteEgressDel` directly, in-process, same netns as Envoy.
  - Startup: inventory kernel state already tagged as this component's own (VRF devices named via `intf.GenerateInterfaceNameVRF`) before the first reconcile, so a restart doesn't treat live tenants as stale.
  - Teardown: delay VRF/route deletion by a configurable grace period after a tenant drops out of desired state, rather than deleting synchronously on the watch event (see Open Decisions).

## 6. Metrics, shutdown, deployment contract

- **Metrics:** Prometheus endpoint (reuse the pattern `galactic-router` already sets up) exposing active VRF/tenant count, reconcile error rate, reconcile latency, teardown-grace-period queue depth.
- **Graceful shutdown:** SIGTERM stops accepting new reconciles. Whether to proactively tear down VRF/route state on its own termination, or leave it for the next instance to reconcile from scratch, is an open call — leaning toward "leave it," since a live Envoy container next to a dying sidecar mid-rollout would otherwise blackhole in-flight connections.
- **Container:** minimal static-Go-binary image (distroless/scratch), matching `containers/galactic-cni/Dockerfile`'s pattern. This repo has no production image build today (see root `CLAUDE.md`), so image location/publishing needs a decision. `securityContext.capabilities.add: [NET_ADMIN]` only, no `privileged` — per PR #851's explicit privilege split (sidecar creates devices/routes, Envoy only binds to them). Resource requests in the same ballpark as the existing VPP telemetry sidecar cited in #855's original body.

## 7. Testing

- Unit tests for the reconciler's desired-state diffing (tenant appears / disappears / pod set changes but tenant id stays the same → no-op).
- Unit tests reusing the existing `internal/plumbing/vrf` / `internal/plumbing/srv6` test harness patterns.
- **Required pre-merge, not optional:** a real-kernel verification pass of `srv6.RouteEgressAdd` run from an Envoy Gateway pod's netns/node specifically — not just unit-test coverage carried over from `galactic-cni`'s pod-netns use case. `RouteEgressAdd`'s doc comments assume `netlink.RouteGet(gateway)` resolves against the node's own default/main-table route; that assumption is proven true for the CNI's context but unverified for this one. PR #851 calls this out explicitly as a live risk, citing that an equivalent untested assumption on the decap side already produced one silent production blackhole — treat this with the same seriousness, as a blocking check before this sidecar is trusted with real traffic, not as generic "validate against a real kernel" follow-up work.
- **Also required pre-merge:** end-to-end decap verification — send real traffic through this sidecar's `seg6` encap route and confirm the existing TC-BPF uSID datapath (`internal/plumbing/ebpf`) decodes and forwards it identically to EVPN-originated traffic. That datapath is existing, shared infrastructure this issue doesn't modify, but it's never been exercised with this sidecar as the traffic's origin — owned by this sidecar's implementer to verify (they're the one generating the test traffic), not assumed correct by construction just because `uformat`'s bit layout is shared between the two paths.
- Integration/e2e validation is #858's job (ContainerLab), but both checks above should happen standalone, before that lands — #858 exercising the path successfully once is not a substitute for this sidecar itself confirming both assumptions in isolation.

## 8. Dependency order

`#854` (CNI: `EndpointSlice` + annotations) — schema is settled (galactic PR #309), so this issue's reconciler/VRF/route logic can start immediately against a hand-authored `EndpointSlice` fixture; it doesn't need #854's code to land first, only its already-resolved schema. → `#856` (NSO: sidecar injection patch) needed to run this sidecar in a real Envoy pod. → `#858` (ContainerLab) for e2e proof.

## 9. Open engineering decisions / risks

1. ~~**Teardown race**~~ — **Decision (2026-08-08): time-based grace period.** No ordering guarantee exists between this sidecar's route deletion and the extension server's config-push for the same backend, and #854 confirmed `galactic-cni` does nothing to help narrow the window (immediate, unconditional `EndpointSlice` removal on DEL, no drain signal). For v1, delay VRF device/route teardown by a fixed interval after a tenant drops out of desired state, rather than tearing down synchronously on the watch event — simple to implement with the existing reconciler (a requeue-after on the "tenant absent" transition), and it bounds the blackhole window even without a proper handshake. The interval value itself isn't picked yet; needs to be long enough to cover the extension server's typical config-push latency plus in-flight connection drain, without holding stale kernel state indefinitely under normal churn.
   **Flagged for follow-up:** this is a stopgap, not a fix — it's a race disguised as a wait, not closed. A time-based delay can still blackhole a slow config-push under load, or hold VRF/route state longer than necessary under fast churn. A real fix (e.g. a signal-based handshake once a channel exists between this sidecar and the extension server, or a readiness/ack mechanism) should be investigated once both components exist and their actual latency characteristics are observable — track as an explicit follow-up, not something this plan resolves.
2. ~~**Startup reconcile safety**~~ — **Decision (2026-08-08): inventory-before-reconcile.** On startup, list existing kernel state tagged as this component's own (VRF devices matching the `intf.GenerateInterfaceNameVRF` naming convention) into a "known at boot" set before running any teardown logic, and block on the watch cache's first full sync (`WaitForCacheSync`) before treating anything absent from it as stale. A pre-existing device with no corresponding `EndpointSlice` yet is provisionally valid until the cache has actually finished its initial list, not immediately eligible for teardown — kept as a separate mechanism from the #1 grace-period timer rather than reusing it, since startup is a one-time, boot-scoped condition (bounded by cache sync completing) and not an ongoing per-tenant transition.
3. **Deployment injection contract with #856** — partially addressed: **recommend container name `galactic-vrf`**, matching the binary (`cmd/galactic-vrf`), so #856's strategic-merge patch has a concrete name to add/find by. This is a recommendation, not a locked contract — the team implementing #856 has latitude to rename it if the generated Envoy Deployment's shape forces a collision or a different convention. Everything else in the contract (image location/publishing, required env vars, the `CAP_NET_ADMIN`-only `securityContext` shape) is still uncoordinated and has no owner on the #856 side yet.
4. ~~**Health-checking VPC backends**~~ — **Decision (2026-08-08): punt as a separate future issue.** In scope per #855's original body (including a specific rationale for why Envoy's native health checks might not be enough — VRF/SRv6 reachability isn't something Envoy can observe from the overlay), but absent from PR #851's accepted design entirely, with no owner anywhere in #855/#856/#857. Explicitly out of scope for this sidecar and for the current #796 workstream as a whole — to be filed as its own follow-up issue once the rest of the mechanism is live and real failure modes are observable, rather than designed speculatively now.
5. ~~**Two kernel-level behaviors flagged unverified in PR #851**~~ — **Addressed for this sidecar's half: made a required pre-merge test step, see §7.** The socket-bind-option framing remains the extension server/#857 side's problem to verify, out of this plan's control. The seg6 encap route run from Envoy's netns specifically (this sidecar's side — `RouteEgressAdd` is proven for the CNI's pod-netns use case, unverified for this new caller context) is now called out in §7 Testing as a named, blocking pre-merge check rather than a general aspiration.
6. **Cross-namespace `HTTPProxy` reference** — **noted dependency, no action for #855.** Still unresolved in the design (placement constraint vs. a per-backend cross-namespace access-grant object, per PR #851, neither chosen), and owned entirely by #856/#857 — but it doesn't affect this sidecar's own implementation: the watch is already cluster-wide by label (§3), independent of where the referencing `HTTPProxy` rule lives. Tracked here for visibility only; whichever way #856/#857 resolves it, this plan doesn't change.
7. ~~**eBPF decap compatibility**~~ — **Addressed: made a required pre-merge test step, see §7.** Whether the existing uSID TC-BPF datapath handles sidecar-originated traffic identically to EVPN-originated traffic was flagged as uncertain in both PR #851 and #854; §7 Testing now names an explicit end-to-end decap verification pass, owned by this sidecar's implementer, as a blocking pre-merge check rather than an assumed-correct-by-construction property.

## Non-goals for this issue (per PR #851)

- Any xDS/EDS pushing — not this component.
- Backend health checking — explicitly punted to a future issue (see Open Decisions #4), not this sidecar.
- The extension server itself, the deployment patch mechanism, and TLS/routing config — #856/#857.
- eBPF decap changes — already exists, out of scope.
