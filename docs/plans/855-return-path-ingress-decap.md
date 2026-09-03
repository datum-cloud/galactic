# Implementation plan — #855 follow-up: return-path ingress decap on the gateway node

- **Parent:** [datum-cloud/enhancements#796](https://github.com/datum-cloud/enhancements/issues/796) — HTTP Ingress for VPC Networks
- **Sibling plans** (read both first):
  - [docs/plans/855-ingress-sidecar-vpc-backend-connectivity.md](855-ingress-sidecar-vpc-backend-connectivity.md) — the accepted #855 design; §4 explicitly punts on the decap side ("already exists, not this issue's problem... verify compatibility... do not build a new decap path for this issue"). This plan is that unverified assumption, found false, and its fix.
  - [docs/plans/855-return-path-gateway-advertisement.md](855-return-path-gateway-advertisement.md) — fixes the *sending* side of the return path. This plan picks up where that one stops: what happens once a correctly-encapsulated reply arrives at the node hosting the Envoy Gateway pod.
- **Status:** proposed, design review complete. No code written for Pieces 1–3 yet. One related defect found during the review (`vrfTableID`'s dead `vrf_table` fallback) is already fixed in the working tree — see [Related fixes](#related-fixes).

---

## 1. Decision log

The review that produced this revision settled the following. They are recorded here because several of them close questions that look open in the sibling plans, and because two of them reverse earlier decisions.

| # | Decision | Consequence |
| - | -------- | ----------- |
| D-1 | **The netns crossing is irreducible.** Neither a different SID Function, nor delivery to the Envoy pod's own cluster IP, nor stateless address translation avoids it. | Root-netns state on the gateway node is mandatory. The only real question was who creates it. See [§4](#4-closed-questions). |
| D-2 | **A root-netns component owns the root-netns half** — `galactic-router`, not the sidecar reaching out via `setns`. | Envoy's pod spec does not change. `hostPID` stays off the Envoy pod. Reverses this plan's earlier "all three pieces extend `internal/ingresssidecar`" shape. |
| D-3 | **Stateful NAT remains excluded; stateless translation was evaluated and rejected on the merits**, not on the Non-Goal. | #796's "NAT or SNAT configuration for return traffic" Non-Goal stands as written. See [§4.3](#43-stateless-address-translation). |
| D-4 | **One gateway pod per node — structurally, not by convention**, on the `edge` overlay: `infra/apps/network-services-operator/downstream/edge/patches/downstream-gateway.yaml:9` provisions Envoy via `envoyDaemonSet`. | Closes this plan's former Open Question 4 and the latent per-`(vpc, node)` gateway-address collision, which `DeriveGatewayAddress`'s per-`(vpc, nodeID)` keying depends on. **Not** guaranteed on the `base`/`staging` overlays, which use `envoyDeployment` (`.../downstream/base/downstream-gateway.yaml:72`, `.../staging/patches/downstream-gateway.yaml:19`) — see [§7.5](#75-deployment-shape-and-where-the-sidecar-actually-runs). |
| D-5 | **Co-location with tenant attachments is expected, not excluded.** The Envoy DaemonSet's own node affinity admits `node=compute` nodes, so a gateway pod routinely shares a node with tenant pods. | Reverses an earlier revision of this decision, which assumed the opposite. D-6 is therefore load-bearing rather than tidy — it is the only thing keeping `vrf_table`'s key uncontended — and §7.4's Argument/`vrf_table` ceilings are live, not hypothetical. |
| D-6 | **The return path gets its own `BGPVRFInstance` and Argument**, rather than sharing the tenant's `(vpc, node)` instance. | Makes `vrf_table`'s key uncontended. Reverses the sibling plan's deliberate share-the-instance decision — see [§6.3](#63-piece-3--the-root-netns-half-of-the-vrf). |
| D-7 | **No root-netns VRF *device*** — a bare reserved routing table instead. | Keeps `galactic-router`, `internal/gc`, and `vrf.Add`'s host VRF-ID allocator entirely out of this. See [§5.2](#52-b3--a-root-netns-vrf-device-silently-rewires-galactic-router). |
| D-8 | **`locator_table`/`function_table` seeding moves to `galactic-router`**, not the sidecar. | Matches the owner `usidmap`'s own package doc already names, and fixes the same hole on compute nodes after a map wipe. |

---

## 2. The framing: the VRF is split across two namespaces

It is tempting to describe this work as *extending a VPC's VRF onto the nodes that host Envoy*. That is accurate at the BGP layer — such a node genuinely becomes another PE for that VPC's Route Target, importing and exporting the same RT over the same EVPN mesh — and it is what makes the sibling plan's `BGPAdvertisement` obviously necessary rather than a bolt-on.

**A terminology warning, because this repo overloads the word.** "Gateway node" below means *a node hosting an Envoy Gateway pod*. It does **not** mean `galactic.datumapis.com/node=edge`, which is `galactic-gateway`'s XDP NAT+LB ingress boundary — a different component on a possibly disjoint node set (see [docs/node-labels.md](../node-labels.md) on that exact collision). Per D-5 a gateway node is frequently an ordinary `node=compute` node.

It is misleading at the datapath layer, and every gap below lives in the gap between the two readings. On a gateway node the VPC's VRF is not extended, it is **split across two network namespaces, joined by a veth**:

| | Tenant pod on any node | Envoy pod on a gateway node |
| ------------------------ | --------------------------------------------- | ------------------------------------------------------ |
| Where the VRF device is | host root netns, created by `galactic-cni` | Envoy's pod netns, created by the sidecar |
| Visible to `galactic-router`/`internal/gc`? | yes | **no** |
| The attachment's address | tenant IPAM, inside the VPC subnet | reserved `GATEWAY-BLOCK` pool, disjoint from tenant space |
| Which VPCs are present | those with pods scheduled here (a subset) | every VPC on the platform with a pod (see [§7.4](#74-ceilings)) |
| Who builds the veth | `galactic-cni`, root netns, netns handle from kubelet | nothing today — this plan |

Both halves are mandatory and neither is optional:

- The **pod-netns half must exist**, because #856 binds Envoy's upstream socket with `SO_BINDTODEVICE` to the VRF device name (`network-services-operator/internal/extensionserver/mutate/vpcpod.go:137` emits `G%09sV`, byte-identical to `intf.GenerateInterfaceNameVRF`'s `"G%09s%s"` + `"V"`). A socket can only name an ifindex in its own netns, and only a VRF device redirects a route lookup into a per-VPC table at all — `SO_BINDTODEVICE` sets the output interface, not the table.
- The **root-netns half must exist**, because that is where the fabric terminates and where `usid_ingress` is attached.

So the veth between them is not an implementation detail, it is the seam. Pieces 2 and 3 below are best read not as "add a second veth and two map writes" but as **building the root-netns half of a VRF that currently only has a pod-netns half** — for which a reference implementation already exists: `internal/hostgw.ConfigureHostGateway` does exactly this for a tenant pod.

---

## 2a. Phase 0 result: a blocker upstream of all three gaps

**A live proof run on `us-central-1-staging-lab` (2026-09-02) found that
inter-node SRv6 decap cannot work on that cluster at all, for reasons upstream
of Gaps 1–3.** Pieces 1–3 remain necessary and their key derivations are
confirmed correct, but implementing them changes nothing until this is settled.
Full record and reproduction steps: [hack/returnpath-lab/README.md](../../hack/returnpath-lab/README.md).

Two compounding causes:

1. **`usid_ingress` is not attached to the interface carrying the traffic.**
   `attach.ResolveInterfaces` skips WireGuard links
   (`internal/plumbing/ebpf/attach/interfaces.go:166`) — a deliberate guard so
   `srv6.ResolveNodeSourceAddress` cannot bake a mesh ULA in as the node's
   source address. But these are Talos nodes with KubeSpan, and `kubespan` is
   what actually carries every inter-node IPv6 packet, iBGP sessions included.
   Attached sets were `[lo bond0 eno2 enp3s0f1]` (gateway node) and
   `[lo bond0 ens2f1np1 ens1f1np1]` (backend node) — neither includes it.
   Capture confirmed the return packet arriving correctly formed on `kubespan`
   while `eno2`/`enp3s0f1`/`bond0`, filtered to the same destination, saw
   nothing.
2. **Attaching it there is not sufficient.** With the program attached to
   `kubespan` through the production `attach.Attach` path and every map entry
   verified, `vrf_table` `pkts` stayed 0. `kubespan` is `link-type RAW (Raw
   IP)` — no Ethernet header — and step 1 unconditionally parses
   `struct usid_ethhdr` and tests `h_proto == ETH_P_IPV6`, so on an L3
   interface it reads the inner IPv6 header's own bytes as an ethertype,
   mismatches, and exits `TC_ACT_UNSPEC` on the one deliberately uncounted
   path.

The datapath therefore assumes an Ethernet-framed fabric. The same applies to
the forward direction: the backend node's `vrf_table` hits come from the Envoy
pod *on that same node*, whose encapsulated traffic loops back via `lo`, which
*is* attached. Cross-node #855 ingress has never worked on this cluster in
either direction.

**This has to be resolved before Pieces 1–3 are worth building**, and the
choice belongs with whoever owns the underlay:

- carry the SRv6 fabric over an Ethernet-framed underlay on these nodes rather
  than over KubeSpan, or
- teach `usid_ingress`/`usid_egress` to handle L3/RAW interfaces — detect the
  absence of a MAC header instead of assuming `ETH_HLEN`, and give step 9 a
  redirect path not dependent on resolved L2 addressing.

Either is materially larger than Pieces 1–3. Note also that assumption 2 in
[§9](#9-pre-merge-verification) is still untested, because no packet ever
reached step 6.

Three further live findings, none of which are this plan's scope but all of
which are real today, are recorded in the harness README: a ~40% forward-path
loss on tap-backed (unikernel) workloads from `hostgw` skipping the permanent
neighbor entry for taps; `locator_table` seeding being unsafe on a node also
running `galactic-gateway`; and the fabric carrying only `/128` routes for
advertised SIDs, with the containing `/48` a `Null0` static.

---

## 3. What's broken

With the sibling plan's fixes deployed, a full end-to-end curl through `envoy-datum-downstream-gateway` into a VPC-hosted backend still fails (`upstream_reset_before_response_started{connection_timeout}`). Packet capture confirmed the backend node now correctly re-encapsulates its reply toward the gateway node's own SID — the previous gap is closed — but the encapsulated packet's fate on arrival was never verified. Three independent gaps in `usid_ingress` (`internal/plumbing/ebpf/prog/usid.c`) each independently prevent delivery.

`usid_ingress` is attached once per node on the bond slave interfaces and processes every SRv6-addressed packet arriving on the wire. Its relevant steps, with the line numbers of each lookup:

| Step | What it does | Line |
| ---- | ------------------------------------------------------------------------ | ---------- |
| 2 | exact-match outer destination's top 64 bits (Block+NodeID) vs `locator_table`; miss → `TC_ACT_UNSPEC` | `usid.c:1098` |
| 3–4 | exact-match (Block, Function nibble) vs `function_table` | `usid.c:1117` |
| 5–6 | exact-match (Block, 12-bit Argument) vs `vrf_table` → `vrf_table_id`, `egress_kind` | `usid.c:1145` |
| 7 | strip the outer header | `usid.c:1257` |
| 8 | `bpf_fib_lookup()` with `BPF_FIB_LOOKUP_DIRECT \| BPF_FIB_LOOKUP_TBID`, `tbid = vrf_table_id` | `usid.c:1399` |
| 9 | `bpf_redirect_peer()` for `EGRESS_KIND_VETH`, `bpf_redirect()` for `EGRESS_KIND_TAP` | `usid.c:1443` |

Steps 8 and 9 always execute **in the netns `usid_ingress` itself runs in — the host root netns**, since that is where the bond slaves live.

The return packet's outer destination is `uSID(gatewayNodeBlock, gatewayNodeID, 0xE, vrfID)`. That is not an assumption: `internal/reconcile.resolveSRv6SID` (`reconcile.go:373`) computes the SID from the *advertising* router's `Spec.SRv6Locator` and `Spec.NodeID` plus the advertisement's own `VRFID`/`Function`, and the sidecar's `PublishGateway` sets `Function = SRv6FunctionEndDT46`. So all three of the above lookups are keyed off the gateway node's own real locator.

### Gap 1 — `locator_table`/`function_table` are empty on the gateway node

```
$ bpftool map dump pinned /sys/fs/bpf/galactic/locator_table   # on the gateway node
[]
$ bpftool map dump pinned /sys/fs/bpf/galactic/function_table
[]
```

`usid_ingress` *is* loaded and attached there — `internal/installer/installer.go:207` calls `attach.StartWatching`, and `galactic-cni`'s DaemonSet keys off `galactic.datumapis.com/galactic: router`, which gateway nodes carry. The maps are pinned. But the only writers of these two are `internal/cnibgp/bgp.go:651,654`, inside `registerEBPFDatapath`, reachable only from a real CNI ADD. A gateway node with no tenant attachment of its own never runs it, so step 2 never matches *any* packet and the program falls through for all of them.

### Gap 2 — `vrf_table` has no entry the real lookup could find

`internal/ingresssidecar/ebpfdatapath.go:368` does write a `vrf_table` entry, but under `ingressSidecarBlock = uformat.BlockMax` with `argument = vrf.TableID(vpc)` — a synthetic key by explicit design, existing purely for `usid_egress`'s opposite-direction lookup via `ifindex_vrf_table`. Step 5–6 keys off the Block genuinely present in the packet's destination — the node's real, `BGPRouter`-derived locator Block. No entry keyed that way exists, so even with Gap 1 fixed the lookup misses.

### Gap 3 — nothing to redirect into

`EGRESS_KIND_VETH`'s `bpf_redirect_peer()` needs step 8's FIB lookup to resolve to a veth's **root-netns-side** ifindex; the helper then delivers across to that veth's peer wherever it lives. That is how a tenant attachment works — `galactic-cni` creates the pair with the host end in root netns.

`ensureEgressVeth` (`ebpfdatapath.go:136`) creates its pair with **both ends inside Envoy's pod netns**, deliberately, so the pod's own `SO_BINDTODEVICE` resolves. There is no root-netns-visible interface belonging to this VPC on this node for step 8 to resolve to. Fixing Gaps 1–2 is necessary but not sufficient.

---

## 4. Closed questions

These were evaluated during review and are closed. They are recorded so they are not re-opened.

### 4.1 A different SID Function

`End.DT46`'s entire semantic is "look the inner packet up in a VRF table," which is what forces the `vrf_table` → table-ID → FIB chain. But a hypothetical "decap and deliver locally" Function would still have to deliver into another netns, and `vrf_table` is keyed `(block, argument)` with neither Node-ID nor Function in the key (`usid.c:713`), so two SIDs differing only in Function collide there anyway. No help.

### 4.2 Delivering to the Envoy pod's own cluster IP

The one thing that already carries arbitrary traffic from the gateway node's root netns into the Envoy pod is Cilium's own veth for that pod's cluster IP. Using it would require the Envoy pod's cluster IP to be routable from an arbitrary backend node across the fabric — false in the multi-PoP topology (`deploy/containerlab` models three separate clusters). Worse, it would appear to work within one cluster and fail across PoPs.

### 4.3 Stateless address translation

This repo already ships two per-VRF translation mechanisms on this exact datapath, and #796's Non-Goal excludes *stateful* NAT specifically, so both were evaluated:

- `apply_nptv6` (`usid.c:918`) — RFC 6296 checksum-neutral prefix translation, applied by `usid_ingress` after decap and by `usid_egress` in reverse. It rewrites **the tenant's own address**, between a ULA prefix and a public prefix.
- `apply_vip_xlat` (`usid.c:969`) — genuine addr+port substitution keyed `(block, argument, proto, port, direction)`. Also the tenant's own service endpoint, at a VIP boundary.

Neither translates a *remote peer's* address, so neither provides a way to make the gateway address reachable from inside a tenant VRF. Building one would be new datapath work, and it would not avoid D-1 regardless.

### 4.4 The sidecar reaching out into root netns

Rejected in favour of D-2. `/proc/1/ns/net` inside the pod is the *pod's* netns; it only becomes the host's with `hostPID: true`, which is **pod-scoped** and therefore lands on Envoy too — directly contradicting PR #851's stated privilege split ("the sidecar holds the capability to create and tear down network devices and routes; Envoy itself only ever needs the capability to bind a socket to a device that already exists"). The hostPath-of-nsfs variant is containable (volumes are pod-level, `volumeMounts` per-container) but requires a change to NSO's strategic-merge patch — a second repo, and the mechanism PR #851 itself flags as fragile — and hands the Envoy pod a handle on the host network namespace.

Note also that the sidecar is not deployed from this repo at all, and what is currently committed on the NSO side is a placeholder: `network-services-operator/config/dev/downstream_resources/downstream-gateway.yaml:75` injects `name: vpc-vrf-sidecar, image: busybox:1.36, command: ["sleep", "infinity"]`. Any claim about the sidecar's mounts or capabilities is a cross-repo assumption of exactly the kind that produced Gaps 1–3.

---

## 5. Defects in the previous revision of this plan

Recorded because each is a thing the earlier design would have got wrong, and the fix for each is now folded into §6.

### 5.1 B1 — no neighbor entry means a guaranteed drop

`internal/hostgw/hostgw.go:121-133` states the rule outright:

> `bpf_fib_lookup()` does not itself trigger ARP/NDP resolution the way ordinary kernel packet forwarding does, so without a pre-existing neighbor table entry it fails with `BPF_FIB_LKUP_RET_NO_NEIGH` and the datapath drops the packet.

The working tenant path therefore installs **three** things per delivery target — the gateway address on the host-side interface, a host route into the table, and a `NUD_PERMANENT` neigh entry keyed on the guest veth's known MAC. The previous revision proposed only the route. Fixed by reusing `hostgw` rather than re-deriving it (§6.3).

### 5.2 B3 — a root-netns VRF device silently rewires `galactic-router`

The previous revision proposed creating a root-netns VRF via `vrf.Add(vpc)`, which names it `intf.GenerateInterfaceNameVRF(vpc)`. Three separate components key off exactly that name in root netns:

| Component | Effect of the new VRF appearing |
| ----------------------------------------------- | --------------------------------------------------------------------------------------------- |
| `internal/gc`'s `resolveVRFKernelState` (`gc.go:756`) | starts matching → GC's repair loop begins writing `(realBlock, VRFID)` into `vrf_table` itself, with its own table ID and an `egress_kind` inferred from whatever link is enslaved (`gc.go:747-795`) |
| `internal/runtime/gobgp`'s `vrfTableID` | `vrfpkg.TableID(vpc)` starts succeeding → the router installs that VPC's whole imported EVPN route set into the table intended to hold one `/128` |
| `internal/gc`'s `CollectOrphanedVRFs`/`RemoveOrphanedVRFs` (`gc.go:400,453`) | becomes the de-facto owner of its lifecycle, deleting it via `vrf.Delete` → `FlushTable` |

Resolved by D-7. Step 8 passes `BPF_FIB_LOOKUP_TBID` with `fib_params.tbid` (`usid.c:1393-1400`) — a bare table-ID lookup. A VRF master device buys nothing on the root-netns side: nothing binds a socket to it and nothing needs ingress l3mdev redirection there.

### 5.3 B4 — the flock dependency the sibling plan dismissed

The sibling plan's §2 argued `/var/lib/cni/galactic-vrf`'s cross-process flock "doesn't apply here" because the sidecar is one long-running process. Allocating a *host* VRF ID would have reintroduced it — racing real CNI plugin processes for the same space — and that flock's writability from the sidecar's container is still one of the sibling plan's undone §7 pre-merge checks. D-7 removes the dependency instead of satisfying it.

### 5.4 B2 — `vrf_table`'s key had three writers

`vrf_table` is a node-global BPF hash keyed `block<<12 | argument`. The previous revision's Piece 3 wrote `(realBlock, vrfID)`, which is the same key two other components write, because `PublishGateway` deliberately reuses the tenant's instance:

```go
// gateway.go:240 — "Same (vpc, node)-keyed BGPVRFInstance a real CNI
// attachment on this node would use ... rather than creating a competing entry"
vrfName := crdnames.BGPVRFInstanceName(vpc, p.nodeName)
```

`argument` in the eBPF key *is* that `Spec.VRFID`, so the gateway and any tenant attachment of the same VPC on the same node shared one key by construction:

| Writer | Value it wants |
| ------------------------------------- | -------------------------------------------------------------- |
| `cnibgp/bgp.go:658` (CNI ADD) | tenant pod's root-netns VRF table, redirect → pod's host veth |
| `gc/gc.go:689` (repair loop) | whatever `resolveVRFKernelState` reads off a root-netns VRF link |
| previous Piece 3 | gateway's table, redirect → gateway's veth |

One key cannot express two of those at once; last writer wins and the loser is misdelivered, including tenant traffic being redirected toward the Envoy pod. Today it is inert only because `resolveVRFKernelState` cannot see a pod-netns VRF and returns `ok=false`.

The previous revision's Open Question 2 framed this as a *Linux VRF table ID* allocation collision. Those do not collide — `findNextAvailableVRFID` handles it. What collided is the eBPF map key, derived from the CRD's `VRFID`. Two different things both called "VRF ID."

Resolved by D-6 (§6.3).

---

## 6. Design

### 6.1 Piece 1 — seed `locator_table`/`function_table` from `galactic-router`

Both maps are keyed by node facts alone — `(block, nodeID)` and `(block, function)` — derived entirely from this node's own `BGPRouter`. They have no per-VPC component. `usidmap`'s own package doc already names the intended owner:

> Milestone 3.1's control daemon (`internal/plumbing/ebpf/attach`) is expected to call `LocatorTable.Register`/`FunctionTable.Register` at startup (and on `BGPRouter.Spec.SRv6Locator` change) to seed `locator_table`/`function_table` for this node's active uSID Block(s) — that wiring is not part of this milestone's scope either.

Implement it in `galactic-router`'s `BGPRouter` reconcile path: it already watches that CRD, already holds `Spec.SRv6Locator` and `Spec.NodeID`, already runs in root netns with a pinned-map handle, and already runs on every node including edge ones (`galactic=router` covers both `compute` and `edge`). Derive `block` via `uformat.Block(netip.MustParsePrefix(locator).Addr())` — the same derivation `cnibgp/bgp.go:606-611` uses — then `Locator.Register(block, uint16(nodeID))` and `Function.Register(block, uformat.FunctionEndDT46)`. Both are idempotent map writes; redundant against `cnibgp`'s own registration on a node that has both, which is harmless (identical values) and is the precedent every additional CNI ADD already relies on.

Putting this in the sidecar instead — the previous revision's proposal — would make a node-scoped fact contingent on a per-VPC reconcile inside a pod that may not exist, and would leave the same hole unrepaired on compute nodes after an `attach.Load` map wipe (the hole `gc.go`'s repair loop exists to plug for `vrf_table` and cannot plug for these two).

No GC interaction: the sweep's scope is `vrf_table` only, and `LocatorTable`/`FunctionTable` deliberately expose no `Reconcile` (`usidmap/doc.go`).

### 6.2 Piece 2 — the veth seam

One veth per `(VPC, gateway node)`, created by `galactic-router`: **host end in root netns, pod end enslaved into the pod-netns VPC VRF.** Structurally identical to a tenant pod's attachment.

Per-VPC, and enslaved, are both forced rather than chosen — see [§7.1](#71-why-the-pod-side-end-must-be-enslaved-per-vpc).

**Two shapes, and a sequencing risk worth naming explicitly.**

*Target shape (recommended).* This veth **replaces** `ensureEgressVeth`'s pod-internal pair and carries both directions:

- Forward: Envoy (bound to the VRF) → route in the VRF table → pod end → host end in root netns → `usid_egress` on the host end's *ingress* hook → SRv6 encap → fabric.
- Return: fabric → bond slave → `usid_ingress` → decap → FIB in the reserved table → `bpf_redirect_peer(host end)` → pod end → socket.

This is exactly `cnibgp`'s own pattern (`attachUsidEgress` on the host-side veth), and it deletes the workaround `ensureEgressVeth` exists for — that "a Linux VRF master device's own TC egress hook never actually fires for traffic routed through it," which is why the sidecar had to invent a pod-internal pair to attach to at all (`ebpfdatapath.go:274-288`). It also moves every eBPF map write into root netns, so the sidecar would no longer need `CAP_BPF` or the bpffs mount for the egress path.

*Conservative shape.* Keep `ensureEgressVeth`'s pair for the forward path and add this veth as return-only. The forward path then egresses `ivsN` while replies arrive on the new veth — asymmetric paths through two interfaces enslaved to the same VRF. That works (the socket is bound to the VRF master, and both links are enslaved to it) but it is unusual enough that someone will later "fix" it, so it needs a comment if chosen.

**The risk:** the target shape modifies a forward path that currently works in the lab. The conservative shape does not. Recommendation is to implement the conservative shape first, prove the return path in isolation, then collapse to the target shape as a separate change — not to do both at once, which is the mistake that produced the compounding gaps this plan exists to fix.

**Sequencing.** The VRF device is created by the sidecar in the pod netns; the veth is created by the router in root netns; the pod end has to be enslaved into that VRF. So there is a handshake either way, and its shape is the main remaining open question — see [§10](#10-open-questions).

The host end needs a deterministic name so it is recoverable after either process restarts, mirroring `intf.GenerateInterfaceNameHost`'s convention.

### 6.3 Piece 3 — the root-netns half of the VRF

Three pieces of root-netns state, all created by `galactic-router` alongside Piece 2's veth, and all of which `internal/hostgw.ConfigureHostGateway` already implements for a tenant pod. Reuse it rather than re-deriving it; the role mapping is:

| `hostgw` parameter | Value here |
| ------------------------- | ---------------------------------------------------------- |
| host-side interface | Piece 2's root-netns veth end |
| the attachment's address | the gateway address (`DeriveGatewayAddress`) |
| `guestHWAddr` | Piece 2's pod-side veth end's MAC (known to the router, which created the pair before moving one end) |
| VRF table ID | the reserved root-netns table below, **not** `vrf.TableID(vpc)` |

That yields the gateway address on the host end, a `/128` route for it into the reserved table, and the `NUD_PERMANENT` neigh entry §5.1 requires.

**The reserved table.** A bare Linux routing table ID, not a VRF device (D-7). It must come from a range that cannot collide with `vrf.Add`'s allocator (`minVRFID = 1` upward, `vrf.go:24`) — pick a high, documented base. Because it is not a VRF device it is invisible to `vrf.ListVRFLinks`, `vrfpkg.TableID`, `resolveVRFKernelState`, and `CollectOrphanedVRFs`, which is the entire point.

**The `vrf_table` entry.** `VRF.Register(realBlock, gwArgument, reservedTableID, usidmap.EgressKindVeth)`, where `gwArgument` comes from **the gateway's own `BGPVRFInstance`** (D-6), not the tenant's. Under a gateway-specific instance name, `resolveVRFKernelState` cannot match it either — it only matches `<vpcKey>-<nodeName>` against root-netns VRF link names — so GC's repair loop stays neutralised, and `cnibgp` can never land on the same key. The advertised SID then encodes `gwArgument`, which is also more honest: it means "deliver to the gateway," not "deliver to the tenant VRF."

`EgressKindVeth` here is a real claim, not a don't-care. `ebpfdatapath.go:361-367`'s comment — *"a don't-care here ... `usid_ingress` is never attached anywhere in this pod's netns — this sidecar has no ingress/decap side at all"* — becomes false with this plan and must be updated.

---

## 7. Constraints that pin the design

### 7.1 Why the pod-side end must be enslaved, per VPC

#856's mutation binds Envoy's upstream socket to the VRF master via `SO_BINDTODEVICE`. A socket with `sk_bound_dev_if` set matches an incoming packet only when that ifindex appears as the packet's `dif` or `sdif`; a reply arriving on a *non*-VRF interface will never find the socket. `net.ipv4.tcp_l3mdev_accept` cannot rescue that case — its early-return fires only for *unbound* sockets — and nothing in this repo sets it anyway (`internal/plumbing/sysctl/sysctl.go:20-27` sets only `rp_filter`, `forwarding`, `proxy_arp`, `proxy_ndp`).

So the tempting one-veth-per-pod simplification is closed off: the pod end must be enslaved into the VRF, which makes the veth per-VPC. **This is derived from kernel behaviour, not measured — it needs one live confirmation** (see §9).

It also means the return path depends on #856's mutation continuing to apply. PR #851 flags upstream drift in Envoy Gateway's generated Deployment as a live risk; if that mutation silently stops applying, this return path breaks in a way that looks like a decap bug. State the dependency and check it (§9).

### 7.2 Overlapping VPC address space

None of Pieces 1–3 route on a tenant's own inner address: Piece 1 is keyed by node identity, and Piece 3's `vrf_table` entry is selected by the outer header's Argument before the inner packet's address is read. Two VPCs with identical backend CIDRs land in different tables regardless. Gateway addresses are drawn from a reserved, tenant-disjoint prefix and hashed per `(vpc, nodeID)`, so they cannot collide across VPCs either — and per D-4 there is at most one gateway pod per node under the DaemonSet shape, which is what makes that per-`(vpc, node)` keying sufficient — see [§7.5](#75-deployment-shape-and-where-the-sidecar-actually-runs) for where that does not hold.

### 7.3 A pre-existing forward-path hazard, now reclassifiable

`ensureRedirectRoute` (`ebpfdatapath.go:473`) installs each backend pod's `/128` into `unix.RT_TABLE_MAIN` — one table shared by every VPC the gateway pod serves. Two VPCs whose backend pods land on the identical address would have the second silently overwrite the first via `RouteReplace`.

The review changes how this should be read. Since #856's `SO_BINDTODEVICE` mutation **is** implemented and verified to name the right device, the VRF-scoped forward path genuinely exists, and this main-table route is a redundant *second* path that can only cause the cross-VPC misroute, never prevent one. That makes it a candidate for **deletion** rather than a follow-up fix — unless it is load-bearing in deployments where the extension server isn't running, which needs confirming before removal. Out of scope here either way; worth its own change.

### 7.4 Ceilings

Both Argument allocators are scoped per node — `cnibgp/bgp.go:204` and `gateway.go:206` both filter on `inst.Spec.RouterRef.Name != routerName` — so the 12-bit Argument space (`uformat.go:88-89`, `0x001`–`0xFFF`, `0x000` reserved) is consumed per node, not globally. Under D-5 the gateway's extra Argument **does** coexist with a tenant's on any node hosting both, so budget two Arguments per VPC on those nodes.

The number that does scale is different, and it is pre-existing. `publishEndpointSlice` fires on **every** CNI ADD with an IPv6 allocation (`ops_add.go:96`) — it is not gated on the pod being an ingress backend — and the sidecar's watch is cluster-wide by label. So a gateway node's sidecar materializes a VRF, and needs an Argument, for every VPC on the platform with at least one pod, not just those fronted by an `HTTPProxy`. Three ceilings follow:

| Ceiling | Value | Source |
| ------------------------------- | ----- | ---------------------- |
| uSID Argument per node | 4095 | `uformat.go:89` |
| Linux VRF table ID in the pod netns | 4095 | `argumentForTableID`, `ebpfdatapath.go:83` |
| `vrf_table` entries per node | 8192 | `usid.c:742` |

`vrf_table`'s own sizing comment says 8192 is "~2 uSID Blocks' worth of Argument space today." At 4095 VPCs with two entries each that is exactly at the wall — and per D-5 two entries per VPC is the co-located case, which is the normal one. So `vrf_table`'s sizing needs revisiting as part of this work, not after it. This is the sibling plan's Open Decision 9 confirmed in code; its active-VRF-count and active-route-count metrics are the instrument.

### 7.5 Deployment shape and where the sidecar actually runs

Envoy is provisioned through `EnvoyProxy.spec.provider.kubernetes`, and the overlays differ on which workload field they use:

| Overlay | Field | One pod per node? |
| ----------------------------------------------------------------- | ----------------- | ---------------------------- |
| `infra/.../downstream/edge/patches/downstream-gateway.yaml:9` | `envoyDaemonSet` | yes, structurally |
| `infra/.../downstream/base/downstream-gateway.yaml:72` | `envoyDeployment` | no — replicas, no anti-affinity |
| `infra/.../downstream/staging/patches/downstream-gateway.yaml:19` | `envoyDeployment` | no |

**The sidecar is deployed, correctly, in exactly one overlay: `edge-staging`.** `infra/.../downstream/edge-staging/patches/vpc-vrf-sidecar.yaml` JSON-patches it into `envoyDaemonSet` (line 29) with the real image (`ghcr.io/datum-cloud/galactic-vrf:v0.0.0-main`, line 43), `NET_ADMIN` + `BPF` (lines 84-85), the bpffs hostPath at `/sys/fs/bpf` (line 101), and — closing one of the sibling plan's undone §7 pre-merge checks — a writable mount at `/var/lib/cni/galactic-vrf` (line 96) for `internal/plumbing/vrf`'s flock. Both feature gates are set: `NODE_NAME` (line 68) and `GALACTIC_VRF_GATEWAY_PREFIX = fd30:e2e::/32` (line 73), so the gateway publisher *and* address provisioning are live there.

Two consequences:

1. **`edge-staging` is the environment to prove this in**, and it is ready — DaemonSet shape (so D-4 holds), real sidecar, both gates on, flock and bpffs mounted. Nothing about the deployment blocks bring-up; the return-path datapath is the only missing piece.
2. **Productionization is a separate, later gap.** The production `edge` overlay has no `vpc-vrf-sidecar` patch at all, and `base`/`staging` use `envoyDeployment`, where D-4 does not hold: nothing stops two replicas per node, and `DeriveGatewayAddress`'s per-`(vpc, nodeID)` keying would then yield the same `/128` in two netns with one `vrf_table` entry between them. Either the DaemonSet shape becomes the contract for any environment running this feature, or the gateway address must be keyed per-pod — which also means a per-pod Argument, since one `vrf_table` key cannot serve two pods.

---

## 8. Teardown

The previous revision left this as an open question. It needs writing explicitly, not piggybacking on the pod-netns veth's removal, and it now spans two components:

| Resource | Owner | Trigger |
| ------------------------------------- | ------------------ | ------------------------------------------------ |
| gateway `BGPAdvertisement` | sidecar (`WithdrawGateway`) | VRF teardown, best-effort, already implemented |
| gateway `BGPVRFInstance` (D-6) | `galactic-router` GC | orphan sweep, same as every other CRD this repo leaves for GC |
| Piece 2 veth (both ends) | `galactic-router` | gateway `BGPVRFInstance` gone |
| gateway address, `/128` route, neigh entry | `galactic-router` | with the veth (deleting the link removes all three) |
| Piece 3 `vrf_table` entry | `galactic-router` | explicit `Unregister` before the veth goes |

Follow the best-effort, `errors.Join`-all shape `removeEgressDatapath` already uses: attempt every step even if an earlier one failed. Order matters in one place — unregister the `vrf_table` entry *before* deleting the veth, so a decapped packet can never be redirected at a freed ifindex.

---

## 9. Pre-merge verification

The sibling plan's three required-but-undone checks still stand. This plan adds four, each of which is a place where the design rests on derived rather than observed behaviour:

1. **`BPF_FIB_LOOKUP_TBID` against a table with no VRF device.** D-7's entire premise. One route in a bare table plus one `bpf_fib_lookup` is enough to confirm.
2. **`bpf_redirect_peer` into a VRF-enslaved pod-side end**, and that the socket actually receives it. This is §7.1's derivation; it is the single highest-risk assumption in the plan.
3. **#856's `SO_BINDTODEVICE` mutation is actually applied** to the cluster in question — `nso_extension_vpcpod_socket_bind_total` (`extensionserver/metrics/metrics.go:183`) should be non-zero. Without it, §7.1's whole argument inverts.
4. **The neigh entry is present and `NUD_PERMANENT`** after setup, and `DROP_REASON_FIB_NO_NEIGH` stays at zero under load.

`drop_reasons` is the instrument for 1, 2 and 4: each has its own counter (`FIB_UNREACHABLE`, `REDIRECT_FAILED`, `FIB_NO_NEIGH`), so those failures are diagnosable without a packet capture.

**One blind spot.** `BPF_FIB_LKUP_RET_FWD_DISABLED`/`NOT_FWDED` — the kernel refusing a forwarding lookup on an interface not configured as a router — has no drop reason of its own (`prog/dropreason.go:25-29` carries only `LookupFailed`, `NoNeigh`, `Unreachable`, `FragNeeded`), so it lands in the generic `fib_lookup_failed` bucket. `ConfigureFIBLookupUplinkSysctls`'s own doc comment records that this exact indistinguishability is what hid the containerlab XDP blocker, and that helper only runs on `galactic-gateway`/`galactic-nat66` nodes — which a gateway node need not be. Adding the counter is a small change and worth doing alongside Piece 3 rather than rediscovering it live.

---

## 10. Open questions

1. **The Piece 2 handshake.** The VRF is created by the sidecar in the pod netns; the veth by the router in root netns; the pod end must be enslaved into that VRF. Who waits for whom, and how does each side recover idempotently after its own restart? Sub-question: how does the router learn the pod's netns — `hostPID` plus a `/proc/*/ns/net` inode scan against an inode the sidecar publishes, or a CRI lookup from the pod's identity? `hostPID` on `galactic-router` (already `hostNetwork`) is far less objectionable than on the Envoy pod, but it is still a new grant.
2. **Where the gateway address lives.** `ensureGatewayAddress` currently assigns it to `ivsN` (`gatewayaddress.go:166`). Under §6.3 it belongs on Piece 2's veth. Under the conservative shape, does it move, or does it stay on `ivsN` with the new veth carrying only the route? Both are locally deliverable since both links are enslaved to the same VRF, but only one keeps `NetlinkGatewayAddressResolver` working unchanged.
3. **`ensureRedirectRoute`'s fate** (§7.3) — delete, or keep for extension-server-less deployments?
4. **`vrf_table` sizing.** Two entries per VPC per co-located node against `max_entries = 8192` puts the ceiling at ~4095 platform VPCs, and `usid.c:742`'s own comment already flags a third concurrent Block as an exhaustion case. Does this change raise it, or does the platform accept that ceiling explicitly?
5. **Is the Envoy node affinity expressing what it means?** `.../edge/patches/downstream-gateway.yaml` requires `galactic.datumapis.com/node NotIn [control]`, but `node`'s documented values are `compute`/`edge` — `control` is a value of the *`galactic`* key (the route reflector). As written the term also requires the `node` label to be present at all. Possibly intended as `galactic NotIn [control]`. Either reading admits compute nodes, so it does not change D-5, but it is worth confirming rather than inheriting.

---

## References

- [internal/plumbing/ebpf/prog/usid.c](../../internal/plumbing/ebpf/prog/usid.c) — `usid_ingress` steps 1–9, `usid_egress`, `enum egress_kind`, `apply_nptv6`, `apply_vip_xlat`.
- [internal/cnibgp/bgp.go](../../internal/cnibgp/bgp.go) — `registerEBPFDatapath` (line 587), the working reference implementation for a tenant attachment.
- [internal/hostgw/hostgw.go](../../internal/hostgw/hostgw.go) — `ConfigureHostGateway`, `installGatewayNeighbor`; the reference implementation Piece 3 reuses.
- [internal/gc/gc.go](../../internal/gc/gc.go) — `SweepEBPFVRFTable`'s repair loop (line 663), `resolveVRFKernelState` (line 756), `CollectOrphanedVRFs` (line 400).
- [internal/ingresssidecar/ebpfdatapath.go](../../internal/ingresssidecar/ebpfdatapath.go) — `ingressSidecarBlock`, `ensureEgressDatapath`, `ensureEgressVeth`, `ensureRedirectRoute`.
- [internal/ingresssidecar/gateway.go](../../internal/ingresssidecar/gateway.go) — `k8sGatewayPublisher`, `lookupBGPRouter`, `allocateGatewayArgument`.
- [internal/plumbing/ebpf/usidmap/doc.go](../../internal/plumbing/ebpf/usidmap/doc.go) — names Piece 1's intended owner; states that `locator_table`/`function_table` are unswept by design.
- `network-services-operator/internal/extensionserver/mutate/vpcpod.go` — `ApplyVPCPodSocketBind`, `vrfDeviceName`; the `SO_BINDTODEVICE` dependency §7.1 rests on.

---

## Related fixes

**`vrfTableID`'s `vrf_table` fallback (PR #500) — fixed, in the working tree.** The fallback added to recover a table ID for a VRF invisible in root netns could never hit any real row: it derived `block` from the *VPC identifier* (`intf.Base62ToHex(vpc)` parsed as hex) while every writer keys `block` off an SRv6 locator's top 48 bits (`uformat.Block`) or off the reserved `uformat.BlockMax`, and it looked up `BGPVRFInstance.Spec.VRFID` as the argument while the sidecar registers `vrf.TableID(vpc)` — two unrelated allocators. Its own doc comment asserted the opposite.

Removed rather than re-keyed, for the reason §6.2's target shape makes clearer: on a node whose only consumer of that VPC is Envoy, the `egress_route_table` entries that table ID would have been used to install are already written per-EndpointSlice by the sidecar itself (`backend.go:107` → `srv6.RouteEgressAdd`), and Envoy only ever connects to backends those same EndpointSlices published. So there was nothing for `galactic-router` to add, and the honest handling is to skip quietly. `internal/plumbing/vrf` gained an `ErrNotFound` sentinel so `applyVRFs` can tell "absent from this netns" (ordinary, now debug-level) from a genuine netlink failure (still an error) — previously that condition logged `"this VRF's routes will not be installed"` on every reconcile, forever, for a VRF that was fine.
