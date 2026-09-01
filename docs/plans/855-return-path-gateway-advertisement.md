# Implementation plan — #855 follow-up: return-path gateway advertisement

- **Parent:** [datum-cloud/enhancements#796](https://github.com/datum-cloud/enhancements/issues/796) — HTTP Ingress for VPC Networks
- **Sibling plan:** [docs/plans/855-ingress-sidecar-vpc-backend-connectivity.md](855-ingress-sidecar-vpc-backend-connectivity.md) — the accepted #855 design this plan extends. Read that one first; this doc only covers the gap it left open.
- **Status:** `GatewayPublisher`/`GatewayAddressResolver` implemented and unit-tested in `internal/ingresssidecar` (`gateway.go`, `gateway_test.go`, `store_gateway_test.go`); wired into `Store` (opt-in, see "Backward compatibility" below) and `cmd/galactic-vrf`. **Address provisioning is now implemented too** (`gatewayaddress.go`, `DeriveGatewayAddress`/`ensureGatewayAddress`), opt-in on a second, independent env var — see "Address provisioning" below, which supersedes this doc's original "Not implemented here" section.

## What's broken, and how it was found

Testing an end-to-end request through `envoy-datum-downstream-gateway` into a VPC-hosted backend (`demo2loc-dfw-dfw-0`, `us-central-1-staging-lab`) showed the request entering Envoy correctly, and — once a separate, unrelated sysctl gap on the same DaemonSet was worked around live — the forward path working exactly as #855 designed it:

1. `vpc-vrf-sidecar` (this sidecar) creates a per-VPC VRF in Envoy's own pod netns and installs a `seg6 ENCAP_RED` egress route for the backend pod's address, toward that pod's own SID — all per the sibling plan.
2. A request from Envoy's netns to the backend address is correctly SRv6-encapsulated (confirmed by packet capture on the node's uplink: outer header addressed to the backend node's computed uSID, inner header the real TCP SYN).
3. The backend pod receives it and replies with a SYN-ACK (confirmed by packet capture on the backend node's own uplink).
4. **The reply never reaches Envoy.** Captured leaving the backend node's uplink, it's a *plain, unencapsulated* IPv6 packet addressed to Envoy's own local gateway address inside the VPC (the source address the kernel picked for Envoy's outbound connection, e.g. `fd20:0:2::4:0:0`) — not SRv6-wrapped toward Envoy's node at all.

The reason: the backend node's own copy of this VPC's VRF only re-encapsulates traffic toward destinations it has an EVPN route for — and **nothing publishes a `BGPAdvertisement` for Envoy's own local gateway address**. `galactic-cni` publishes one for every pod's own address (`internal/cnibgp/bgp.go`), which is exactly why the *forward* direction already works — but this sidecar's own address, on the *return* side, has no equivalent. Confirmed live: `kubectl get bgpadvertisement -A` on the edge node hosting Envoy showed nothing referencing that address at all.

This is a real gap in the accepted design (PR #851), not a bug in existing code: neither #855's own plan nor #856's does not mention publishing anything for the sidecar's own address — see the sibling plan's §1 "Attach/detach VPC network lifecycle" row, which scopes pod IP/attachment publishing to `galactic-cni` alone and says nothing about the sidecar's own reverse path.

## What this plan adds

Mirrors `internal/cnibgp/bgp.go`'s own pod-address publish pattern (`lookupBGPRouter`, `allocateArgument`/`checkArgumentCollision`, `routeTarget`, `buildVRFInstanceSpec`/`buildAdvertisementSpec`), reimplemented in miniature in `internal/ingresssidecar/gateway.go` rather than imported — `cnibgp`'s version is entangled with CNI-only concerns (prevResult, IPAM, per-container-ID annotations, ADD/DEL rollback tracking) this sidecar has none of. Consolidating the two into one shared package is a reasonable follow-up, not done here to avoid touching `cnibgp`'s existing, heavily-relied-upon publish path in the same change that introduces this new caller.

- **`GatewayPublisher`** (`PublishGateway`/`WithdrawGateway`): given a VPC and this node's own local address in it, publishes/withdraws a `BGPAdvertisement` for that address, reusing the *same* `(vpc, node)`-keyed `BGPVRFInstance` a real CNI attachment on this node would use (so a coincidentally-colocated tenant pod's own VRFID bookkeeping is never disturbed), and the *same* route-target formula every other advertisement for that VPC uses — so any node importing that VPC's RT picks this up too, with no coordination needed beyond both sides computing the identical value. Never deletes the (possibly shared) `BGPVRFInstance` on withdraw — that stays `galactic-router`'s GC controller's job, same as every other CRD this codebase leaves for GC to reap.
- **`GatewayAddressResolver`** (`ResolveGatewayAddress`): discovers this sidecar's own local address for a VPC by scanning the VPC's Linux VRF device (the one `internal/plumbing/vrf.Add` creates) for a slave interface carrying a global-scope IPv6 address. Returns `ErrGatewayAddressNotProvisioned` when none exists yet — the common case today, see below.
- **`Store` wiring**: `SetGatewayPublisher` is an opt-in setter, not a constructor argument — every existing `NewStore` call site is unchanged. Publish is attempted once per VPC's VRF lifetime (alongside `EnsureVRF`); withdraw once per VRF teardown (alongside `RemoveVRF`, best-effort — a failed withdraw never blocks the kernel-side cleanup that follows it). A resolver reporting `ErrGatewayAddressNotProvisioned` is logged at debug and left to retry on the next reconcile for that VPC, never treated as a route-reconcile failure.
- **`cmd/galactic-vrf`**: wires the two together only when `GALACTIC_VRF_NODE_NAME` (or legacy `NODE_NAME`) is set — see `internal/config.VRFConfig`'s `NodeName`/`Namespace` fields.

## Backward compatibility

Every piece above is inert by default:

- `Store.SetGatewayPublisher` is never called unless `cfg.NodeName != ""`.
- Even when called, `NetlinkGatewayAddressResolver` returns `ErrGatewayAddressNotProvisioned` for every VPC today, since nothing provisions the address it looks for (see next section) — so `PublishGateway` never actually runs against a real deployment yet.

No existing deployment of this sidecar is affected by this change until both a node identity is configured *and* something provisions a gateway address per VPC.

## Address provisioning (supersedes "Not implemented here")

This doc originally left address provisioning as an open gap, citing an unresolved IPAM coordination question: "whether the sidecar requests its own allocation the way `galactic-cni` does for a pod, or a fixed reserved slot per VPC subnet, or something else." Investigating that question found the real answer is neither option as originally framed:

- **A real tenant VPC's address space is not owned by this repo.** `internal/cniipam`'s only *computed* allocation path (`internal/cni/ipam.PoolAllocator`, sequential first-fit over a configured pool CIDR) is used for lab/self-managed deployments; the production addressing scheme (`ipam.addresses`) takes pre-decided addresses from an external system this repo has no visibility into. A live tenant address's own bit layout doesn't match `PoolAllocator`'s own increment logic, confirming this directly rather than by inference from the docs alone. So there is no "reserved slot" inside a VPC's own subnet this repo can prove is safe to claim — the allocator that would need to avoid it isn't code this repo can read.
- **The fix doesn't need one.** BGP import into a VPC's VRF is driven entirely by Route Target community, computed from the VPC id (`vpcRouteTarget` in `gateway.go`) — never by whether an advertised prefix's address value falls inside any particular subnet. A gateway address only needs to be (a) globally unique and (b) advertised with the correct RT; it never needs to be a member of the tenant's own pool at all.

`gatewayaddress.go`'s `DeriveGatewayAddress(prefix, vpc, nodeID)` acts on that: `prefix` is a reserved, byte-aligned IPv6 CIDR that is disjoint *by construction* from tenant space (never handed to any IPAM, local or external, as a pool to allocate from), not disjoint by avoidance within it. The host bits are filled deterministically from `sha256(vpcHex + "|" + nodeID)` — collision-safe against another VPC's or another node's own derived address with overwhelming probability, which is sufficient here since nothing else ever contends for a specific value the way a live IPAM allocation call does.

`ensureGatewayAddress`, called from `ensureEgressDatapath` right after `ensureEgressVeth`, assigns the derived address to the same VRF-slave veth (`ivsN`) that function already creates for `usid_egress`'s own attachment — so `NetlinkGatewayAddressResolver` (already implemented, unchanged) finds it with zero further wiring, and IPv6 source-address selection picks it up for the forward path too (closing a second, related symptom found live: with no global address anywhere in the VRF, the kernel fell back to a link-local source for Envoy's own outbound connections into the VPC).

**Opt-in on a second, independent env var (`GALACTIC_VRF_GATEWAY_PREFIX` / `internal/config.VRFConfig.GatewayPrefix`), only takes effect when `NodeName` is also set.** Deliberately no compiled-in default: *which* reserved prefix to use is a real platform-addressing decision — the exact kind of thing this doc's own "Not implemented here" section was right to flag as not-to-improvise-silently — for whoever owns this deployment's IPAM plan to make explicitly, then configure. The code closes the mechanism; picking and rolling out an actual prefix value is a deployment decision, not a code change.

Both `GALACTIC_VRF_NODE_NAME` and `GALACTIC_VRF_GATEWAY_PREFIX` are unset in every deployment today, so this remains fully inert until an operator configures both — no existing behavior changes.

## Second gap found live: wrong outer SRv6 source address (fixed)

Configuring both env vars against `us-central-1-staging-lab` (infra#4420) and re-running the full end-to-end curl test still failed, with the identical `upstream_reset_before_response_started{connection_timeout}` symptom as before either fix. Chasing that down live found a second, independent bug, this time in the *forward* path's own outer SRv6 header, not the return path this doc otherwise covers:

`ensureNodeSourceAddress` (`ebpfdatapath.go`) called `srv6.ResolveNodeSourceAddress()` unmodified — the same function `galactic-cni` uses, which auto-detects "the fabric interface" as whichever interface carries the local default IPv6 route. That's correct for `galactic-cni`, which runs in the host's own root network namespace, where the default route really does belong to the real fabric uplink. It is wrong by construction for this sidecar: #855's own design runs it inside Envoy's pod netns, where the interface carrying the default route is the pod's own Cilium-managed `eth0` — a ULA address from the cluster's tenant pod pool (`fd20::/20`), not this node's real, globally-routable address at all.

Confirmed live: a packet capture on the sending node's own uplink showed the outer SRv6 header's source address matching the Envoy pod's own pod IP bit for bit. The destination (a real uSID locator SID) routed correctly through genuine global BGP transit — confirmed both via `stat.ripe.net` (fully visible, 319/319 RIS peers) and a traceroute that reached real backbone routers before dying at what a running-config's own peer descriptions identified as the destination provider's own top-of-rack switches, with no ICMP error. That is the signature of a customer-facing anti-spoofing/BCP38 filter silently dropping a packet whose source address is not a real, routable address — exactly what a ULA source is.

Two theories were considered and ruled out live before landing on this one:

- **A missing specific `/128` route for the destination uSID address** (only the containing `/48` aggregate, backed by a `Null0` placeholder, was ever advertised) — ruled out by comparing against `deploy/containerlab`'s own known-working `dfw-worker` FRR config, which uses the identical aggregate+`Null0` pattern with no per-SID address anywhere, plus the fact that TC-BPF ingress classification runs before any kernel FIB lookup, so a `Null0` route can never affect a packet `usid_ingress` actually intercepts.
- **Two disconnected upstream providers with no shared route reflector** — ruled out by `stat.ripe.net`'s AS-path data, which showed the sending node's own upstream ASN as the penultimate hop before the origin AS in nearly every observed path to the destination prefix — the two networks are demonstrably not islands.

**Fix:** a new `NodeSourceAddressResolver` interface (`nodesourceaddress.go`), with a production implementation that reads this node's own real address off a `BGPPeer` CR's `spec.updateSource` (the local source address for that BGP session — `spec.address` is the *remote* peer's address) rather than any local netns interface state. Every `BGPPeer` targeting this node's own `BGPRouter` carries the same real answer, so the first one with a parseable `updateSource` wins. Wired in opt-in via `SetNodeSourceAddressResolver`, gated on the same `cfg.NodeName != ""` condition as `SetGatewayPublisher` — `ensureNodeSourceAddress` falls back to the old `srv6.ResolveNodeSourceAddress()` behavior when no resolver is configured, so this is purely additive until `cmd/galactic-vrf` wires it.

Needs one more RBAC grant this sidecar didn't have before: `bgppeers` get/list/watch, alongside the `bgprouters`/`bgpvrfinstances`/`bgpadvertisements` infra#4420 already added.
