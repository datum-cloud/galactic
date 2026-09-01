# Implementation plan — #855 follow-up: return-path gateway advertisement

- **Parent:** [datum-cloud/enhancements#796](https://github.com/datum-cloud/enhancements/issues/796) — HTTP Ingress for VPC Networks
- **Sibling plan:** [docs/plans/855-ingress-sidecar-vpc-backend-connectivity.md](855-ingress-sidecar-vpc-backend-connectivity.md) — the accepted #855 design this plan extends. Read that one first; this doc only covers the gap it left open.
- **Status:** `GatewayPublisher`/`GatewayAddressResolver` implemented and unit-tested in `internal/ingresssidecar` (`gateway.go`, `gateway_test.go`, `store_gateway_test.go`); wired into `Store` (opt-in, see "Backward compatibility" below) and `cmd/galactic-vrf`. **Address provisioning is explicitly not implemented** — see "Not implemented here."

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

## Not implemented here

**Provisioning the gateway address itself** — creating a veth-style attachment into each VPC this sidecar handles, with its own IPAM allocation, so `NetlinkGatewayAddressResolver` has something to find — is a real, separate gap, deliberately left open:

- It needs real kernel-level work (interface creation, address assignment) inside Envoy's own netns, which the sibling plan's own §7 already treats as requiring "a real-kernel verification pass... not possible from this sandbox" for the *forward*-path mechanism it does implement — the same constraint applies here, more so, since this is new kernel-facing code rather than a call into already-proven `internal/plumbing` primitives.
- It needs an IPAM coordination story this plan doesn't have: whether the sidecar requests its own allocation the way `galactic-cni` does for a pod, or a fixed reserved slot per VPC subnet, or something else, is an open design question, not a detail to improvise silently.
- The live demo/test environment this gap was found in had a manually created veth (`gwatt1`, address `fd20:0:2::4:0:0/96`) standing in for this — evidence the *symptom* is real, not evidence of how provisioning should actually work in production.

Filing this as its own follow-up (a sub-issue of #855 or a new #796 sub-issue, matching how #859's health-checking gap was handled) is the right next step, not bundling it into this change.
