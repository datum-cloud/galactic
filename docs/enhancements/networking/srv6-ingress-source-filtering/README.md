# SRv6 ingress source filtering

Status: Proposed.

## Summary

Galactic nodes accept SRv6 traffic for a tenant network only when it comes
from another node in the Galactic fabric. Today a node decides what to do with
an SRv6 packet from its destination alone, so the fabric's isolation rests on
its SRv6 address space never being reachable from outside. This adds a second,
independent check: the node also verifies the packet's source against the set
of fabric peers it already knows, and drops anything else.

## Motivation

Customers expect a private network to accept traffic only from their own
instances and from the platform services they have configured, such as load
balancers and NAT gateways. A single routing mistake, a provider announcing a
prefix it should not, or a future cross-site link should not be enough to let
outside traffic into a tenant network or through a NAT gateway.

Source filtering makes that guarantee hold inside the datapath rather than
depending on how the underlay is routed, and gives operators visibility into
any traffic that would have violated it.

## Goals

- Deliver SRv6 traffic into a tenant network only when its source is a known
  fabric peer.
- Apply the same rule to NAT gateways, so only fabric members can send traffic
  through them.
- Reject a packet that claims a peer's source but arrives on a link that peer
  is not reachable through.
- Roll out safely: an audit mode that counts would-be drops without dropping,
  metrics for every decision, and no change in behaviour until enabled.
- Keep the per-packet cost to a single table lookup on traffic already
  addressed to the node.

## Non-goals

- Encrypt or authenticate traffic between sites. A source address can still be
  forged on a path that legitimately carries fabric traffic; closing that needs
  an authenticated underlay, which is a separate enhancement.
- Restrict which tenant a fabric peer may send to. Per-tenant source binding
  is a follow-up phase.
- Filter non-SRv6 traffic, or change BGP, BFD or route reflector sessions.

## High-level architectural proposal

Every legitimate SRv6 packet is sourced from the sender's own SRv6 address:
compute nodes, edge gateways and NAT gateways all set the outer source to an
address inside their node's locator. Each node already learns every peer's
locator from the fabric underlay, so the set of legitimate sources is known
locally and updates as the fabric converges.

```
fabric routes (FRR / GoBGP)  ─►  source filter reconciler  ─►  allow-list map
                                        (galactic-cni, galactic-nat)       │
                                                                           ▼
SRv6 packet ─► uSID ingress: destination is ours? ─► source allowed on this link? ─► tenant VRF
                                    │ no                         │ no
                                    ▼                            ▼
                             normal stack                 drop (enforce) / count (audit)
```

- **Datapath.** The uSID ingress program gains a source check immediately
  after it recognises its own locator and before any tenant delivery: a
  longest-prefix lookup of the outer source in an allow-list, plus a check
  that the packet arrived on an interface the matching peer is reachable
  through. The NAT gateway program gets the same check before it forwards,
  and additionally rejects sources that are not well-formed tenant addresses.
- **Control plane.** A reconciler in `galactic-cni` (and in `galactic-nat` for
  gateway nodes) builds the allow-list from the routes the fabric's BGP has
  installed. A route becomes an allow-list entry only when all of these hold:
  - it was installed by the fabric's own routing (the underlay BGP, or
    `galactic-router` for gateway routes), not by a static or other route
    source;
  - its next hop is a configured fabric BGP peer;
  - it falls inside the configured SR domain prefixes, at node-locator length
    or longer, and is not the node's own locator.

  Each entry is bound to the interfaces its route uses. The reconciler reuses
  the existing netlink route and link watch, applies changes as diffs, and
  resyncs periodically.

  The allow-list is built from these routes rather than from the BGP peer list
  itself because the two carry different addresses. A peer's BGP session runs
  between link or private addresses, but its SRv6 traffic is sourced from its
  locator. BGP is how each node learns which locator belongs to which peer, and
  the resulting route also records the link that peer is reachable through,
  which is what interface binding needs.
- **Modes.** `off` (default, no behaviour change), `audit` (count and log
  would-be drops, deliver everything) and `enforce` (drop). The filter stays
  open until its first complete sync, and a stale allow-list is kept rather
  than cleared if the control plane fails, so a control-plane fault cannot
  black-hole tenant traffic.
- **Configuration.** The mode, the SR domain prefixes, strict or loose
  interface binding, and any static extra sources, set per node by the
  deployment.
- **Observability.** Counters for every decision (checked, allowed, denied by
  prefix, denied by interface, bypassed before first sync), the allow-list
  size and mode as metrics, and a bounded record of denied sources for triage.
- **Compatibility.** The new state lives in new maps only, so upgrading does
  not disturb existing pinned datapath state.

## Rollout

1. Ship with the filter off.
2. Enable audit on staging cells and review any denials.
3. Enforce on staging, then audit and enforce in production.

## Follow-ups

- Per-tenant source binding: a tenant network accepts traffic only from the
  sources that advertise that tenant.
- Authenticated underlay for cross-site links.
