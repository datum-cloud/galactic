// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package natattach loads the compiled NAT66 XDP program and attaches it to
// every one of a shard's fabric-facing uplinks.
//
// It mirrors the edge attach package's mechanics almost verbatim: pinned maps,
// verifier-error unwrapping, incompatible-map recreation on a schema change, and
// native-driver-mode attach with no generic-mode fallback. See that package for
// the rationale behind each, which applies here unchanged.
//
// # Sharing the hook with the edge gateway
//
// An interface takes one native XDP program. On a node where the gateway runs
// too, the shard does not attach itself: it runs from the egress slot of the
// node's shared XDP dispatcher (internal/plumbing/ebpf/xdpdispatch), whose root
// holds every uplink for both datapaths. cmd/galactic-nat drives that through
// xdpattach.DispatchSet; Load and PopulateProgArray here are the same in
// either mode.
//
// # No kernel preflight check
//
// Unlike its sibling, Load runs no preflight check first. The edge preflight
// package is scoped to that datapath's own map types, which do not include the
// LRU hash this connection table uses, and the uSID preflight package is scoped
// to the TC-BPF datapath. Neither fits, and a third package is out of scope for
// now. Loading already surfaces "this kernel cannot load this program" clearly,
// just later than a dedicated check would.
//
// # Re-attachment
//
// Every uplink ResolveUplinks returns -- the operator's override, or the
// auto-detected set -- is attached at process startup, so a multi-homed shard
// node translates on all of them and losing one uplink does not stop
// translation on the rest. A single uplink is a one-element list, and one
// naming a bonding master is expanded to that bond's slaves by ResolveTargets,
// native XDP against a bonding master being unreliable.
//
// The attach step is shared with the edge attach package (xdpattach.Attach):
// every target is checked for native XDP support before any is touched, and
// each bond slave is waited back into its aggregate before the next is
// attached, since a driver that drops carrier to reallocate its rings would
// otherwise take every member of the bond down together.
//
// Startup is not the end of it. Auto-detection reads routes, and a shard that
// starts before BGP converges sees only some of its uplinks, so the caller
// keeps the attachment set current with xdpattach.Watch: every link or route
// change resolves the uplinks again, and any not yet attached is attached
// through the same gate, one at a time. An uplink is never detached because it
// stopped resolving, only once it is gone, since detaching bounces the link
// exactly as attaching does.
package natattach
