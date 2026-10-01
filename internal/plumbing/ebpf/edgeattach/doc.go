// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package edgeattach loads the compiled edge XDP program and attaches it to the
// gateway node's underlay-facing uplink.
//
// Load mirrors the uSID datapath's own loading mechanics almost verbatim,
// pinned maps and incompatible-map recreation included, none of which is
// attach-mechanism specific. Attach is genuinely different: XDP attaches
// through a kernel bpf_link, a different surface than a TC filter entirely.
//
// The configured uplink is usually one physical interface, attached at process
// startup. One naming a bonding master is expanded to that bond's slaves and
// every one is attached, native XDP against a bonding master being unreliable.
//
// A bond's membership can change after startup, so the caller does not resolve
// the targets only once: it re-runs ResolveTargets on every netlink link or
// route change and hands the result to an xdpattach.Set, which attaches a
// member enslaved or replaced since through the same bond-safe gate, and
// releases the link of one that is gone.
//
// Native mode is required, not preferred. Attach always requests driver mode and
// returns an error rather than silently retrying in generic mode, which has
// materially different performance characteristics: accepting it silently would
// defeat the reason this design chose XDP, and would violate the same no-partial-
// fallback invariant the preflight checks hold the rest of the datapath to.
//
// Unlike a TC filter, which persists in the kernel independent of any process
// holding a reference, an unpinned link detaches when the last descriptor
// referencing it closes. This package does not pin the returned links: the
// owning process holds them open for its lifetime, in that xdpattach.Set, and
// closes them on shutdown.
// A restart therefore starts from a genuinely clean slate, with no existing
// attachment to conflict with and so no replace case to handle.
package edgeattach
