// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package nptv6 implements RFC 6296 stateless IPv6-to-IPv6 Network Prefix
// Translation for backends presenting a ULA that must appear as a different
// (public/global) prefix. Unlike NAT66/masquerade (internal/maglev's
// separately-sharded stateful tier), this is a pure 1:1 prefix rewrite with
// no connection table: the same source address always maps to the same
// translated address, in both directions, with no per-flow state anywhere.
//
// # Checksum neutrality
//
// A naive prefix rewrite would invalidate every TCP/UDP checksum that
// covers the address (the IPv6 pseudo-header includes both addresses) —
// RFC 6296 avoids that without ever touching the L4 header by folding a
// precomputed "adjustment" value into one 16-bit word of the address itself
// (§3.4), chosen so the address's own 1's-complement checksum contribution
// is unchanged end to end. Adjustment is a pure function of the two
// configured prefixes (Mapping.Adjustment) — the same value applies to
// every address sharing that Mapping and never needs recomputing per
// packet; Translate then does one 1's-complement add/subtract of that
// precomputed value into the fixed word, exactly the O(1)-per-packet cost
// the design plan requires.
//
// # Scope: /48-or-shorter prefixes only
//
// RFC 6296 defines two placements for the adjustment word: §3.4 (MUST
// support), for prefixes of length 48 or shorter, fixes it at bits 48..63 —
// implemented here. §3.5 (SHOULD support), for prefixes of length 49..64,
// instead scans the address's own Interface Identifier words (64..79,
// 80..95, 96..111, 112..127, in that order) for the first word that isn't
// already 0xFFFF and uses that — a genuinely per-address decision, not a
// fixed location, and not implemented here: this repo's own VPC subnet
// prefixes are /48 (see deploy/containerlab/resources/tenants/*/nad.yaml's
// "ipv6_subnet" fields), so the §3.4 case is the one this design actually
// needs. Mapping.Adjustment and Translate both reject a prefix longer than
// /48 with a clear error rather than attempting the more complex §3.5
// scheme incorrectly.
//
// # VRFID-keyed, never address-keyed
//
// This package itself has no notion of a VRF or tenant at all — a Mapping
// is just two prefixes. Scoping by VRFID (so two tenants may configure the
// identical ULAPrefix without collision) is the caller's job: the eBPF-side
// table this package's Adjustment feeds (a new nptv6map, mirroring
// internal/plumbing/ebpf/edgemap's Register/Reconcile/Generation
// crash-safety convention) is keyed by VRFID, consulted only after the
// existing SRv6 uSID decap program (internal/plumbing/ebpf/prog/usid.c) has
// already resolved which tenant VRF a packet belongs to — see the design
// plan's §2.
package nptv6
