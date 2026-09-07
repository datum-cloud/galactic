// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package nptv6 implements RFC 6296 stateless IPv6-to-IPv6 network prefix
// translation, for backends presenting a ULA that must appear as a different,
// globally routable prefix.
//
// Unlike the stateful NAT66 tier, this is a pure one-to-one prefix rewrite with
// no connection table: the same source address always maps to the same
// translated address, in both directions, with no per-flow state anywhere.
//
// # Checksum neutrality
//
// A naive prefix rewrite invalidates every transport checksum that covers the
// address, the IPv6 pseudo-header including both. RFC 6296 avoids that without
// touching the L4 header, by folding a precomputed adjustment into one 16-bit
// word of the address itself, chosen so the address's own checksum contribution
// is unchanged end to end.
//
// The adjustment is a pure function of the two configured prefixes, so the same
// value applies to every address sharing a mapping and never needs recomputing.
// Translating is then one add or subtract into a fixed word, which is the
// constant per-packet cost the datapath requires.
//
// # Scope: prefixes of /48 or shorter
//
// RFC 6296 defines two placements for the adjustment word. The mandatory one,
// for prefixes of /48 or shorter, fixes it at bits 48 through 63, which is what
// this implements. The optional one, for /49 through /64, instead scans the
// interface identifier for the first word that is not already all ones, a
// per-address decision rather than a fixed location.
//
// That second scheme is not implemented: the VPC subnet prefixes here are /48,
// so the mandatory case is the one this design needs. A prefix longer than /48
// is rejected with a clear error rather than translated incorrectly.
//
// # Keyed by VRF, never by address
//
// This package has no notion of a VRF or tenant: a mapping is two prefixes.
// Scoping by VRF, so two tenants may configure the same ULA prefix without
// colliding, is the caller's job. The eBPF table this feeds is keyed by VRF and
// consulted only after the uSID decap has already resolved which tenant a
// packet belongs to.
package nptv6
