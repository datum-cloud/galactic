// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package nat66prog holds the compiled XDP program that implements one
// shard of galactic-nat66's sharded, stateful NAT66 egress tier (design
// plan §3) -- deliberately its own standalone datapath, not a personality
// bolted onto galactic-gateway's own edgedsr.c: tenant egress traffic
// (backend -> arbitrary internet destination) is a different pattern from
// ingress (fixed VIP, fixed backend pool) and needs its own placement
// ring, own state, own maps, with nothing shared between the two tiers.
//
// nat66.c is the single source of truth for the packet path; see its
// header comment for the full walkthrough. `go generate` (via bpf2go)
// compiles it with clang into a CO-RE-portable BPF object and generates
// matching Go bindings (Nat66Objects, LoadNat66, LoadNat66Objects, plus
// per-map/per-program fields) in this package.
//
// Same not-committed-generated-artifacts convention as
// internal/plumbing/ebpf/prog and internal/plumbing/ebpf/edgeprog: see
// either's doc.go for the full rationale (a compiled binary blob risks
// silently drifting out of sync with its own source with nothing to catch
// the mismatch short of a byte-diff).
//
// Placement: sibling of internal/plumbing/ebpf/edgeprog under the shared
// internal/plumbing/ebpf/ umbrella, its own package rather than a second
// program in edgeprog -- same "different datapath domain, no shared
// map/key layout" reasoning edgeprog's own doc.go gives for not folding
// into internal/plumbing/ebpf/prog.
//
// This package does not itself load or attach the compiled program to any
// interface -- that is internal/plumbing/ebpf/nat66attach's job (mirroring
// edgeattach's shape), driven by cmd/galactic-nat66.
package nat66prog

// See internal/plumbing/ebpf/prog/doc.go for why -idirafter lists both
// multiarch directories and why -cc is omitted.
//
// -Wno-address-of-packed-member: same known clang false positive
// edgenat.c's own doc.go documented -- struct l4_view's sport_ptr/
// dport_ptr/check_ptr fields all sit at compile-time-fixed *even* offsets
// within their packed struct (nat66_tcphdr's source/dest/check are
// 0/2/16; nat66_udphdr's are 0/2/6), genuinely 2-byte aligned despite the
// packed attribute.
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cflags "-O2 -g -Wall -Wno-address-of-packed-member -idirafter /usr/include/x86_64-linux-gnu -idirafter /usr/include/aarch64-linux-gnu" -target bpfel,bpfeb -type conn_key -type conn_value -type shard_config Nat66 nat66.c
