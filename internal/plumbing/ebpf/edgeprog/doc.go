// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package edgeprog holds the compiled XDP program that implements the edge
// gateway's ingress Full-NAT (DNAT+SNAT) load-balancing and reverse un-NAT
// datapath, plus a direct SRv6 uSID push/strip -- no Geneve overlay, no
// separate gateway-tier decap step, no kernel VRF/FIB dependency for the
// encap itself (see the design plan at
// /home/sprygada/.claude/datum/plans/merry-percolating-tulip.md for the
// full rationale versus the earlier, rejected gwprog/Geneve approach).
//
// edgenat.c is the single source of truth for the packet path; see its
// header comment for the full walkthrough. `go generate` (via bpf2go,
// github.com/cilium/ebpf's code generator) compiles it with clang into a
// CO-RE-portable BPF object and generates matching Go bindings
// (EdgenatObjects, LoadEdgenat, LoadEdgenatObjects, plus per-map/
// per-program fields) in this package -- run `go generate ./...` from the
// repo root, or `go generate` from this directory, after editing
// edgenat.c.
//
// Same not-committed-generated-artifacts convention as
// internal/plumbing/ebpf/prog (see that package's doc.go): *_bpfel.go/
// *_bpfel.o and *_bpfeb.go/*_bpfeb.o are gitignored, regenerated fresh by
// `task build:ebpf` at every build site.
//
// Placement: sibling of internal/plumbing/ebpf/prog under the shared
// internal/plumbing/ebpf/ umbrella, kept as its own package rather than a
// second program in prog itself -- this is a different datapath domain
// (edge ingress NAT/LB vs. SRv6 uSID decap) with no shared map/key layout,
// so folding it into prog would couple two things that change for
// unrelated reasons (CONVENTIONS.md: "prefer creating a focused
// sub-package over adding to an existing large one").
//
// This package does not itself load or attach the compiled program to any
// interface -- that is internal/plumbing/ebpf/edgeattach's job, and
// ultimately internal/gateway's KernelDatapath, which calls into
// edgeattach/edgemap from Engine's convergence loop.
package edgeprog

// See internal/plumbing/ebpf/prog/doc.go for why -idirafter lists both
// multiarch directories and why -cc is omitted (same clang/bpf2go
// environment, same rationale, not repeated here).
//
// -Wno-address-of-packed-member suppresses a known clang false positive
// for this file's l4_view.{sport,dport,check}_ptr fields: taking the
// address of a __be16 member inside a packed struct warns generically
// (packed structs can place a field at any byte offset), but every field
// edgenat.c takes the address of sits at a compile-time-fixed *even*
// offset (edge_tcphdr's source/dest/check are 0/2/16; edge_udphdr's are
// 0/2/6) -- genuinely 2-byte aligned despite the struct's packed
// attribute, so there is no real unaligned-access risk to suppress
// unsafely here.
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cflags "-O2 -g -Wall -Wno-address-of-packed-member -idirafter /usr/include/x86_64-linux-gnu -idirafter /usr/include/aarch64-linux-gnu" -target bpfel,bpfeb -type rule_key -type backend -type rule_value -type conn_key -type conn_value -type gw_config Edgenat edgenat.c
