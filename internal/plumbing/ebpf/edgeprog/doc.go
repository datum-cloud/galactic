// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package edgeprog holds the compiled XDP program that implements the edge
// gateway's Maglev/DSR (Direct Server Return) consistent-hash
// load-balancing datapath, plus a direct SRv6 uSID push -- no Geneve
// overlay, no separate gateway-tier decap step, no kernel VRF/FIB
// dependency for the encap itself, and (unlike the Full-NAT predecessor
// this replaces) no address/port rewriting or reverse-path decap of any
// kind: the backend answers the client directly, so this program only
// ever needs a forward path. See the DSR/Maglev design plan (kitt
// notebook, projects/galactic/dsr-maglev-nptv6-nat66-design.md) for the
// full rationale, and edgedsr.c's own header comment for what this
// simplification removes versus the Full-NAT edgenat.c it replaces
// (removed entirely, not kept as an alternate mode -- breaking change, no
// migration path).
//
// edgedsr.c is the single source of truth for the packet path; see its
// header comment for the full walkthrough. `go generate` (via bpf2go,
// github.com/cilium/ebpf's code generator) compiles it with clang into a
// CO-RE-portable BPF object and generates matching Go bindings
// (EdgedsrObjects, LoadEdgedsr, LoadEdgedsrObjects, plus per-map/
// per-program fields) in this package -- run `go generate ./...` from the
// repo root, or `go generate` from this directory, after editing
// edgedsr.c.
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
// Unlike edgenat.c, edgedsr.c never takes the address of a field inside a
// packed struct (no rewrite-by-pointer of any header field -- see its own
// header comment), so -Wno-address-of-packed-member is no longer needed.
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cflags "-O2 -g -Wall -idirafter /usr/include/x86_64-linux-gnu -idirafter /usr/include/aarch64-linux-gnu" -target bpfel,bpfeb -type vip_key -type backend -type vip_value -type vip_stats_value -type encap_config Edgedsr edgedsr.c
