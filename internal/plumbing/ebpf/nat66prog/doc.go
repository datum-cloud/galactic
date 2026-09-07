// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package nat66prog holds the compiled XDP program implementing one shard of
// the sharded, stateful NAT66 egress tier.
//
// It is deliberately its own datapath rather than a second personality on the
// edge gateway's: tenant egress toward an arbitrary internet destination is a
// different pattern from ingress toward a fixed VIP and backend pool, and needs
// its own placement ring, state, and maps, sharing nothing with that tier.
//
// nat66.c is the single source of truth for the packet path; its header comment
// walks it. `go generate` compiles it with clang into a CO-RE-portable BPF
// object and generates the matching Go bindings here.
//
// The generated files are gitignored rather than committed, as in the sibling
// datapath packages: a committed binary blob can drift out of sync with its
// source with nothing short of a byte-diff to catch it.
//
// This package neither loads nor attaches the program; internal/plumbing/ebpf/
// nat66attach does, driven by cmd/galactic-nat66.
package nat66prog

// See the uSID program package's doc.go for why the include flags list both
// multiarch directories and why the compiler is not named explicitly.
//
// The packed-member warning is suppressed for a known false positive: the
// pointer fields into the L4 view all sit at compile-time-fixed even offsets
// within their packed structs, so they are genuinely 2-byte aligned despite the
// packed attribute.
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cflags "-O2 -g -Wall -Wno-address-of-packed-member -idirafter /usr/include/x86_64-linux-gnu -idirafter /usr/include/aarch64-linux-gnu" -target bpfel,bpfeb -type conn_key -type conn_value -type shard_config Nat66 nat66.c
