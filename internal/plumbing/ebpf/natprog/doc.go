// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package natprog holds the compiled XDP programs implementing one shard of
// the sharded, stateful egress translation tier -- NAT66 (IPv6 to IPv6) and
// NAT64 (IPv6 to IPv4, RFC 6146) over one session table and one port
// allocator.
//
// It is deliberately its own datapath rather than a second personality on the
// edge gateway's: tenant egress toward an arbitrary internet destination is a
// different pattern from ingress toward a fixed VIP and backend pool, and needs
// its own placement ring, state, and maps, sharing nothing with that tier.
//
// nat.c is the single source of truth for the packet path; its header comment
// walks it, including why the two families' translation paths are separate
// tail-called programs behind one dispatcher rather than branches in one.
// `go generate` compiles it with clang into a CO-RE-portable BPF object and
// generates the matching Go bindings here.
//
// The generated files are gitignored rather than committed, as in the sibling
// datapath packages: a committed binary blob can drift out of sync with its
// source with nothing short of a byte-diff to catch it.
//
// This package neither loads nor attaches the programs; internal/plumbing/ebpf/
// natattach does, driven by cmd/galactic-nat.
package natprog

// Tail-call slot indices into the nat_progs program array, mirroring the
// datapath's own NAT_PROG_* constants. natattach populates every slot before
// the dispatcher is attached, so a packet never arrives at an empty one.
const (
	ProgNAT66Forward uint32 = 0
	ProgNAT66Return  uint32 = 1
	ProgNAT64Forward uint32 = 2
	ProgNAT64Return  uint32 = 3
	ProgCount        uint32 = 4
)

// Address families as the datapath writes them into conn_key.family. They
// discriminate a NAT64 row, whose IPv4 addresses are stored IPv4-mapped, from a
// genuine IPv6 flow that happens to fall in ::ffff:0:0/96.
const (
	FamilyIPv6 uint8 = 6
	FamilyIPv4 uint8 = 4
)

// See the uSID program package's doc.go for why the include flags list both
// multiarch directories and why the compiler is not named explicitly.
//
// The packed-member warning is suppressed for a known false positive: the
// pointer fields into the L4 view all sit at compile-time-fixed even offsets
// within their packed structs, so they are genuinely 2-byte aligned despite the
// packed attribute.
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cflags "-O2 -g -Wall -Wno-address-of-packed-member -idirafter /usr/include/x86_64-linux-gnu -idirafter /usr/include/aarch64-linux-gnu" -target bpfel,bpfeb -type conn_key -type conn_value -type shard_config Nat nat.c
