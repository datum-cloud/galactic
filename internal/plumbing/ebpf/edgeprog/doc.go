// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package edgeprog holds the compiled XDP program implementing the edge
// gateway's Maglev direct-server-return load-balancing datapath, plus a direct
// SRv6 uSID push. No overlay, no separate decap step, no kernel VRF dependency
// for the encapsulation, and no address or port rewriting: the backend answers
// the client directly, so this program only ever needs a forward path.
//
// edgedsr.c is the single source of truth for the packet path; its header
// comment walks it. `go generate` compiles it with clang into a
// CO-RE-portable BPF object and generates the matching Go bindings here. Run it
// after editing the C source.
//
// The generated files are gitignored rather than committed and are regenerated
// at every build site, for the same reason as the other datapath packages: a
// committed binary blob can drift out of sync with its source with nothing short
// of a byte-diff to catch it.
//
// It is a sibling of the uSID datapath package rather than a second program
// inside it. The two are different domains, edge ingress load balancing against
// uSID decap, sharing no map or key layout, so folding them together would
// couple things that change for unrelated reasons.
//
// This package neither loads nor attaches the program; the attach package and
// the gateway engine's datapath do that.
package edgeprog

// See the uSID program package's doc.go for why the include flags list both
// multiarch directories and why the compiler is not named explicitly.
//
// This program never takes the address of a field inside a packed struct, so it
// needs no warning suppression for that.
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cflags "-O2 -g -Wall -idirafter /usr/include/x86_64-linux-gnu -idirafter /usr/include/aarch64-linux-gnu" -target bpfel,bpfeb -type vip_key -type backend -type vip_value -type vip_stats_value -type encap_config Edgedsr edgedsr.c
