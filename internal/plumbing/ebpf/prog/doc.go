// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package prog holds the compiled TC-BPF program implementing the uFMT 48+16
// uSID decode and forward datapath.
//
// usid.c is the single source of truth for the packet path; its header comment
// walks the nine steps. `go generate` compiles it with clang into a
// CO-RE-portable BPF object and generates the matching Go bindings in this
// package. Run it after editing usid.c.
//
// The generated Go and object files are gitignored rather than committed,
// unlike this repo's other generated code: they embed a compiled binary blob,
// and a committed artifact can drift out of sync with usid.c with nothing short
// of a byte-diff to catch it. Every build site regenerates them, which the
// build, lint, and test tasks and both container builder stages all depend on,
// so clang must be on PATH or named by $BPF2GO_CC to build or test this module.
// There is no fallback to a checked-in copy.
//
// This package neither loads nor attaches the program. It exposes typed handles
// to the maps and program for the loader package and for this package's own
// tests.
//
// It sits beside internal/plumbing/ebpf/uformat, the pure-Go bit-layout library
// with no kernel dependency. The two share the same key-composition arithmetic
// deliberately, so the kernel program and the Go control plane cannot drift on
// bit positions.
package prog

// The -idirafter flags work around a clang quirk on Debian-style multiarch
// layouts: with a BPF target, clang's default header search drops
// /usr/include/<triple>, which exists for the host GNU target and not for the
// BPF virtual one, so <linux/bpf.h>'s own <asm/types.h> goes unresolved even
// though the libc headers are installed. Listing both supported architectures
// covers it, and -idirafter silently skips whichever is absent, so this is
// harmless on distributions that resolve these headers without a multiarch
// subdirectory.
//
// -cc is deliberately omitted: bpf2go defaults to $BPF2GO_CC or "clang", so CI
// can pin an exact version without this directive changing.
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cflags "-O2 -g -Wall -idirafter /usr/include/x86_64-linux-gnu -idirafter /usr/include/aarch64-linux-gnu" -target bpfel,bpfeb -type locator_value -type function_value -type vrf_value -type ifindex_vrf_value -type nptv6_value -type vip_xlat_key -type vip_xlat_value -type egress_route_key -type egress_route_value -type public_uplink_value Usid usid.c
