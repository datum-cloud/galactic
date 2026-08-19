// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package prog holds the compiled TC-BPF program that implements the
// `uFMT 48+16` uSID decode/forward datapath (design plan
// .local/plan-ebpf-xdp-usid-datapath.md §4.2/§4.4; Milestone 2.2 of
// .local/implementation-plan-ebpf-xdp-usid-datapath.md).
//
// usid.c is the single source of truth for the packet path; see its
// header comment for the full 9-step walkthrough. `go generate` (via
// bpf2go, github.com/cilium/ebpf's code generator) compiles it with clang
// into a CO-RE-portable BPF object and generates matching Go bindings
// (UsidObjects, LoadUsid, LoadUsidObjects, plus per-map/per-program
// fields) in this package -- run `go generate ./...` from the repo root,
// or `go generate` from this directory, after editing usid.c.
//
// Unlike this repo's other generated code (e.g. *.pb.go, committed
// per CLAUDE.md: "Generated protobuf files ... are committed; never
// hand-edit them"), the generated *_bpfel.go/*_bpfel.o and
// *_bpfeb.go/*_bpfeb.o files are gitignored, not committed: they embed a
// compiled binary blob rather than plain Go source, and committing a
// compiled artifact risks it silently drifting out of sync with usid.c
// with nothing to catch the mismatch short of a byte-diff. Instead, every
// build site regenerates them fresh via `task build:ebpf` -- a hard
// dependency of `task build`/`lint`/`test:unit`/`test:unit-root`/`test:e2e`
// (see Taskfile.yaml), and of containers/galactic-cni/Dockerfile and
// containers/galactic-router/Dockerfile's builder stages -- so clang must
// be on PATH (or $BPF2GO_CC) to build or test this module at all; there is
// no fallback to a checked-in copy.
//
// Placement: sibling of internal/plumbing/ebpf/uformat (Milestone 2.1)
// under the shared internal/plumbing/ebpf/ umbrella -- uformat is the
// pure-Go bit-layout library with no kernel dependency; this package is
// the compiled BPF program itself. The two intentionally share the exact
// same key-composition arithmetic (locator_key = top 8 bytes of the
// address as-is; function_key = Block<<4|Function; vrf_key =
// Block<<12|Argument) so the kernel program and the Go control plane
// (Milestone 3.x, which will populate these maps) can never drift on bit
// positions -- see usid.c's map-key comment block for the details.
//
// This package does not itself load or attach the compiled program to any
// interface -- that is Milestone 3.1's job (extending galactic-cni's `run`
// subcommand). This package only builds the object and exposes typed Go
// handles to its maps and program, via bpf2go's generated loader
// functions, for that later milestone (and this milestone's own
// BPF_PROG_TEST_RUN-based tests) to use.
package prog

// The -idirafter flags below work around a clang quirk specific to
// Debian/Ubuntu-style multiarch layouts (confirmed via the `build` job's
// real run of this directive in .github/workflows/ci.yaml, on
// ubuntu-latest): with `-target bpfel`/`bpfeb`, clang's default header
// search list drops `/usr/include/<triple>` (present for the host GNU
// target, absent for the BPF virtual target), so `<linux/bpf.h>`'s own
// `<asm/types.h>` include goes unresolved even though
// `linux-libc-dev`/`libc6-dev` did install it -- just not somewhere the
// BPF target's search path looks. Listing both the amd64 and arm64
// multiarch directories explicitly covers this repo's two supported
// architectures; -idirafter silently skips whichever one doesn't exist on
// the host, so this is harmless on non-Debian systems (Fedora, Alpine,
// macOS) that resolve these headers without any multiarch subdirectory.
//
// -cc is deliberately omitted: bpf2go's own default is
// getEnv("BPF2GO_CC", "clang"), so CI can pin an exact clang version by
// setting $BPF2GO_CC (see .github/workflows/ci.yaml) without this
// directive needing to change, while everyone else keeps getting plain
// "clang" off their PATH.
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cflags "-O2 -g -Wall -idirafter /usr/include/x86_64-linux-gnu -idirafter /usr/include/aarch64-linux-gnu" -target bpfel,bpfeb -type locator_value -type function_value -type vrf_value -type ifindex_vrf_value -type nptv6_value -type vip_xlat_key -type vip_xlat_value -type egress_route_key -type egress_route_value -type public_uplink_value Usid usid.c
