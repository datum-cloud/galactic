// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package xmitdrops counts XDP redirects that the kernel fails after the
// redirecting program has returned, which no counter inside an XDP program can
// see. xmitdrops.c attaches to the xdp_redirect_err and xdp_devmap_xmit
// tracepoints and counts the dropped frames by target interface, stage and
// errno.
//
// The common case is a redirect to an interface that cannot take an XDP frame:
// a driver with no ndo_xdp_xmit, such as a bridge, dummy or tunnel device, or
// a veth whose peer has neither an XDP program nor GRO. A route change can
// steer forwarded traffic onto such an interface, and every frame sent there
// is lost while the redirecting program reports success.
//
// The tracepoints fire in every network namespace and name no reliable owner.
// The counts cover every XDP program that redirects to an interface in the
// network namespace Attach runs in, not only the caller's.
//
// The counter is absent on kernels whose xdp_redirect_err tracepoint layout
// predates map_type: Attach fails with an unsupported-layout error and the
// gateway logs the attach warning.
//
// As with the other datapath packages, `go generate` compiles xmitdrops.c and
// writes the Go bindings, which are gitignored rather than committed.
package xmitdrops

// See the uSID program package's doc.go for why the include flags list both
// multiarch directories and why the compiler is not named explicitly.
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cflags "-O2 -g -Wall -idirafter /usr/include/x86_64-linux-gnu -idirafter /usr/include/aarch64-linux-gnu" -target bpfel,bpfeb -type xmit_drop_key -type xmit_cfg Xmitdrops xmitdrops.c
