// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package plumbing provides the low-level kernel and network primitives the
// galactic binaries share. It holds no code of its own; the sub-packages cover
// SRv6 encoding and interface naming (intf, srv6), Linux VRF lifecycle (vrf),
// interface sysctls (sysctl), bonding-master recognition (bond), loopback
// address detection (loaddr), stateless prefix translation (nptv6), Router
// Advertisements for tap-attached guests (radv), VIP binding on backend nodes
// (vip), and the eBPF datapaths (ebpf).
//
// Anything requiring CAP_NET_ADMIN or a real kernel is not unit-tested; the
// end-to-end suite covers it.
package plumbing
