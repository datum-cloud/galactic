// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package xdpattach attaches an XDP program to a list of interfaces without
// taking a bonded uplink down in the process.
//
// It is the attach step both XDP datapaths share: the edge gateway's
// (internal/plumbing/ebpf/edgeattach) and the egress shard's
// (internal/plumbing/ebpf/natattach). Each resolves its own targets, a bonding
// master always expanded to its slaves, and hands the list here. See gate.go
// for why attaching to a bond slave needs care that attaching to an ordinary
// interface does not.
//
// Every attach is in the one mode the caller passes, the host's mode from
// internal/plumbing/ebpf/xdpmode: native (driver) mode, or generic (SKB) mode
// on a host with a bnxt_en NIC. An attach that fails returns an error rather
// than retrying in the other mode, which has materially different performance
// characteristics. Coverage is read back from the kernel, so an interface
// holding the program in the other mode counts as uncovered.
package xdpattach
