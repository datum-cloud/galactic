// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package xdpattach attaches a native XDP program to a list of interfaces
// without taking a bonded uplink down in the process.
//
// It is the attach step both XDP datapaths share: the edge gateway's
// (internal/plumbing/ebpf/edgeattach) and the egress shard's
// (internal/plumbing/ebpf/natattach). Each resolves its own targets, a bonding
// master always expanded to its slaves, and hands the list here. See gate.go
// for why attaching to a bond slave needs care that attaching to an ordinary
// interface does not.
//
// Native mode is required, not preferred. Attach always requests driver mode
// and returns an error rather than silently retrying in generic mode, which has
// materially different performance characteristics.
package xdpattach
