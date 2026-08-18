// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package egressroutemap implements the read/write API for the eBPF uSID
// datapath's egress_route_table and node_src_addr_table maps
// (internal/plumbing/ebpf/prog/usid.c's struct egress_route_key/value and
// usid_egress's egress-routing extension) -- see
// docs/plans/tc-bpf-egress-srv6-encap.md for the mechanism this replaces
// (internal/plumbing/srv6's kernel-native SEG6 lwtunnel route
// encapsulation, confirmed broken by CVE-2026-31668 under this
// codebase's own per-tenant-VRF architecture) and why.
//
// Two callers, two processes, mirroring vipxlatmap's own precedent for
// exactly this shape: internal/runtime/gobgp/monitor.go
// (galactic-router, a long-lived daemon that never loads/attaches an
// eBPF program of its own) writes Register/Unregister entries as EVPN
// paths arrive and are withdrawn -- the same events that used to drive
// srv6.RouteEgressAdd/RouteEgressDel/RouteMainAdd/RouteMainDel -- and
// internal/cnibgp (galactic-cni, the process that actually loads and
// attaches usid_egress) writes this node's own SetNodeSourceAddress
// entry once, at datapath registration time, alongside its existing
// attachUsidEgress call.
package egressroutemap
