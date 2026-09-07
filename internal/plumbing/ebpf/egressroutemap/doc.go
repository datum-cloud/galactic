// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package egressroutemap implements the read/write API for the eBPF uSID
// datapath's egress_route_table, node_src_addr_table, and public_uplink_table
// maps, which together drive usid_egress's encapsulation.
//
// It replaces kernel SEG6 lwtunnel route encapsulation, which is unusable under
// per-tenant VRFs: the lwtunnel reuses one route cache across the input and
// output resolution paths, whose routing contexts differ once every tenant has
// its own VRF.
//
// Two callers in two processes. The router, a long-lived daemon that never
// loads a program of its own, registers and unregisters route entries as EVPN
// paths arrive and are withdrawn. The CNI side, which does load and attach
// usid_egress, writes this node's source address and uplink entries at datapath
// registration time.
package egressroutemap
