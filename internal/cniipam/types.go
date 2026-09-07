// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package cniipam implements galactic-ipam, the delegated CNI IPAM plugin in
// the galactic chain, which both master plugins invoke through the standard
// delegation protocol.
//
// A master plugin delegates here if and only if its own "ipam" block is
// present; no environment variable or sibling field can trigger or suppress
// that. Once delegated to, mode selection belongs entirely to this package,
// decided by which fields are present and rejected as a config error if they
// disagree:
//
//   - ipam.addresses: the addresses were decided upstream. Nothing is
//     allocated; every address is assigned exactly as given, prefix length
//     included, for both families, and nothing is persisted. Cannot be
//     combined with the fields below.
//   - ipam.static_ip: one IPv6 address assigned with a /64 and no IPv4.
//     Superseded by ipam.addresses.
//   - ipam.ipv6_subnet and ipam.ipv4_subnet, either alone or together: the
//     pool path, where this package chooses the address.
//
// The local-IPAM environment flag only fills in a default IPv6 pool CIDR when
// the ipam block is present but names no addresses, no static address, and no
// subnet. It cannot manufacture an ipam block.
//
// Allocation state persists in on-disk marker files keyed by container ID, so
// this package needs no Kubernetes client: DEL looks its own allocation up
// locally rather than reading it back from a CRD annotation. Only the pool path
// persists anything; an address decided elsewhere is validated at ADD and never
// stored, so DEL has nothing to release and CHECK nothing to verify.
package cniipam

import (
	"net"

	"github.com/containernetworking/cni/pkg/types"
)

// IPAM is the JSON shape of a CNI config's "ipam" block. The master plugins
// embed the same shape, since the full netconf including this block is passed
// through to the delegate unmodified.
type IPAM struct {
	// Type names the delegated binary, which the delegation protocol reads to
	// know what to exec. It is not a mode selector: mode is decided from which
	// of the fields below are present.
	Type string `json:"type"`
	// StaticIP is the legacy single-address path: one IPv6 address, no
	// prefix length of its own, no IPv4. Addresses supersedes it.
	StaticIP   string `json:"static_ip,omitempty"`
	IPv6Subnet string `json:"ipv6_subnet,omitempty"`
	IPv4Subnet string `json:"ipv4_subnet,omitempty"`
	// AddressFamilies, when non-empty, restricts allocation to the listed
	// families: whichever subnet names an excluded family is cleared before
	// allocation ever sees it. It only narrows the pools already configured and
	// cannot widen allocation to a family with no pool set. Empty means no
	// restriction. Meaningless for the static and upstream-decided paths, which
	// carry what they were given regardless.
	AddressFamilies []string `json:"address_families,omitempty"`
	// Routes is declared but not read by any allocation path.
	Routes []Route `json:"routes,omitempty"`
	// Addresses carries addresses decided outside this plugin. Its presence
	// selects the path that assigns exactly these, both families with prefix
	// lengths preserved, rather than allocating anything.
	Addresses []Address `json:"addresses,omitempty"`
}

// Route describes a static route to install.
type Route struct {
	Dst string `json:"dst"`
	GW  string `json:"gw,omitempty"`
}

// Address is one pre-decided address in CIDR form (an explicit prefix length
// is required) with the gateway reachability through it depends on.
type Address struct {
	Address string `json:"address"`
	Gateway string `json:"gateway,omitempty"`
}

// IPAMResult holds the allocation details a master plugin uses to build its CNI
// result and, for veth, to configure the guest interface. The IPv4 fields are
// nil on an IPv6-only attachment.
type IPAMResult struct {
	IPv6Subnet  *net.IPNet
	IPv6Gateway net.IP
	IPv4Address net.IP
	IPv4Gateway net.IP
	Routes      []*net.IPNet
}

// pluginConf is the full CNI config document this plugin receives on stdin, the
// same one the master plugin parsed, passed through unmodified. Only the "ipam"
// key and the CNI version are read; the master-plugin fields are present in the
// JSON and ignored.
type pluginConf struct {
	types.PluginConf
	IPAM *IPAM `json:"ipam"`
}
