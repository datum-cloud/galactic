// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package cniipam implements galactic-ipam, the delegated CNI IPAM plugin
// in the galactic CNI chain (see github.com/containernetworking/cni/pkg/ipam
// for the delegation protocol both master plugins, galactic-veth and
// galactic-tap, invoke this through via ExecAdd/ExecDel/ExecCheck).
//
// Explicit contract: a master plugin delegates here if and only if its own
// "ipam" block is present at all — no environment variable or sibling
// config field can trigger or suppress that decision (that's the master's
// own call, made before this package is ever invoked). Once delegated to,
// mode selection is entirely this package's own, decided by which fields
// are present and rejected as a config error if they disagree:
//
//   - ipam.addresses — the addresses were decided upstream (Datum's
//     networking layer allocates an IPv6 endpoint block, typically a /96,
//     optionally an IPv4 /32, each with a gateway). Nothing is allocated:
//     every address is assigned exactly as given, prefix length included,
//     for both families, and nothing is persisted. Cannot be combined with
//     the fields below.
//   - ipam.static_ip — the legacy single-address path: one IPv6 address,
//     assigned with a /64, no IPv4. Superseded by ipam.addresses.
//   - ipam.ipv6_subnet/ipv4_subnet (either family alone, or both) — the
//     pool path: this package chooses the address.
//
// GALACTIC_IPAM_ENABLE_LOCAL_IPAM only fills in a default IPv6
// pool CIDR when the ipam block is present but specifies no addresses, no
// static_ip and no subnet — it can no longer manufacture an ipam block out
// of thin air the way its GALACTIC_CNI_ENABLE_LOCAL_IPAM predecessor did.
//
// Allocation state persists in on-disk marker files (internal/cni/ipam),
// keyed by containerID, so this package never needs a Kubernetes client
// at all: DEL looks its own allocation up locally instead of reading it
// back from a BGPAdvertisement CRD annotation galactic-bgp wrote. Only the
// pool path persists anything: an address decided elsewhere (addresses,
// static_ip) is validated at ADD and never stored, so DEL has nothing to
// release and CHECK nothing to verify.
package cniipam

import (
	"net"

	"github.com/containernetworking/cni/pkg/types"
)

// IPAM is the JSON shape of a CNI config's "ipam" block, as galactic-ipam
// itself parses it (the master plugins each embed the same shape as
// *IPAM in their own PluginConf, since the full netconf — including this
// block — is what gets passed through to the delegate unmodified).
type IPAM struct {
	// Type names the delegated binary (e.g. "galactic-ipam") — a CNI IPAM
	// delegation implementation detail (github.com/containernetworking/cni/
	// pkg/ipam.ExecAdd/ExecDel read this to know which binary to exec), not
	// a mode selector. Mode is decided from which of the fields below are
	// present instead — see the package doc comment.
	Type string `json:"type"`
	// StaticIP is the legacy single-address path: one IPv6 address, no
	// prefix length of its own, no IPv4. Addresses supersedes it.
	StaticIP   string `json:"static_ip,omitempty"`
	IPv6Subnet string `json:"ipv6_subnet,omitempty"`
	IPv4Subnet string `json:"ipv4_subnet,omitempty"`
	// AddressFamilies, when non-empty, restricts allocation to the listed
	// families ("ipv6"/"ipv4"): parseConf clears whichever of
	// IPv6Subnet/IPv4Subnet names an excluded family before allocate/
	// deallocate/checkAllocation ever see them. It only narrows whichever
	// pools are already configured — it can't widen allocation to a family
	// with no pool CIDR set. Empty means no restriction (allocate from every
	// configured pool, same as if this field didn't exist). Meaningless for
	// the static_ip and addresses paths, which carry exactly what they were
	// given regardless of this field.
	AddressFamilies []string `json:"address_families,omitempty"`
	// Routes is declared but not read by any allocation path.
	Routes []Route `json:"routes,omitempty"`
	// Addresses carries addresses decided outside galactic-ipam. Presence
	// selects the addresses path, which assigns exactly these -- both
	// families, prefix lengths preserved -- rather than allocating anything.
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

// IPAMResult holds the allocation details a master plugin uses to build
// its own CNI result and, for veth, to configure the guest interface.
// IPv4Address/IPv4Gateway are nil when the attachment is IPv6-only.
type IPAMResult struct {
	IPv6Subnet  *net.IPNet
	IPv6Gateway net.IP
	IPv4Address net.IP
	IPv4Gateway net.IP
	Routes      []*net.IPNet
}

// pluginConf is the full CNI config document galactic-ipam receives as
// args.StdinData — the same document the master plugin itself parsed,
// passed through unmodified per the IPAM delegation protocol. Only the
// "ipam" key (plus cniVersion, for result versioning) is ever read; the
// master-plugin-specific fields (vpc, vpcattachment, terminations, ...)
// are present in the JSON but simply ignored here.
type pluginConf struct {
	types.PluginConf
	IPAM *IPAM `json:"ipam"`
}
