// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cni

// IPAM is the static IPAM block embedded in the galactic plugin's CNI
// config. With BGP-driven dynamic routing, only Addresses are needed —
// the Routes field that previously pushed user-supplied prefixes into
// the kernel via IPAM has been removed.
type IPAM struct {
	Type      string    `json:"type"`
	Addresses []Address `json:"addresses,omitempty"`
}

type Address struct {
	Address string `json:"address"`
}
