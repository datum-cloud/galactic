// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cni

type Termination struct {
	Network string `json:"network"`
	Via     string `json:"via,omitempty"`
}

type IPAM struct {
	Type      string    `json:"type"`                 // "pool" (default) or "static"
	Pool      string    `json:"pool,omitempty"`       // IPv6 CIDR pool, e.g. "fd00:10:ff01::/48"
	Gateway   string    `json:"gateway,omitempty"`    // IPv6 gateway address
	SubnetLen int       `json:"subnet_len,omitempty"` // prefix length per allocation (default 80)
	StaticIP  string    `json:"static_ip,omitempty"`  // used when type="static"
	Routes    []Route   `json:"routes,omitempty"`
	Addresses []Address `json:"addresses,omitempty"`
}

type Route struct {
	Dst string `json:"dst"`
	GW  string `json:"gw,omitempty"`
}

type Address struct {
	Address string `json:"address"`
}
