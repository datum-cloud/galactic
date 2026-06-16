// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cni

type Termination struct {
	Network string `json:"network"`
	Via     string `json:"via,omitempty"`
}

type IPAM struct {
	Type      string    `json:"type"`
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
