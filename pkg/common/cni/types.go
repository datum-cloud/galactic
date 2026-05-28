// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cni

type Termination struct {
	Network string `json:"network"`
	Via     string `json:"via,omitempty"`
}

// GoBGPConfig holds the address of the local GoBGP gRPC API.
type GoBGPConfig struct {
	Address string `json:"address,omitempty"`
}

// AddressOrDefault returns the configured address or the node-local default.
func (c GoBGPConfig) AddressOrDefault() string {
	if c.Address == "" {
		return "127.0.0.1:50051"
	}
	return c.Address
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
