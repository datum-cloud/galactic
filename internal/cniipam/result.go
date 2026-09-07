// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cniipam

import (
	"encoding/json"
	"fmt"
	"net"

	"github.com/containernetworking/cni/pkg/types"
	type100 "github.com/containernetworking/cni/pkg/types/100"
)

// BuildCNIResult constructs the result IPAM delegation returns: addresses and
// routes only, no interfaces. The master plugin owns interface creation
// entirely, and keeping interfaces out of this result is what delegation exists
// to enforce.
func BuildCNIResult(cniVersion string, res *IPAMResult) *type100.Result {
	result := &type100.Result{CNIVersion: cniVersion}
	if res == nil {
		return result
	}
	if res.IPv6Subnet != nil {
		result.IPs = append(result.IPs, &type100.IPConfig{
			Address: *res.IPv6Subnet,
			Gateway: res.IPv6Gateway,
		})
	}
	if res.IPv4Address != nil {
		result.IPs = append(result.IPs, &type100.IPConfig{
			Address: net.IPNet{IP: res.IPv4Address, Mask: net.CIDRMask(32, 32)},
			Gateway: res.IPv4Gateway,
		})
	}
	for _, r := range res.Routes {
		result.Routes = append(result.Routes, &types.Route{Dst: *r})
	}
	return result
}

// ResultToIPAMResult converts a CNI result, as returned to a master plugin that
// just delegated an ADD, into the local shape callers apply directly.
//
// It marshals and re-parses rather than type-asserting, since the concrete type
// returned depends on CNI version negotiation.
func ResultToIPAMResult(res types.Result) (*IPAMResult, error) {
	jsonBytes, err := json.Marshal(res)
	if err != nil {
		return nil, fmt.Errorf("marshal IPAM result: %w", err)
	}
	parsed, err := type100.NewResult(jsonBytes)
	if err != nil {
		return nil, fmt.Errorf("parse IPAM result: %w", err)
	}
	versioned, err := type100.GetResult(parsed)
	if err != nil {
		return nil, fmt.Errorf("get IPAM result: %w", err)
	}

	r := &IPAMResult{}
	for _, ipConf := range versioned.IPs {
		if ipConf.Address.IP.To4() != nil {
			r.IPv4Address = ipConf.Address.IP
			r.IPv4Gateway = ipConf.Gateway
			continue
		}
		subnet := ipConf.Address
		r.IPv6Subnet = &subnet
		r.IPv6Gateway = ipConf.Gateway
	}
	for _, rt := range versioned.Routes {
		dst := rt.Dst
		r.Routes = append(r.Routes, &dst)
	}
	return r, nil
}
