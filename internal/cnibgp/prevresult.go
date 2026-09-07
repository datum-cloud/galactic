// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cnibgp

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/containernetworking/cni/pkg/types"
	type100 "github.com/containernetworking/cni/pkg/types/100"

	"go.datum.net/galactic/internal/cniipam"
)

// inferFromPrevResult reconstructs the IPAM result and infers whether the
// preceding master plugin created a veth or a tap, both from rawPrevResult, the
// raw JSON of the chain's accumulated result so far. The typed field is never
// populated by a plain unmarshal, so the raw form is the one to read.
//
// This plugin has no kernel-interface access or IPAM knowledge of its own, so
// this is the only way it learns either.
//
// Result parsing accepts only the current CNI result versions, and the master
// plugin's printed result carries the conflist's version verbatim rather than
// one this plugin controls. A conflist authored with an older version therefore
// fails ADD here for every attachment in the chain. That is a hard requirement
// on every conflist in this chain, not an implementation detail.
//
// Interface-kind inference: a veth master's result declares one interface with a
// non-empty sandbox, the guest end moved into the container namespace, while a
// tap master's declares none, the device staying on the host.
//
// It counts sandbox-carrying interfaces rather than interfaces outright, on
// purpose. Another plugin chained after this one may append a host-side entry,
// and a raw count would then silently reclassify a tap master as veth, or the
// reverse, instead of failing loudly, both counts being valid cases. Whether an
// interface was moved into the container's namespace is the property that
// actually distinguishes the two.
func inferFromPrevResult(
	rawPrevResult map[string]interface{},
) (ifaceType string, ipamResult *cniipam.IPAMResult, parsed types.Result, err error) {
	if rawPrevResult == nil {
		return "", nil, nil, errors.New("no prevResult: galactic-bgp must be chained after a master plugin")
	}

	jsonBytes, err := json.Marshal(rawPrevResult)
	if err != nil {
		return "", nil, nil, fmt.Errorf("marshal prevResult: %w", err)
	}
	parsed, err = type100.NewResult(jsonBytes)
	if err != nil {
		return "", nil, nil, fmt.Errorf("parse prevResult: %w", err)
	}
	versioned, err := type100.GetResult(parsed)
	if err != nil {
		return "", nil, nil, fmt.Errorf("get prevResult: %w", err)
	}

	if len(versioned.Interfaces) == 0 {
		return "", nil, nil, errors.New("prevResult declares no interfaces")
	}

	var sandboxed int
	for _, iface := range versioned.Interfaces {
		if iface.Sandbox != "" {
			sandboxed++
		}
	}
	switch sandboxed {
	case 0:
		ifaceType = ifaceTypeTap
	case 1:
		ifaceType = ifaceTypeVeth
	default:
		return "", nil, nil, fmt.Errorf(
			"prevResult declares %d interfaces with a non-empty Sandbox, want 0 (tap master) or 1 (veth master)",
			sandboxed)
	}

	ipamResult, err = cniipam.ResultToIPAMResult(parsed)
	if err != nil {
		return "", nil, nil, fmt.Errorf("convert prevResult IPs: %w", err)
	}
	if ipamResult.IPv6Subnet == nil && ipamResult.IPv4Address == nil {
		// No IPAM allocation at all, as for a tap workload managing its own
		// addressing. Nil rather than a zero-value result, matching what
		// every other caller in this chain treats as no IPAM.
		ipamResult = nil
	}
	return ifaceType, ipamResult, parsed, nil
}
