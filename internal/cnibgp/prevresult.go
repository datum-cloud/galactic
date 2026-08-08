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

// inferFromPrevResult reconstructs the ipamResult and infers whether the
// preceding master plugin created a veth or tap interface, both from
// rawPrevResult — the raw JSON form of the CNI chain's accumulated result
// so far (PluginConf.RawPrevResult; the typed PluginConf.PrevResult field
// is never populated by plain JSON unmarshal, per its "json:\"-\"" tag —
// ops_check.go elsewhere in this repo already reads prevResult the same,
// correct way).
//
// galactic-bgp has no kernel-interface access or IPAM knowledge of its own
// — this is the only way it learns either. Interface-kind inference: a
// veth master's own result declares two interfaces (host + guest, the
// guest carrying a non-empty sandbox); a tap master's declares exactly one
// (host only, empty sandbox) — see the design note's "Split the veth/tap
// master into two binaries" section for why this is inferable from shape
// alone, with no interface_type field anywhere in the chain.
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

	switch len(versioned.Interfaces) {
	case 1:
		ifaceType = ifaceTypeTap
	case 2:
		ifaceType = ifaceTypeVeth
	default:
		return "", nil, nil, fmt.Errorf(
			"prevResult declares %d interfaces, want 1 (tap master) or 2 (veth master)", len(versioned.Interfaces))
	}

	ipamResult, err = cniipam.ResultToIPAMResult(parsed)
	if err != nil {
		return "", nil, nil, fmt.Errorf("convert prevResult IPs: %w", err)
	}
	if ipamResult.IPv6Subnet == nil && ipamResult.IPv4Address == nil {
		// No IPAM allocation at all (e.g. a tap workload managing its own
		// addressing) — nil, not a zero-value result, matches what every
		// other caller in this chain already treats as "no IPAM."
		ipamResult = nil
	}
	return ifaceType, ipamResult, parsed, nil
}
