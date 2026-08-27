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
// type100.NewResult only accepts a Result whose own CNIVersion field is
// exactly "1.0.0" or "1.1.0" (github.com/containernetworking/cni's
// pkg/types/100 supportedVersions) — and the master plugin's printed Result
// carries the conflist's own cniVersion value verbatim (buildResult/
// buildTapResult set CNIVersion: pluginConf.CNIVersion), not a value this
// plugin controls. A conflist authored with an older cniVersion (e.g.
// "0.4.0") therefore fails ADD here for every attachment in the chain. This
// is a real, hard requirement on every conflist in this repo's CNI chain —
// see docs/cni/conflist-reference.md's cniVersion paragraph — not just an
// implementation detail of this function.
//
// galactic-bgp has no kernel-interface access or IPAM knowledge of its own
// — this is the only way it learns either. Interface-kind inference: a
// veth master's own result declares one interface with a non-empty Sandbox
// (the guest end, moved into the container netns — see internal/cni/
// result.go's buildResult); a tap master's declares zero (the tap device
// stays on the host — internal/cnitap/result.go's buildTapResult). This
// counts Sandbox-carrying interfaces rather than len(Interfaces) itself,
// on purpose: #306 chains galactic-route into this same prevResult next,
// and total interface count is not this plugin's to own — if anything
// appended later adds a host-side interface entry of its own, a raw count
// would silently reclassify a tap master as veth (or vice versa) instead
// of failing loudly, because both 1 and 2 are valid switch cases. Whether
// an interface was moved into the container's netns is the actual property
// that distinguishes veth from tap, not how many entries happen to be in
// the slice — see the design note's "Split the veth/tap master into two
// binaries" section for why no interface_type field exists anywhere in the
// chain to make this explicit instead.
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
		// No IPAM allocation at all (e.g. a tap workload managing its own
		// addressing) — nil, not a zero-value result, matches what every
		// other caller in this chain already treats as "no IPAM."
		ipamResult = nil
	}
	return ifaceType, ipamResult, parsed, nil
}
