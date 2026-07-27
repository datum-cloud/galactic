// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package vmtap

import (
	"fmt"

	"github.com/containernetworking/cni/pkg/types"
	type100 "github.com/containernetworking/cni/pkg/types/100"
	"github.com/vishvananda/netlink"
)

// buildResult copies prevResult forward (interfaces, IPs, routes — vmtap-cni
// is the last plugin in the chain, so its own result is what the CNI runtime
// hands back to the caller) and appends the tap device as a new interface
// entry.
//
// The tap's Sandbox field is set to containerID rather than a netns path —
// there is no netns for the VM the way there is for a container, so this
// plugin uses containerID (the CRI sandbox ID passed as CNI_CONTAINERID) as
// the hand-off key kraftlet is expected to read the CNI ADD result back out
// by. This convention is not yet confirmed against the actual kraftlet
// integration — see the "how kraftlet reads this plugin's result" open item
// in .local/kraftlet-cilium-tap-plan.md section 7.
//
// tapLink's MTU is expected to already equal the resolved route MTU (not
// eth0's link MTU) — see resolveRedirectInterface and the MTU caveat in
// docs/vmtap-cni/configuration.md — so no separate route-MTU field is
// needed: the tap's own Mtu communicates the corrected value.
func buildResult(conf *PluginConf, tapLink netlink.Link, containerID string) (*type100.Result, error) {
	prevResult, err := type100.GetResult(conf.PrevResult)
	if err != nil {
		return nil, fmt.Errorf("get prevResult: %w", err)
	}

	result := &type100.Result{
		CNIVersion: conf.CNIVersion,
		Interfaces: append([]*type100.Interface{}, prevResult.Interfaces...),
		IPs:        append([]*type100.IPConfig{}, prevResult.IPs...),
		Routes:     append([]*types.Route{}, prevResult.Routes...),
		DNS:        prevResult.DNS,
	}

	attrs := tapLink.Attrs()
	result.Interfaces = append(result.Interfaces, &type100.Interface{
		Name:    attrs.Name,
		Mac:     attrs.HardwareAddr.String(),
		Mtu:     attrs.MTU,
		Sandbox: containerID,
	})

	return result, nil
}
