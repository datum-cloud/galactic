// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cnibgp

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"

	"go.datum.net/galactic/internal/plumbing/intf"
)

// cmdAdd is galactic-bgp's own ADD: the last (per the design note's sample
// conflists) plugin in the chain, publishing SRv6/BGP/eBPF state for
// whatever the master plugin already created. It never touches a kernel
// interface — everything it needs (which interface kind, which addresses)
// comes from prevResult (see prevresult.go).
func cmdAdd(args *skel.CmdArgs) (err error) {
	pluginConf, err := parseConf(args.StdinData)
	if err != nil {
		return err
	}

	ifaceType, ipamResult, prevResult, err := inferFromPrevResult(pluginConf.RawPrevResult)
	if err != nil {
		return &types.Error{Code: 6, Msg: fmt.Sprintf("infer from prevResult: %v", err)}
	}

	nodeName := cniConfig.NodeName
	namespace := pluginConf.Namespace

	slog.Info("ADD: starting", "containerID", args.ContainerID,
		"vpc", pluginConf.VPC, "vpcAttachment", pluginConf.VPCAttachment,
		"ifaceType", ifaceType, "namespace", namespace, "nodeName", nodeName)

	tracker := &resourceTracker{
		vpc:           pluginConf.VPC,
		vpcAttachment: pluginConf.VPCAttachment,
		nodeName:      nodeName,
		namespace:     namespace,
	}

	rollbackCtx, rollbackCancel := context.WithTimeout(context.Background(), cniTimeout)
	defer func() {
		if err != nil {
			slog.Error("ADD: failed, rolling back created resources", "err", err,
				"containerID", args.ContainerID, "vpc", pluginConf.VPC, "vpcAttachment", pluginConf.VPCAttachment)
			tracker.cleanup(rollbackCtx)
			rollbackCancel()
		}
	}()

	k8sClient, err := newK8sClient()
	if err != nil {
		return fmt.Errorf("create k8s client: %w", err)
	}
	tracker.k8s = k8sClient

	vpcHex, err := intf.Base62ToHex(pluginConf.VPC)
	if err != nil {
		return fmt.Errorf("decode VPC: %w", err)
	}

	cfg := publishConfig{vpc: pluginConf.VPC, vpcAttachment: pluginConf.VPCAttachment, ifaceType: ifaceType}
	result, err := publishBGPState(args, cfg, nodeName, namespace, ipamResult, vpcHex, k8sClient)
	tracker.advertisementCreated = result.advertisementCreated
	tracker.vrfInstanceCreated = result.vrfInstanceCreated
	if err != nil {
		return err
	}

	// Pass prevResult through unchanged: this plugin adds no new interfaces
	// or IPs of its own, so its own CNI result is exactly what it received.
	// Per the design note's sample conflists, galactic-bgp is the last
	// plugin in the chain, so this becomes the runtime's authoritative
	// result for the ADD.
	return types.PrintResult(prevResult, pluginConf.CNIVersion)
}
