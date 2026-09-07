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

	"go.datum.net/galactic/internal/nadpatch"
	"go.datum.net/galactic/internal/plumbing/intf"
)

// cmdAdd is this plugin's ADD: the last in the chain, publishing SRv6, BGP, and
// eBPF state for whatever the master plugin created. It never touches a kernel
// interface; everything it needs comes from the previous result.
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

	defer func() {
		if err != nil {
			slog.Error("ADD: failed, rolling back created resources", "err", err,
				"containerID", args.ContainerID, "vpc", pluginConf.VPC, "vpcAttachment", pluginConf.VPCAttachment)
			// A fresh context, rather than one created up front and shared
			// with the work that just failed. The publish path's retries
			// can burn tens of seconds, each on its own fresh timeout, so
			// a context created before that call could already be expired
			// here and the delete would fail with a deadline error rather
			// than not-found. That is not treated as an ignorable
			// not-found, so the just-created CRDs would leak.
			//
			// Giving rollback its own full budget, on the failure path
			// only, also means a successful ADD never allocates a context
			// it does not use.
			rollbackCtx, rollbackCancel := context.WithTimeout(context.Background(), cniTimeout)
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
	tracker.publishResult = result
	if err != nil {
		return err
	}

	// The EndpointSlice publish is a separate step after the CRDs succeed,
	// rather than folded into their retry closure. No IPAM result, or one with
	// no IPv6 address, is the same "nothing to publish" skip the SRv6
	// registration already makes: not an error, and not specific to tap
	// workloads.
	if ipamResult != nil && ipamResult.IPv6Subnet != nil {
		podName := nadpatch.ParsePodName(args.Args)
		// The EndpointSlice goes in the pod's own namespace, distinct from the
		// one holding the BGP CRDs, which is very often different.
		podNamespace := nadpatch.ParsePodNamespace(args.Args)
		if podName == "" || podNamespace == "" {
			return fmt.Errorf(
				"publish EndpointSlice: no K8S_POD_NAME/K8S_POD_NAMESPACE in CNI_ARGS %q", args.Args)
		}
		esCtx, esCancel := context.WithTimeout(context.Background(), cniTimeout)
		esErr := publishEndpointSlice(
			esCtx, k8sClient, podNamespace, podName, pluginConf.VPC, pluginConf.VPCAttachment,
			ipamResult.IPv6Subnet.IP, result.sid,
		)
		esCancel()
		if esErr != nil {
			return fmt.Errorf("publish EndpointSlice: %w", esErr)
		}
	}

	// Pass the previous result through unchanged: this plugin adds no interfaces
	// or addresses of its own. Being last in the chain, this becomes the
	// runtime's authoritative result for the ADD.
	return types.PrintResult(prevResult, pluginConf.CNIVersion)
}
