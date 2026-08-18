// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cnibgp

import (
	"context"
	"log/slog"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	type100 "github.com/containernetworking/cni/pkg/types/100"

	"go.datum.net/galactic/internal/nadpatch"
)

// cmdDel deletes the per-pod EndpointSlice cmdAdd published, then falls
// through to the same no-op the rest of the chain's DEL paths follow for
// the BGPVRFInstance/BGPAdvertisement CRDs and eBPF vrf_table entry: those
// are keyed by (vpc, vpcAttachment) and may still be in use by another
// pod/VM sharing the same attachment, so deleting them here would race with
// a concurrent ADD during restarts — cleanup for those stays galactic-
// router's GC controller's job (see internal/cni's own cmdDel for the full
// reasoning, identical here).
//
// The EndpointSlice is a deliberate, correct divergence from that pattern:
// it's 1:1 with exactly one pod, never shared, so there's no "might belong
// to a live sibling" risk to avoid — see the #854 plan's Phase 5. Deletion
// is best-effort: any failure (including failing to build a k8s client at
// all) is logged and DEL still returns success, since a k8s API hiccup
// during pod teardown shouldn't block the pod from actually going away —
// Phase 8's ownerReference-to-Pod is the backstop for exactly this case.
func cmdDel(args *skel.CmdArgs) error {
	// DEL is idempotent per the CNI spec: always return success, even if
	// parsing the config fails — logging vpc/vpcAttachment (when parseable)
	// is the only reason to parse at all here, since there's no cleanup to
	// gate on it.
	pluginConf, parseErr := parseConf(args.StdinData)
	if parseErr != nil {
		slog.Error("DEL: failed to parse CNI config, skipping cleanup", "err", parseErr,
			"containerID", args.ContainerID)
		result := &type100.Result{}
		_ = types.PrintResult(result, "1.0.0")
		return nil
	}

	slog.Info("DEL: skipping shared resource cleanup (handled by GC)", "containerID", args.ContainerID,
		"vpc", pluginConf.VPC, "vpcAttachment", pluginConf.VPCAttachment)

	deleteEndpointSliceBestEffort(args, pluginConf.Namespace)

	result := &type100.Result{}
	_ = types.PrintResult(result, pluginConf.CNIVersion)
	return nil
}

// deleteEndpointSliceBestEffort deletes this pod's EndpointSlice, logging
// (never failing DEL) on any error — see cmdDel's own doc comment for why.
func deleteEndpointSliceBestEffort(args *skel.CmdArgs, namespace string) {
	podName := nadpatch.ParsePodName(args.Args)
	if podName == "" {
		slog.Debug("DEL: no K8S_POD_NAME in CNI_ARGS, nothing to delete",
			"containerID", args.ContainerID, "cniArgs", args.Args)
		return
	}

	k8sClient, err := newK8sClient()
	if err != nil {
		slog.Error("DEL: failed to create k8s client, EndpointSlice cleanup deferred to GC",
			"err", err, "containerID", args.ContainerID, "podName", podName)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), cniTimeout)
	defer cancel()
	if err := deleteEndpointSlice(ctx, k8sClient, namespace, podName); err != nil {
		slog.Error("DEL: failed to delete EndpointSlice, cleanup deferred to GC",
			"err", err, "containerID", args.ContainerID, "podName", podName, "namespace", namespace)
		return
	}
	slog.Info("DEL: EndpointSlice deleted", "containerID", args.ContainerID, "podName", podName, "namespace", namespace)
}
