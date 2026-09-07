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

// cmdDel deletes the per-pod EndpointSlice the ADD path published, then falls
// through to the same no-op the rest of the chain's DEL paths follow for the BGP
// CRDs and the vrf_table entry. Those are keyed by attachment and may still be
// in use by another pod sharing it, so deleting them here would race a
// concurrent ADD during a restart; that cleanup stays garbage collection's job.
//
// The EndpointSlice is a deliberate divergence: it is one per pod and never
// shared, so there is no live sibling to endanger. Deletion is best-effort, and
// any failure, including failing to build a client at all, is logged while DEL
// still returns success: an API hiccup during teardown must not block the pod
// from going away. The owner reference is the backstop for exactly that case.
func cmdDel(args *skel.CmdArgs) error {
	// DEL is idempotent per the CNI spec and always returns success, even when
	// the config fails to parse. Parsing exists only to log the identifiers when
	// they are available; no cleanup is gated on it.
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

	deleteEndpointSliceBestEffort(args)

	result := &type100.Result{}
	_ = types.PrintResult(result, pluginConf.CNIVersion)
	return nil
}

// deleteEndpointSliceBestEffort deletes this pod's EndpointSlice, logging
// rather than failing DEL on any error. The slice lives in the pod's own
// namespace, not the one holding the BGP CRDs, which this path deliberately
// leaves alone.
func deleteEndpointSliceBestEffort(args *skel.CmdArgs) {
	podName := nadpatch.ParsePodName(args.Args)
	podNamespace := nadpatch.ParsePodNamespace(args.Args)
	if podName == "" || podNamespace == "" {
		slog.Debug("DEL: no K8S_POD_NAME/K8S_POD_NAMESPACE in CNI_ARGS, nothing to delete",
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
	if err := deleteEndpointSlice(ctx, k8sClient, podNamespace, podName); err != nil {
		slog.Error("DEL: failed to delete EndpointSlice, cleanup deferred to GC",
			"err", err, "containerID", args.ContainerID, "podName", podName, "namespace", podNamespace)
		return
	}
	slog.Info("DEL: EndpointSlice deleted", "containerID", args.ContainerID, "podName", podName, "namespace", podNamespace)
}
