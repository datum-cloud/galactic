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
	"go.datum.net/galactic/internal/podslice"
)

// cmdDel releases what this container's ADD published: its per-pod
// EndpointSlice, and its entry on this node's BGPAdvertisement for the
// attachment, deleting the advertisement once no container it records is
// still alive (releaseAdvertisement). A replacement container on this node
// whose ADD ran first keeps the advertisement. The BGPVRFInstance and the
// vrf_table entry are shared by every attachment on this VPC on this node, so
// reclaiming them stays garbage collection's job, as does anything a DEL that
// never ran leaves behind.
//
// The EndpointSlice is still shared across a pod's sandboxes, so DEL deletes
// it only when this sandbox wrote it.
//
// Deletion is best-effort, and any failure, including failing to build a
// client at all, is logged while DEL still returns success: an API hiccup
// during teardown must not block the pod from going away. GC is the backstop
// for exactly that case.
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

	deleteEndpointSliceBestEffort(args)
	releaseAdvertisementBestEffort(args, pluginConf.Namespace, pluginConf.VPC, pluginConf.VPCAttachment)

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
	deleted, err := podslice.Delete(ctx, k8sClient, podNamespace, podName, args.ContainerID)
	if err != nil {
		slog.Error("DEL: failed to delete EndpointSlice, cleanup deferred to GC",
			"err", err, "containerID", args.ContainerID, "podName", podName, "podNamespace", podNamespace)
		return
	}
	if !deleted {
		slog.Info("DEL: EndpointSlice absent or written by another sandbox, left in place",
			"containerID", args.ContainerID, "podName", podName, "podNamespace", podNamespace)
		return
	}
	slog.Info("DEL: EndpointSlice deleted",
		"containerID", args.ContainerID, "podName", podName, "podNamespace", podNamespace)
}

// releaseAdvertisementBestEffort releases this container's entry on this
// node's advertisement for the attachment (releaseAdvertisement), logging
// rather than failing DEL on any error.
func releaseAdvertisementBestEffort(args *skel.CmdArgs, namespace, vpc, vpcAttachment string) {
	if cniConfig == nil || cniConfig.NodeName == "" {
		slog.Warn("DEL: no node name, advertisement cleanup deferred to GC", "containerID", args.ContainerID)
		return
	}
	k8sClient, err := newK8sClient()
	if err != nil {
		slog.Error("DEL: failed to create k8s client, advertisement cleanup deferred to GC",
			"err", err, "containerID", args.ContainerID)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), cniTimeout)
	defer cancel()
	if err := releaseAdvertisement(ctx, k8sClient, namespace, vpc, vpcAttachment, cniConfig.NodeName,
		args.ContainerID); err != nil {
		slog.Error("DEL: failed to release advertisement, cleanup deferred to GC", "err", err,
			"containerID", args.ContainerID, "vpc", vpc, "vpcAttachment", vpcAttachment)
		return
	}
	slog.Info("DEL: released advertisement", "containerID", args.ContainerID,
		"vpc", vpc, "vpcAttachment", vpcAttachment)
}
