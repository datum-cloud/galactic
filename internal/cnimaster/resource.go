// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cnimaster

import (
	"fmt"
	"log/slog"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	bgpv1alpha1 "go.datum.net/network/api/v1alpha1"
)

// NADPatchTimeout bounds the NAD-annotation patch call each master plugin
// makes with the k8s client from NewK8sClient, right after creating it —
// veth's and tap's own ADD both use the same budget.
const NADPatchTimeout = 10 * time.Second

var scheme = runtime.NewScheme()

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	// bgpv1alpha1 is registered even though neither master plugin reads or
	// writes BGP CRDs itself (that's galactic-bgp's own, chain-invoked
	// concern now) — kept here only because nothing else needs its own
	// scheme, and NAD annotation's unstructured.Unstructured Patch call
	// doesn't require any scheme registration at all. Harmless to leave;
	// trim if this scheme ever needs to shrink for another reason.
	utilruntime.Must(bgpv1alpha1.AddToScheme(scheme))
}

// NewK8sClient creates a new Kubernetes client using the in-cluster config.
// The only k8s call either master plugin makes directly is the NAD
// annotation patch.
func NewK8sClient() (client.Client, error) {
	restCfg, err := ctrl.GetConfig()
	if err != nil {
		return nil, fmt.Errorf("get kubeconfig: %w", err)
	}
	c, err := client.New(restCfg, client.Options{Scheme: scheme})
	if err != nil {
		return nil, fmt.Errorf("create k8s client: %w", err)
	}
	return c, nil
}

// CleanupAttachment rolls back a failed ADD's host-side interface for
// selective rollback. Errors are logged but never returned — the caller
// already has a failure to report.
//
// ifaceKind names the interface kind for log messages ("veth", "tap"); del
// removes the attachment's own host/guest interface pair.
//
// Deliberately absent: deleting the VRF. The VRF is shared by every
// attachment on this VPC on this node (internal/plumbing/vrf keys it by
// VPC alone), and vrf.Add is idempotent, so there's no way to distinguish
// "I created it" from "a sibling attachment already had." Deleting it on
// this attachment's own failed ADD could tear down a still-live sibling's
// VRF out from under it. Reclaiming it is exclusively galactic-router's GC
// controller's job.
func CleanupAttachment(vpc, vpcAttachment, ifaceKind string, del func(vpc, vpcAttachment string) error) {
	slog.Info("Selective rollback: cleaning up resources created during failed ADD",
		"vpc", vpc, "vpcAttachment", vpcAttachment)

	if err := del(vpc, vpcAttachment); err != nil {
		slog.Error("Rollback: failed to delete "+ifaceKind, "err", err,
			"vpc", vpc, "vpcAttachment", vpcAttachment)
	} else {
		slog.Debug("Rollback: deleted "+ifaceKind, "vpc", vpc, "vpcAttachment", vpcAttachment)
	}
}
