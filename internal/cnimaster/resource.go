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

// NADPatchTimeout bounds each API call a master plugin makes with the client
// from NewK8sClient: the chain-completeness read right after creating it, and
// the annotation patch later in the same ADD.
const NADPatchTimeout = 10 * time.Second

var scheme = runtime.NewScheme()

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	// The BGP types are registered even though neither master plugin reads or
	// writes them, that being the BGP plugin's concern. Nothing else needs its
	// own scheme, and the annotation patch uses an unstructured object needing
	// no registration at all. Harmless to leave.
	utilruntime.Must(bgpv1alpha1.AddToScheme(scheme))
}

// NewK8sClient creates a Kubernetes client from the in-cluster config. The only
// call either master plugin makes directly is the annotation patch.
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

// CleanupAttachment rolls back a failed ADD's host-side interface. Errors are
// logged and never returned, the caller already having a failure to report.
//
// ifaceKind names the interface kind for log messages, and del removes the
// attachment's own interface pair.
//
// Deliberately absent: deleting the VRF. It is shared by every attachment on
// this VPC on this node, and creating it is idempotent, so there is no way to
// tell "I created it" from "a sibling already had". Deleting it on a failed ADD
// could tear down a live sibling's VRF. Reclaiming it is garbage collection's
// job.
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
