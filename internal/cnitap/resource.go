// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cnitap

import (
	"fmt"
	"log/slog"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"go.datum.net/galactic/internal/cni/tap"
	bgpv1alpha1 "go.datum.net/network/api/v1alpha1"
)

var cniScheme = runtime.NewScheme()

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(cniScheme))
	utilruntime.Must(bgpv1alpha1.AddToScheme(cniScheme))
}

// newK8sClient creates a new Kubernetes client using the in-cluster config,
// scoped to cniScheme. The only k8s call this plugin makes directly is the
// NAD annotation patch.
func newK8sClient() (client.Client, error) {
	restCfg, err := ctrl.GetConfig()
	if err != nil {
		return nil, fmt.Errorf("get kubeconfig: %w", err)
	}
	c, err := client.New(restCfg, client.Options{Scheme: cniScheme})
	if err != nil {
		return nil, fmt.Errorf("create k8s client: %w", err)
	}
	return c, nil
}

// resourceTracker tracks resources created during cmdAdd for selective
// rollback. galactic-tap-cni's ADD only ever creates the VRF and the tap
// device — BGP/SRv6/eBPF publish is galactic-bgp's own, separately
// chain-invoked plugin now, with its own smaller tracker (internal/cnibgp);
// termination routes are galactic-route's own, with its own smaller
// tracker (internal/cniroute).
type resourceTracker struct {
	vpc, vpcAttachment string
}

// Deliberately absent: deleting the VRF. tap.Delete below only removes this
// attachment's own tap device, which is genuinely private to it — but the
// VRF itself is shared by every attachment on this VPC on this node
// (internal/plumbing/vrf), and vrf.Add is idempotent, so a "vrfCreated" flag
// here could never distinguish "I created it" from "a sibling attachment
// already had." Deleting it on this attachment's own failed ADD could tear
// down a still-live sibling's VRF out from under it — see internal/cni's own
// resourceTracker.cleanup for the identical reasoning. Reclaiming it is
// exclusively galactic-router's GC controller's job.
func (rt *resourceTracker) cleanup() {
	slog.Info("Selective rollback: cleaning up resources created during failed ADD",
		"vpc", rt.vpc, "vpcAttachment", rt.vpcAttachment)

	if err := tap.Delete(rt.vpc, rt.vpcAttachment); err != nil {
		slog.Error("Rollback: failed to delete tap", "err", err,
			"vpc", rt.vpc, "vpcAttachment", rt.vpcAttachment)
	} else {
		slog.Debug("Rollback: deleted tap", "vpc", rt.vpc, "vpcAttachment", rt.vpcAttachment)
	}
}
