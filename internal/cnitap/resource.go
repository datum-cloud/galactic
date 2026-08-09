// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cnitap

import (
	"fmt"
	"log/slog"

	"github.com/containernetworking/plugins/pkg/ipam"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"go.datum.net/galactic/internal/cni/tap"
	"go.datum.net/galactic/internal/plumbing/vrf"
)

var cniScheme = runtime.NewScheme()

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(cniScheme))
	// No BGP CRD scheme registration: this package no longer reads or
	// writes BGP CRDs itself (that's galactic-bgp's own, chain-invoked
	// concern now — internal/cnibgp/resource.go registers bgpv1alpha1 for
	// its own client), and NAD annotation's unstructured.Unstructured Patch
	// call doesn't require any scheme registration at all.
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
// rollback. galactic-tap-cni's ADD only ever creates the VRF, the tap
// device, and (if delegated) an IPAM allocation — BGP/SRv6/eBPF publish is
// galactic-bgp's own, separately chain-invoked plugin now, with its own
// smaller tracker (internal/cnibgp).
type resourceTracker struct {
	vpc, vpcAttachment string
	vrfCreated         bool
	routesCreated      int

	// ipamDelegated, ipamType, and ipamStdin record enough to release the
	// IPAM allocation during rollback — see internal/cni's own
	// resourceTracker for the full doc comment on why this fires
	// unconditionally on "ipam" block presence rather than only after a
	// confirmed ExecAdd.
	ipamDelegated bool
	ipamType      string
	ipamStdin     []byte
}

func (rt *resourceTracker) cleanup() {
	slog.Info("Selective rollback: cleaning up resources created during failed ADD",
		"vpc", rt.vpc, "vpcAttachment", rt.vpcAttachment)

	if rt.ipamDelegated {
		if err := ipam.ExecDel(rt.ipamType, rt.ipamStdin); err != nil {
			slog.Error("Rollback: failed to release IPAM allocation", "err", err, "ipamType", rt.ipamType)
		} else {
			slog.Debug("Rollback: released IPAM allocation", "ipamType", rt.ipamType)
		}
	}

	if err := tap.Delete(rt.vpc, rt.vpcAttachment); err != nil {
		slog.Error("Rollback: failed to delete tap", "err", err,
			"vpc", rt.vpc, "vpcAttachment", rt.vpcAttachment)
	} else {
		slog.Debug("Rollback: deleted tap", "vpc", rt.vpc, "vpcAttachment", rt.vpcAttachment)
	}

	if err := vrf.Delete(rt.vpc, rt.vpcAttachment); err != nil {
		slog.Error("Rollback: failed to delete VRF", "err", err,
			"vpc", rt.vpc, "vpcAttachment", rt.vpcAttachment)
	} else {
		slog.Debug("Rollback: deleted VRF", "vpc", rt.vpc, "vpcAttachment", rt.vpcAttachment)
	}
}
