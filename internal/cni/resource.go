// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cni

import (
	"fmt"
	"log/slog"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"go.datum.net/galactic/internal/cni/veth"
	"go.datum.net/galactic/internal/plumbing/vrf"
	bgpv1alpha1 "go.datum.net/network/api/v1alpha1"
)

var cniScheme = runtime.NewScheme()

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(cniScheme))
	// bgpv1alpha1 is registered even though this package no longer reads or
	// writes BGP CRDs itself (that's galactic-bgp's own, chain-invoked
	// concern now) — kept here only because nothing else in this package
	// needs its own scheme, and NAD annotation's unstructured.Unstructured
	// Patch call doesn't require any scheme registration at all. Harmless
	// to leave; trim if this scheme ever needs to shrink for another reason.
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
// rollback. galactic-cni is veth-only, and its ADD only ever creates the
// VRF and the veth pair — BGP/SRv6/eBPF publish is galactic-bgp's own,
// separately chain-invoked plugin now, with its own smaller tracker
// (internal/cnibgp); termination routes are galactic-route's own, with its
// own smaller tracker (internal/cniroute); so this one no longer needs to
// know anything about either.
type resourceTracker struct {
	vpc, vpcAttachment string
	vrfCreated         bool
}

// cleanup rolls back all tracked resources in reverse creation order.
// Errors are logged but never returned — the caller already has a failure.
// Takes no context: unlike before this split, nothing here makes a k8s
// call anymore (BGP CRD/eBPF rollback is galactic-bgp's own tracker now).
func (rt *resourceTracker) cleanup() {
	slog.Info("Selective rollback: cleaning up resources created during failed ADD",
		"vpc", rt.vpc, "vpcAttachment", rt.vpcAttachment)

	if err := veth.Delete(rt.vpc, rt.vpcAttachment); err != nil {
		slog.Error("Rollback: failed to delete veth", "err", err,
			"vpc", rt.vpc, "vpcAttachment", rt.vpcAttachment)
	} else {
		slog.Debug("Rollback: deleted veth", "vpc", rt.vpc, "vpcAttachment", rt.vpcAttachment)
	}

	if err := vrf.Delete(rt.vpc, rt.vpcAttachment); err != nil {
		slog.Error("Rollback: failed to delete VRF", "err", err,
			"vpc", rt.vpc, "vpcAttachment", rt.vpcAttachment)
	} else {
		slog.Debug("Rollback: deleted VRF", "vpc", rt.vpc, "vpcAttachment", rt.vpcAttachment)
	}
}
