// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cni

import (
	"context"
	"log/slog"

	bgpv1alpha1 "go.miloapis.com/cosmos/api/bgp/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"go.datum.net/galactic/internal/cni/tap"
	"go.datum.net/galactic/internal/cni/veth"
	"go.datum.net/galactic/internal/plumbing/srv6"
	"go.datum.net/galactic/internal/plumbing/vrf"
)

var cniScheme = runtime.NewScheme()

// enableLocalIPAM controls whether the plugin performs IP allocation when
// no explicit ipam block is present in the CNI config. Defaults to false.
var enableLocalIPAM bool

// SetEnableLocalIPAM sets the local IPAM flag from the CLI.
func SetEnableLocalIPAM(v bool) {
	enableLocalIPAM = v
}

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(cniScheme))
	utilruntime.Must(bgpv1alpha1.AddToScheme(cniScheme))
}

// resourceTracker tracks resources created during cmdAdd for selective rollback.
type resourceTracker struct {
	vpc, vpcAttachment string
	ifaceType          string
	vrfCreated         bool
	routesCreated      int
	srv6SID            string
	vrfInstanceCreated bool
	advCreated         bool
	k8s                client.Client
	namespace          string
}

// cleanup rolls back all tracked resources in reverse creation order.
// Errors are logged but never returned — the caller already has a failure.
func (rt *resourceTracker) cleanup(ctx context.Context) {
	slog.Info("Selective rollback: cleaning up resources created during failed ADD",
		"vpc", rt.vpc, "vpcAttachment", rt.vpcAttachment)

	// 1. Delete BGPAdvertisement (withdraws prefixes)
	if rt.advCreated && rt.k8s != nil {
		adv := &bgpv1alpha1.BGPAdvertisement{
			ObjectMeta: metav1.ObjectMeta{
				Name:      bgpAdvertisementName(rt.vpc, rt.vpcAttachment),
				Namespace: rt.namespace,
			},
		}
		if err := rt.k8s.Delete(ctx, adv); client.IgnoreNotFound(err) != nil {
			slog.Error("Rollback: failed to delete BGPAdvertisement", "err", err,
				"name", adv.Name, "namespace", rt.namespace)
		}
	}

	// 2. Delete BGPVRFInstance
	if rt.vrfInstanceCreated && rt.k8s != nil {
		vrfInst := &bgpv1alpha1.BGPVRFInstance{
			ObjectMeta: metav1.ObjectMeta{
				Name:      bgpVRFInstanceName(rt.vpc, rt.vpcAttachment),
				Namespace: rt.namespace,
			},
		}
		if err := rt.k8s.Delete(ctx, vrfInst); client.IgnoreNotFound(err) != nil {
			slog.Error("Rollback: failed to delete BGPVRFInstance", "err", err,
				"name", vrfInst.Name, "namespace", rt.namespace)
		}
	}

	// 3. Delete SRv6 ingress route (only if we got a SID)
	if rt.srv6SID != "" {
		if err := srv6.RouteIngressDel(rt.srv6SID, rt.vpc, rt.vpcAttachment); err != nil {
			slog.Error("Rollback: failed to delete SRv6 ingress route", "err", err,
				"sid", rt.srv6SID)
		}
	}

	// 4. Delete host veth (veth mode only)
	if rt.ifaceType == interfaceTypeVeth {
		if err := veth.Delete(rt.vpc, rt.vpcAttachment); err != nil {
			slog.Error("Rollback: failed to delete veth", "err", err,
				"vpc", rt.vpc, "vpcAttachment", rt.vpcAttachment)
		}
	}

	// 5. Delete tap (tap mode only)
	if rt.ifaceType == interfaceTypeTap {
		if err := tap.Delete(rt.vpc, rt.vpcAttachment); err != nil {
			slog.Error("Rollback: failed to delete tap", "err", err,
				"vpc", rt.vpc, "vpcAttachment", rt.vpcAttachment)
		}
	}

	// 6. Delete VRF (flushes all routes, removes VRF interface)
	if err := vrf.Delete(rt.vpc, rt.vpcAttachment); err != nil {
		slog.Error("Rollback: failed to delete VRF", "err", err,
			"vpc", rt.vpc, "vpcAttachment", rt.vpcAttachment)
	}
}
