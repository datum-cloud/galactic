// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cnibgp

import (
	"context"
	"fmt"
	"log/slog"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"go.datum.net/galactic/internal/crdnames"
	bgpv1alpha1 "go.datum.net/network/api/v1alpha1"
)

var cniScheme = runtime.NewScheme()

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(cniScheme))
	utilruntime.Must(bgpv1alpha1.AddToScheme(cniScheme))
}

// newK8sClient creates a new Kubernetes client using the in-cluster config,
// scoped to cniScheme (BGP CRDs).
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

// resourceTracker tracks the resources cmdAdd created, for selective rollback.
// This plugin's ADD only ever creates BGP CRDs and an eBPF vrf_table entry;
// kernel-interface cleanup belongs to each master plugin's own tracker.
//
// publishResult is embedded rather than copied field by field, so a field added
// to one struct cannot silently stop being tracked in the other with no
// compiler error to catch it.
type resourceTracker struct {
	vpc, vpcAttachment, nodeName string
	namespace                    string
	k8s                          client.Client

	publishResult
}

// cleanup rolls back the tracked resources. Errors are logged and never
// returned, the caller already having a failure.
//
// Deliberately conditional. The BGPVRFInstance is deleted only when this ADD's
// own attempt created it, and the vrf_table entry is never unregistered at all.
// Unlike the advertisement, which is a reliable one-per-attachment key, both are
// shared by every attachment on this VPC on this node. Once a second
// attachment's ADD reuses a live sibling's, which is the ordinary case since
// both writes are idempotent, rolling either back would tear down that
// sibling's VRF.
//
// Reclaiming shared per-node state is garbage collection's job, once it has
// confirmed no advertisement for this VPC and node remains. The map entry has no
// cheap "did I just create this" signal the way an API object's write result
// does, so it stays unconditional there. The CRD does have one, which is what
// lets a rejected freshly created instance self-heal on retry rather than
// wedging permanently.
func (rt *resourceTracker) cleanup(ctx context.Context) {
	slog.Info("Selective rollback: cleaning up resources created during failed ADD",
		"vpc", rt.vpc, "vpcAttachment", rt.vpcAttachment)

	if rt.advertisementCreated && rt.k8s != nil {
		adv := &bgpv1alpha1.BGPAdvertisement{
			ObjectMeta: metav1.ObjectMeta{
				Name:      crdnames.BGPAdvertisementName(rt.vpc, rt.vpcAttachment, rt.nodeName),
				Namespace: rt.namespace,
			},
		}
		if err := rt.k8s.Delete(ctx, adv); client.IgnoreNotFound(err) != nil {
			slog.Error("Rollback: failed to delete BGPAdvertisement", "err", err,
				"name", adv.Name, "namespace", rt.namespace)
		} else {
			slog.Debug("Rollback: deleted BGPAdvertisement", "name", adv.Name, "namespace", rt.namespace)
		}
	}

	if rt.vrfInstanceCreated && rt.k8s != nil {
		vrfInst := &bgpv1alpha1.BGPVRFInstance{
			ObjectMeta: metav1.ObjectMeta{
				Name:      crdnames.BGPVRFInstanceName(rt.vpc, rt.nodeName),
				Namespace: rt.namespace,
			},
		}
		if err := rt.k8s.Delete(ctx, vrfInst); client.IgnoreNotFound(err) != nil {
			slog.Error("Rollback: failed to delete freshly-created BGPVRFInstance", "err", err,
				"name", vrfInst.Name, "namespace", rt.namespace)
		} else {
			slog.Debug("Rollback: deleted freshly-created BGPVRFInstance", "name", vrfInst.Name, "namespace", rt.namespace)
		}
	}
}
