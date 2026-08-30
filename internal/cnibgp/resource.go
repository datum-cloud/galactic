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

// resourceTracker tracks resources created during cmdAdd for selective
// rollback. galactic-bgp's own ADD only ever creates BGP CRDs and an eBPF
// vrf_table entry — the kernel-interface/VRF cleanup that used to live
// alongside these in one process-wide tracker is now each master plugin's
// own, smaller tracker (internal/cni, internal/cnitap), scoped to exactly
// what its own ADD creates.
//
// publishResult is embedded, rather than its five fields being copied over
// field-by-field, so a future field added to one struct can't silently stop
// being tracked in the other with no compiler error to catch it — cmdAdd
// assigns the whole publishResult from publishBGPState in one shot
// (tracker.publishResult = result).
type resourceTracker struct {
	vpc, vpcAttachment, nodeName string
	namespace                    string
	k8s                          client.Client

	publishResult
}

// cleanup rolls back all tracked resources. Errors are logged but never
// returned — the caller already has a failure.
//
// Deliberately conditional: deleting the BGPVRFInstance CRD only when this
// ADD's own attempt just created it (vrfInstanceCreated), and never
// unregistering the eBPF vrf_table entry registerEBPFDatapath wrote at all.
// Unlike the BGPAdvertisement below (still a reliable 1:1 key per
// attachment — see crdnames.BGPAdvertisementName), both the BGPVRFInstance
// and the vrf_table entry are shared by every attachment on this VPC on
// this node (crdnames.BGPVRFInstanceName): once a second attachment's ADD
// reuses an already-live sibling's CRD/eBPF entry (publishBGPState's
// CreateOrUpdate and usidmap.VRF.Register are both idempotent-by-name/key,
// so this is the ordinary case, not an edge case), unconditionally rolling
// either back here would tear down a live sibling's VRF out from under it.
// This is the same reasoning internal/cni/veth and internal/plumbing/vrf
// already apply on the kernel side (see vrf.Delete's doc comment): shared
// per-(vpc,node) state is exclusively galactic-router's GC controller's job
// to reclaim, once it has confirmed via every BGPAdvertisement for this
// VPC/node that none remain (internal/gc's CollectOrphanedCRDs and
// SweepEBPFVRFTable) — the eBPF entry has no cheap "did I just create this"
// signal the way a k8s object's CreateOrUpdate result gives us, so it stays
// unconditional there; the BGPVRFInstance does, which is what lets a
// checkArgumentCollision rejection of a freshly-created instance (see
// publishBGPState) self-heal on retry instead of wedging permanently.
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
