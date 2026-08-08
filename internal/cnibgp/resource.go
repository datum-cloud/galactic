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

	"go.datum.net/galactic/internal/cni/crdnames"
	"go.datum.net/galactic/internal/plumbing/ebpf/attach"
	"go.datum.net/galactic/internal/plumbing/vrf"
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
type resourceTracker struct {
	vpc, vpcAttachment string
	namespace          string
	k8s                client.Client

	vrfInstanceCreated   bool
	advertisementCreated bool
	ebpfRegistered       bool
	ebpfBlock            uint64
	ebpfArgument         uint16
}

// cleanup rolls back all tracked resources. Errors are logged but never
// returned — the caller already has a failure.
func (rt *resourceTracker) cleanup(ctx context.Context) {
	slog.Info("Selective rollback: cleaning up resources created during failed ADD",
		"vpc", rt.vpc, "vpcAttachment", rt.vpcAttachment)

	if rt.advertisementCreated && rt.k8s != nil {
		adv := &bgpv1alpha1.BGPAdvertisement{
			ObjectMeta: metav1.ObjectMeta{
				Name:      crdnames.BGPAdvertisementName(rt.vpc, rt.vpcAttachment),
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
				Name:      crdnames.BGPVRFInstanceName(rt.vpc, rt.vpcAttachment),
				Namespace: rt.namespace,
			},
		}
		if err := rt.k8s.Delete(ctx, vrfInst); client.IgnoreNotFound(err) != nil {
			slog.Error("Rollback: failed to delete BGPVRFInstance", "err", err,
				"name", vrfInst.Name, "namespace", rt.namespace)
		} else {
			slog.Debug("Rollback: deleted BGPVRFInstance", "name", vrfInst.Name, "namespace", rt.namespace)
		}
	}

	if rt.ebpfRegistered {
		if vrfTableID, err := vrf.TableID(rt.vpc, rt.vpcAttachment); err != nil {
			slog.Error("Rollback: failed to resolve VRF table id, skipping eBPF vrf_table unregister", "err", err,
				"vpc", rt.vpc, "vpcAttachment", rt.vpcAttachment)
		} else if err := unregisterEBPFDatapath(rt.ebpfBlock, rt.ebpfArgument, vrfTableID, attach.PinDir); err != nil {
			slog.Error("Rollback: failed to unregister eBPF vrf_table entry", "err", err,
				"block", rt.ebpfBlock, "argument", rt.ebpfArgument)
		} else {
			slog.Debug("Rollback: unregistered eBPF vrf_table entry",
				"block", rt.ebpfBlock, "argument", rt.ebpfArgument)
		}
	}
}
