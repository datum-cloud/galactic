// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cnitap

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/containernetworking/plugins/pkg/ipam"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"go.datum.net/galactic/internal/cni/crdnames"
	"go.datum.net/galactic/internal/cni/tap"
	"go.datum.net/galactic/internal/cnibgp"
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
// scoped to cniScheme.
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
// rollback. galactic-tap-cni is tap-only, so this is scoped to exactly what
// its own ADD creates: the VRF, the tap device, and — for now, until BGP
// publish becomes its own chain-invoked plugin — the BGP CRDs and eBPF
// vrf_table entry that internal/cnibgp.PublishBGPStateK8s wrote on its
// behalf. Mirrors internal/cni's own resourceTracker.
type resourceTracker struct {
	vpc, vpcAttachment string
	vrfCreated         bool
	routesCreated      int
	vrfInstanceCreated bool
	advCreated         bool
	k8s                client.Client
	namespace          string

	ebpfRegistered bool
	ebpfBlock      uint64
	ebpfArgument   uint16

	// ipamDelegated, ipamType, and ipamStdin record enough to release the
	// IPAM allocation during rollback — see internal/cni's own
	// resourceTracker for the full doc comment on why this fires
	// unconditionally on "ipam" block presence rather than only after a
	// confirmed ExecAdd.
	ipamDelegated bool
	ipamType      string
	ipamStdin     []byte
}

func (rt *resourceTracker) cleanup(ctx context.Context) {
	slog.Info("Selective rollback: cleaning up resources created during failed ADD",
		"vpc", rt.vpc, "vpcAttachment", rt.vpcAttachment)

	if rt.advCreated && rt.k8s != nil {
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
		} else if err := cnibgp.UnregisterEBPFDatapath(rt.ebpfBlock, rt.ebpfArgument, vrfTableID, attach.PinDir); err != nil {
			slog.Error("Rollback: failed to unregister eBPF vrf_table entry", "err", err,
				"block", rt.ebpfBlock, "argument", rt.ebpfArgument)
		} else {
			slog.Debug("Rollback: unregistered eBPF vrf_table entry",
				"block", rt.ebpfBlock, "argument", rt.ebpfArgument)
		}
	}

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
