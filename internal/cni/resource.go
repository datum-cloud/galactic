// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cni

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
	"go.datum.net/galactic/internal/cni/veth"
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
// scoped to cniScheme (core types + BGP CRDs — the latter needed for both
// rollback's own CRD deletes and the cnibgp.PublishBGPState call this
// client gets passed into).
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
// rollback. galactic-cni is veth-only, so this is scoped to exactly what its
// own ADD creates: the VRF, the veth pair, and — for now, until BGP publish
// becomes its own chain-invoked plugin — the BGP CRDs and eBPF vrf_table
// entry that internal/cnibgp.PublishBGPState wrote on its behalf.
type resourceTracker struct {
	vpc, vpcAttachment string
	vrfCreated         bool
	routesCreated      int
	vrfInstanceCreated bool
	advCreated         bool
	k8s                client.Client
	namespace          string

	// ebpfRegistered, ebpfBlock, and ebpfArgument mirror
	// cnibgp.PublishResult's fields, recorded here so cleanup can call
	// cnibgp.UnregisterEBPFDatapath for the same (block, argument) pair.
	ebpfRegistered bool
	ebpfBlock      uint64
	ebpfArgument   uint16

	// ipamDelegated, ipamType, and ipamStdin record enough to release the
	// IPAM allocation during rollback. Set as soon as pluginConf.IPAM != nil
	// is known (before configureIPAM/ipam.ExecAdd is even attempted) rather
	// than only after a successful ExecAdd: ipam.ExecDel is idempotent per
	// the CNI IPAM delegation protocol (galactic-ipam's own cmdDel no-ops
	// when it finds no allocation for the containerID), so calling it
	// unconditionally whenever an "ipam" block was configured is safe and
	// covers every failure path, including ones where ExecAdd itself never
	// ran. Without this, a failed ADD that got past IPAM permanently burns
	// an address/subnet out of the pool — the on-disk marker file has no
	// implicit teardown the way the old in-memory-only allocator did.
	ipamDelegated bool
	ipamType      string
	ipamStdin     []byte
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

	// 2. Delete BGPVRFInstance
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

	// 3. Unregister the eBPF uSID datapath's vrf_table entry (only if
	// PublishBGPState actually wrote one). A pinned BPF map entry has no
	// implicit teardown when the VRF/interfaces are deleted below, so it
	// must be removed explicitly here.
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

	// 4. Release the IPAM allocation (if pluginConf carried an "ipam" block
	// at all — see the ipamDelegated field doc comment for why this fires
	// unconditionally on that alone, not just after a confirmed ExecAdd).
	if rt.ipamDelegated {
		if err := ipam.ExecDel(rt.ipamType, rt.ipamStdin); err != nil {
			slog.Error("Rollback: failed to release IPAM allocation", "err", err, "ipamType", rt.ipamType)
		} else {
			slog.Debug("Rollback: released IPAM allocation", "ipamType", rt.ipamType)
		}
	}

	// 5. Delete host veth
	if err := veth.Delete(rt.vpc, rt.vpcAttachment); err != nil {
		slog.Error("Rollback: failed to delete veth", "err", err,
			"vpc", rt.vpc, "vpcAttachment", rt.vpcAttachment)
	} else {
		slog.Debug("Rollback: deleted veth", "vpc", rt.vpc, "vpcAttachment", rt.vpcAttachment)
	}

	// 6. Delete VRF (flushes all routes, removes VRF interface)
	if err := vrf.Delete(rt.vpc, rt.vpcAttachment); err != nil {
		slog.Error("Rollback: failed to delete VRF", "err", err,
			"vpc", rt.vpc, "vpcAttachment", rt.vpcAttachment)
	} else {
		slog.Debug("Rollback: deleted VRF", "vpc", rt.vpc, "vpcAttachment", rt.vpcAttachment)
	}
}
