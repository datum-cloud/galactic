// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cni

import (
	"fmt"
	"log/slog"

	"github.com/containernetworking/plugins/pkg/ipam"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"go.datum.net/galactic/internal/cni/veth"
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
// rollback. galactic-cni is veth-only, and its ADD only ever creates the
// VRF, the veth pair, and (if delegated) an IPAM allocation — BGP/SRv6/eBPF
// publish is galactic-bgp's own, separately chain-invoked plugin now, with
// its own smaller tracker (internal/cnibgp); termination routes are
// galactic-route's own, with its own smaller tracker (internal/cniroute);
// so this one no longer needs to know anything about either.
type resourceTracker struct {
	vpc, vpcAttachment string

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
// Takes no context: unlike before this split, the only non-kernel call left
// here is ipam.ExecDel, which (like ExecAdd) shells out to the delegated
// plugin binary rather than making a k8s API call (BGP CRD/eBPF rollback is
// galactic-bgp's own tracker now).
//
// Deliberately absent: deleting the VRF. veth.Delete below only removes
// this attachment's own host/guest veth pair, which is genuinely private to
// it — but the VRF itself is now shared by every attachment on this VPC on
// this node (internal/plumbing/vrf keys it by VPC alone), and vrf.Add is
// idempotent, so there's no way to distinguish "I created it" from "a
// sibling attachment already had." Deleting it on this attachment's own
// failed ADD could tear down a still-live sibling's VRF out from under it —
// the same reasoning internal/cnibgp's resourceTracker applies to the
// BGPVRFInstance CRD and eBPF vrf_table entry. Reclaiming it is exclusively
// galactic-router's GC controller's job, once it has confirmed via every
// BGPAdvertisement for this VPC/node that none remain.
func (rt *resourceTracker) cleanup() {
	slog.Info("Selective rollback: cleaning up resources created during failed ADD",
		"vpc", rt.vpc, "vpcAttachment", rt.vpcAttachment)

	// 1. Release the IPAM allocation (if pluginConf carried an "ipam" block
	// at all — see the ipamDelegated field doc comment for why this fires
	// unconditionally on that alone, not just after a confirmed ExecAdd).
	if rt.ipamDelegated {
		if err := ipam.ExecDel(rt.ipamType, rt.ipamStdin); err != nil {
			slog.Error("Rollback: failed to release IPAM allocation", "err", err, "ipamType", rt.ipamType)
		} else {
			slog.Debug("Rollback: released IPAM allocation", "ipamType", rt.ipamType)
		}
	}

	// 2. Delete host veth
	if err := veth.Delete(rt.vpc, rt.vpcAttachment); err != nil {
		slog.Error("Rollback: failed to delete veth", "err", err,
			"vpc", rt.vpc, "vpcAttachment", rt.vpcAttachment)
	} else {
		slog.Debug("Rollback: deleted veth", "vpc", rt.vpc, "vpcAttachment", rt.vpcAttachment)
	}
}
