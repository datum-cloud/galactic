// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package egressroute reconciles a tenant VRF's ::/0 default route toward
// the assigned gateway node's egress_sid, on every compute node that has a
// local VRF for that tenant (datum-cloud/enhancements#865, design plan
// §4.4/§7.1). It is the per-node route-installing half of the plan's
// candidate-2 decision (a new controller, not galactic-cni's cmdAdd) —
// see internal/controller/egressroute_controller.go for the ticker-driven
// wrapper that calls Run periodically, mirroring internal/gc's own
// split between the real logic (this package) and a thin controller
// wrapper (internal/controller/gc_controller.go).
//
// Scope: this package only ever installs/removes a plain IPv6 ::/0 route
// (design plan §3.4 — IPv4 egress destinations are out of scope for
// Phase 1's datapath, so an IPv4 default route would be pointless work).
//
// Two significant inferences this package makes, neither spelled out
// explicitly in the design plan text, flagged here for review:
//
//  1. tenant_arg reuse: the Argument value embedded in the destination
//     uSID this package builds is the tenant's own BGPVRFInstance.Spec.
//     VRFID — the same Argument value already allocated for that VPC's
//     *ingress* SRv6 decap on this same node (internal/cnibgp/bgp.go's
//     allocateArgument). This is safe because VRFID uniqueness is scoped
//     per-node (allocateArgument scans only the calling router's own
//     BGPVRFInstances), which is exactly the isolation property egress's
//     tenant_arg needs too (no two VPCs on the *same* node ever share a
//     value) — nothing downstream compares one node's choice against
//     another node's for the same VPC, so the value does not need to be
//     globally consistent across every node hosting that VPC, only
//     locally unique on each one.
//  2. NetworkGatewayStatus.EgressSID (this repo's own network API
//     addition, not in the original design plan text) publishes the
//     assigned gateway's egress_sid locator so a compute node can resolve
//     it at all — necessary because RouteEgressAdd's underlying
//     netlink.RouteGet requires a real kernel route to the destination
//     SID to already exist, which only happens once it's been advertised
//     into BGP/EVPN the same way SRv6Address already is.
package egressroute

import (
	"context"
	"fmt"
	"net"
	"net/netip"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"go.datum.net/galactic/internal/crdnames"
	"go.datum.net/galactic/internal/plumbing/ebpf/uformat"
	"go.datum.net/galactic/internal/plumbing/srv6"
	"go.datum.net/galactic/internal/plumbing/vrf"
	bgpv1alpha1 "go.datum.net/network/api/v1alpha1"
)

// ipv6DefaultPrefix is ::/0 — the only prefix this package ever installs a
// route for (see this package's own doc comment on IPv4 scope).
var ipv6DefaultPrefix = &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)}

// Result summarizes one reconcile pass, mirroring gc.CleanupResult's shape
// and logging convention.
type Result struct {
	RoutesInstalled int
	RoutesRemoved   int
	Errors          int
}

// Run reconciles every local Galactic-managed VRF interface's ::/0 default
// route against NetworkEgressPolicy state in namespace, for this node
// (nodeName). For each local VRF:
//
//   - If an accepted NetworkEgressPolicy names this VRF's VPC, and that
//     policy has an AssignedGatewayNode whose NetworkGateway publishes a
//     non-empty EgressSID, and this node has its own BGPVRFInstance for
//     the VPC: ensure the ::/0 SEG6 encap route exists, encapsulating
//     toward that gateway's egress_sid locator with this VPC's own VRFID
//     as the uSID Argument (tenant_arg) — see this package's doc comment
//     for why VRFID is safe to reuse this way.
//   - Otherwise: ensure no ::/0 route remains in that VRF's table (removes
//     one if enablement was withdrawn, the assigned gateway isn't ready
//     yet, or was never installed at all).
//
// Best-effort: one VRF's failure is logged and counted, not fatal to the
// rest of the pass — same convention as gc.RunGC.
func Run(ctx context.Context, k8s client.Client, namespace, nodeName string, log Logger) Result {
	var result Result

	links, err := vrf.ListVRFLinks()
	if err != nil {
		log.Error(err, "list local VRF links")
		result.Errors++
		return result
	}
	if len(links) == 0 {
		return result
	}

	enabled, err := acceptedEgressPolicyByVPC(ctx, k8s, namespace)
	if err != nil {
		log.Error(err, "list NetworkEgressPolicies")
		result.Errors++
		return result
	}

	for _, link := range links {
		vpc, ok := vrf.ResolveVPC(link.Name)
		if !ok {
			continue // not a Galactic VRF
		}

		tableID, err := vrf.TableID(vpc)
		if err != nil {
			log.Error(err, "resolve table ID for local VRF", "vpc", vpc, "vrf", link.Name)
			result.Errors++
			continue
		}

		dest, err := resolveEgressDestination(ctx, k8s, namespace, nodeName, vpc, enabled)
		if err != nil {
			log.Error(err, "resolve egress destination for VPC", "vpc", vpc)
			result.Errors++
			continue
		}

		if dest == nil {
			removed, err := removeDefaultRoute(tableID)
			if err != nil {
				log.Error(err, "remove egress default route", "vpc", vpc, "table", tableID)
				result.Errors++
				continue
			}
			if removed {
				log.Info("removed egress default route", "vpc", vpc, "table", tableID)
				result.RoutesRemoved++
			}
			continue
		}

		if err := srv6.RouteEgressAdd(ipv6DefaultPrefix, *dest, tableID); err != nil {
			log.Error(err, "install egress default route", "vpc", vpc, "table", tableID, "destination", dest.String())
			result.Errors++
			continue
		}
		result.RoutesInstalled++
	}

	return result
}

// Logger is the minimal structured-logging interface Run needs — satisfied
// by both log/slog's *slog.Logger (via a thin adapter) and
// sigs.k8s.io/controller-runtime/pkg/log's logr.Logger, so this package
// depends on neither directly.
type Logger interface {
	Info(msg string, keysAndValues ...any)
	Error(err error, msg string, keysAndValues ...any)
}

// acceptedEgressPolicyByVPC lists every NetworkEgressPolicy in namespace and
// returns the first Accepted one found per vpcRef. Taking the first is safe
// even if a VPC has multiple policies (one per vpcAttachmentRef, design
// plan §4.1): AssignedGatewayNode is a pure function of vpcRef alone
// (gateway.AssignPrimaryNode), so every accepted policy for the same VPC
// resolves to the identical value regardless of which one this picks.
func acceptedEgressPolicyByVPC(
	ctx context.Context, k8s client.Client, namespace string,
) (map[string]*bgpv1alpha1.NetworkEgressPolicy, error) {
	list := &bgpv1alpha1.NetworkEgressPolicyList{}
	if err := k8s.List(ctx, list, client.InNamespace(namespace)); err != nil {
		return nil, fmt.Errorf("list NetworkEgressPolicies: %w", err)
	}

	byVPC := make(map[string]*bgpv1alpha1.NetworkEgressPolicy, len(list.Items))
	for i := range list.Items {
		policy := &list.Items[i]
		if !policy.DeletionTimestamp.IsZero() {
			continue
		}
		if !meta.IsStatusConditionTrue(policy.Status.Conditions, bgpv1alpha1.ConditionTypeAccepted) {
			continue
		}
		if _, exists := byVPC[policy.Spec.VPCRef]; exists {
			continue
		}
		byVPC[policy.Spec.VPCRef] = policy
	}
	return byVPC, nil
}

// resolveEgressDestination returns the full destination uSID this VPC's
// default route should encapsulate toward, or nil if egress is not
// (yet, or no longer) enabled for it — never an error for "not enabled",
// only for a real lookup failure.
func resolveEgressDestination(
	ctx context.Context, k8s client.Client, namespace, nodeName, vpc string,
	enabled map[string]*bgpv1alpha1.NetworkEgressPolicy,
) (*net.IP, error) {
	policy, ok := enabled[vpc]
	if !ok || policy.Status.AssignedGatewayNode == "" {
		return nil, nil
	}

	gw := &bgpv1alpha1.NetworkGateway{}
	gwKey := client.ObjectKey{Namespace: namespace, Name: policy.Status.AssignedGatewayNode}
	if err := k8s.Get(ctx, gwKey, gw); err != nil {
		if errors.IsNotFound(err) {
			return nil, nil // assigned node no longer exists; treat as not-yet-ready
		}
		return nil, fmt.Errorf("get NetworkGateway %s: %w", policy.Status.AssignedGatewayNode, err)
	}
	if gw.Status.EgressSID == "" {
		return nil, nil // assigned gateway isn't offering egress yet
	}

	locator, err := netip.ParseAddr(gw.Status.EgressSID)
	if err != nil {
		return nil, fmt.Errorf("parse egress_sid %q for gateway %s: %w", gw.Status.EgressSID, gw.Name, err)
	}
	block, err := uformat.Block(locator)
	if err != nil {
		return nil, fmt.Errorf("read Block from egress_sid %q: %w", gw.Status.EgressSID, err)
	}
	nodeID, err := uformat.NodeID(locator)
	if err != nil {
		return nil, fmt.Errorf("read Node-ID from egress_sid %q: %w", gw.Status.EgressSID, err)
	}

	vrfInst := &bgpv1alpha1.BGPVRFInstance{}
	vrfKey := client.ObjectKey{Namespace: namespace, Name: crdnames.BGPVRFInstanceName(vpc, nodeName)}
	if err := k8s.Get(ctx, vrfKey, vrfInst); err != nil {
		if errors.IsNotFound(err) {
			return nil, nil // no ingress VRF instance yet for this VPC on this node
		}
		return nil, fmt.Errorf("get BGPVRFInstance %s: %w", vrfKey.Name, err)
	}
	// VRFID's own CRD range (1-65535) is wider than uformat's 12-bit
	// Argument field (up to 0xFFF=4095) -- the same range mismatch
	// internal/gc/gc.go's SweepEBPFVRFTable already guards against for
	// the ingress path; mirrored here rather than silently truncating.
	if vrfInst.Spec.VRFID < int32(uformat.ArgumentMin) || vrfInst.Spec.VRFID > int32(uformat.ArgumentMax) {
		return nil, fmt.Errorf("BGPVRFInstance %s has out-of-range VRFID %d for uSID Argument use [%#x,%#x]",
			vrfKey.Name, vrfInst.Spec.VRFID, uint16(uformat.ArgumentMin), uint16(uformat.ArgumentMax))
	}
	//nolint:gosec // range-checked immediately above
	tenantArg := uint16(vrfInst.Spec.VRFID)

	dest, err := uformat.Encode(uformat.Fields{Block: block, NodeID: nodeID, Function: 0, Argument: tenantArg})
	if err != nil {
		return nil, fmt.Errorf("encode egress destination uSID: %w", err)
	}
	destIP := net.IP(dest.AsSlice())
	return &destIP, nil
}

// removeDefaultRoute removes ipv6DefaultPrefix's SEG6 encap route from
// tableID if present, reporting whether anything was actually removed.
// Checks for existence first (rather than calling srv6.RouteEgressDel
// unconditionally and tolerating a "no such route" error) — the same
// list-then-delete convention internal/plumbing/vrf.flush already uses.
func removeDefaultRoute(tableID uint32) (bool, error) {
	routes, err := netlink.RouteListFiltered(
		unix.AF_INET6,
		&netlink.Route{Table: int(tableID)},
		netlink.RT_FILTER_TABLE,
	)
	if err != nil {
		return false, fmt.Errorf("list routes in table %d: %w", tableID, err)
	}

	found := false
	for _, r := range routes {
		if r.Dst != nil && r.Dst.String() == ipv6DefaultPrefix.String() {
			found = true
			break
		}
	}
	if !found {
		return false, nil
	}

	if err := srv6.RouteEgressDel(ipv6DefaultPrefix, tableID); err != nil {
		return false, err
	}
	return true, nil
}
