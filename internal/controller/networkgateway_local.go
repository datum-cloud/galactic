// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	bgpv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	"go.datum.net/galactic/internal/gateway"
	"go.datum.net/galactic/internal/gateway/localhandoff"
)

// NetworkGateway condition types and reasons for the Local handoff and the
// public path (docs/gateway/architecture.md).
const (
	// ConditionTypeLocalHandoff reports whether every backend on this
	// gateway's node is ready for Galactic Worker's Local handoff. It is set
	// only while the gateway's Worker integration is on.
	ConditionTypeLocalHandoff = "LocalHandoff"

	// ConditionTypePublicPath reports whether the gateway's public path
	// covers both VIP families. While it is False, each family it names is
	// withdrawn from BGP on this node.
	ConditionTypePublicPath = "PublicPath"

	reasonLocalHandoffReady    = "Ready"
	reasonNoLocalBackends      = "NoLocalBackends"
	reasonLocalHandoffNotReady = bgpv1alpha1.BackendHealthReasonLocalHandoffNotReady

	reasonPublicPathCovered = "Covered"
	// ReasonFamilyWithdrawn is a VIP family the gateway withdraws because its
	// public path does not cover it.
	ReasonFamilyWithdrawn = "FamilyWithdrawn"
	// ReasonAggregateStillAttracts is a withdrawn family that a covering
	// aggregate this node still advertises keeps attracting. The gateway
	// reports it and does not suppress the aggregate.
	ReasonAggregateStillAttracts = "AggregateStillAttracts"
)

// LocalHandoff hands this node's backends to their TAPs through Galactic
// Worker. *localhandoff.Manager satisfies it.
type LocalHandoff interface {
	SetBackends(backends []localhandoff.Backend)
	Snapshot() localhandoff.Snapshot
}

// PublicPathState says which VIP families the gateway's public path does not
// cover on this node, and why. An empty reason means the family is covered.
type PublicPathState struct {
	IPv6 string
	IPv4 string
}

// withdrawn reports whether s withdraws family.
func (s PublicPathState) withdrawn(family string) (string, bool) {
	if family == "v4" {
		return s.IPv4, s.IPv4 != ""
	}
	return s.IPv6, s.IPv6 != ""
}

// publicPath returns this pass's PublicPathState.
func (r *NetworkGatewayReconciler) publicPath() PublicPathState {
	if r.PublicPath == nil {
		return PublicPathState{}
	}
	return r.PublicPath()
}

// localBackends returns the backends on this node among desired's rules.
func localBackends(node string, desired gateway.EngineState) []localhandoff.Backend {
	seen := map[string]bool{}
	var out []localhandoff.Backend
	keys := make([]string, 0, len(desired.Rules))
	for k := range desired.Rules {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		for _, b := range desired.Rules[k].PlacedBackends {
			if b.Node != node || seen[b.USID.String()] {
				continue
			}
			seen[b.USID.String()] = true
			out = append(out, localhandoff.Backend{AttachmentUID: b.AttachmentUID, VPC: b.VPC, Slot: b.Slot,
				USID: b.USID})
		}
	}
	return out
}

// syncLocalBackends hands this node's backends among desired to the Local
// handoff, when it is on.
func (r *NetworkGatewayReconciler) syncLocalBackends(desired gateway.EngineState) {
	if r.LocalHandoff == nil {
		return
	}
	r.LocalHandoff.SetBackends(localBackends(r.NodeName, desired))
}

// stampStatus sets the status fields the gateway writes on every status
// write: BackendHealthFiltering, the Local handoff's backends and condition,
// and the public path's condition.
func (r *NetworkGatewayReconciler) stampStatus(gw *bgpv1alpha1.NetworkGateway) {
	gw.Status.BackendHealthFiltering = r.BackendHealth
	if r.LocalHandoff == nil {
		gw.Status.LocalBackends = nil
	} else {
		snap := r.LocalHandoff.Snapshot()
		gw.Status.LocalBackends = make([]bgpv1alpha1.NetworkGatewayLocalBackend, 0, len(snap.Attachments))
		var notReady []string
		firstReason := ""
		for _, a := range snap.Attachments {
			gw.Status.LocalBackends = append(gw.Status.LocalBackends, bgpv1alpha1.NetworkGatewayLocalBackend{
				AttachmentUID: a.AttachmentUID, Ready: a.Ready, Reason: a.Reason})
			if !a.Ready {
				notReady = append(notReady, a.AttachmentUID+" ("+a.Reason+")")
				if firstReason == "" {
					firstReason = a.Reason
				}
			}
		}
		cond := metav1.Condition{Type: ConditionTypeLocalHandoff, Status: metav1.ConditionTrue}
		switch {
		case len(snap.Attachments) == 0:
			cond.Reason, cond.Message = reasonNoLocalBackends, "no backend runs on node "+r.NodeName
		case len(notReady) == 0:
			cond.Reason = reasonLocalHandoffReady
			cond.Message = fmt.Sprintf("%d backend attachments on node %s are handed to their TAPs through "+
				"Galactic Worker", len(snap.Attachments), r.NodeName)
		default:
			cond.Status = metav1.ConditionFalse
			cond.Reason = reasonLocalHandoffNotReady
			if firstReason == bgpv1alpha1.LocalBackendReasonWorkerUnavailable {
				cond.Reason = firstReason
			}
			cond.Message = fmt.Sprintf("%d of %d backend attachments on node %s are not ready for the Local "+
				"handoff, so their flows through this node are dropped and galactic-router reports them "+
				"Unhealthy: %s", len(notReady), len(snap.Attachments), r.NodeName, cappedList(notReady))
		}
		setGatewayCondition(gw, cond)
	}
	if r.PublicPath != nil {
		pp := r.publicPath()
		cond := metav1.Condition{Type: ConditionTypePublicPath, Status: metav1.ConditionTrue,
			Reason: reasonPublicPathCovered, Message: "the public path covers both VIP families on node " + r.NodeName}
		var parts []string
		if pp.IPv6 != "" {
			parts = append(parts, "IPv6: "+pp.IPv6)
		}
		if pp.IPv4 != "" {
			parts = append(parts, "IPv4: "+pp.IPv4)
		}
		if len(parts) > 0 {
			cond.Status, cond.Reason = metav1.ConditionFalse, ReasonFamilyWithdrawn
			cond.Message = "VIP families withdrawn from BGP on node " + r.NodeName + ": " + strings.Join(parts, "; ")
		}
		setGatewayCondition(gw, cond)
	}
}

// advertisesIPv4 reports whether o's IPv4 VIPs are advertised from this
// node: they are loaded and the public path covers IPv4.
func (r *NetworkGatewayReconciler) advertisesIPv4(o ruleOutcome, pp PublicPathState) bool {
	return r.IPv4VIPs && o.ipv4 == ipv4Loaded && pp.IPv4 == ""
}

// familyAdvertised amends a published rule's Advertised condition adv for
// the VIP families the public path withdraws on this node.
func (r *NetworkGatewayReconciler) familyAdvertised(ctx context.Context, published bool, namespace, routerName string,
	desired gateway.DesiredRule, pp PublicPathState, adv metav1.Condition) (metav1.Condition, error) {
	if !published {
		return adv, nil
	}
	aggregates, err := r.coveringAggregates(ctx, namespace, routerName, desired.VIPAddresses, pp)
	return withdrawnFamilies(adv, r.NodeName, desired.VIPAddresses, pp, aggregates), err
}

// withdrawnFamilies amends rule's Advertised condition adv for the VIP
// families the public path withdraws on node. A rule with every VIP family
// withdrawn is not advertised from node (FamilyWithdrawn, or
// AggregateStillAttracts when an aggregate this node advertises still covers
// one of its VIPs); one with a family left says which family it lost.
func withdrawnFamilies(adv metav1.Condition, node string, vips []netip.Addr, pp PublicPathState,
	aggregates []string) metav1.Condition {
	var gone, kept []string
	for _, f := range []struct {
		name, label string
		is4         bool
	}{{"v6", "IPv6", false}, {"v4", "IPv4", true}} {
		has := false
		for _, v := range vips {
			if v.Unmap().Is4() == f.is4 {
				has = true
			}
		}
		if !has {
			continue
		}
		if why, ok := pp.withdrawn(f.name); ok {
			gone = append(gone, f.label+" ("+why+")")
		} else {
			kept = append(kept, f.label)
		}
	}
	if len(gone) == 0 {
		return adv
	}
	msg := "the public path withdraws " + strings.Join(gone, ", ") + " on node " + node
	if len(aggregates) > 0 {
		msg += ", but advertisements " + cappedList(aggregates) + " still cover its VIPs and attract their clients"
	}
	if len(kept) == 0 {
		adv.Status, adv.Reason = metav1.ConditionFalse, ReasonFamilyWithdrawn
		if len(aggregates) > 0 {
			adv.Reason = ReasonAggregateStillAttracts
		}
		adv.Message = "not advertised from node " + node + ": " + msg
		return adv
	}
	adv.Message += "; " + msg
	return adv
}

// coveringAggregates lists the BGPAdvertisements of this node's router, other
// than the gateway's own rule advertisements, whose prefixes cover a VIP of a
// family pp withdraws with a shorter prefix. Withdrawing the VIP's host route
// does not move clients an aggregate still attracts; the gateway reports such
// an aggregate and leaves it in place.
func (r *NetworkGatewayReconciler) coveringAggregates(ctx context.Context, namespace, routerName string,
	vips []netip.Addr, pp PublicPathState) ([]string, error) {
	if routerName == "" || (pp.IPv4 == "" && pp.IPv6 == "") {
		return nil, nil
	}
	var withdrawn []netip.Addr
	for _, v := range vips {
		v = v.Unmap()
		if _, ok := pp.withdrawn(familyName(v)); ok {
			withdrawn = append(withdrawn, v)
		}
	}
	if len(withdrawn) == 0 {
		return nil, nil
	}
	list := &bgpv1alpha1.BGPAdvertisementList{}
	if err := r.List(ctx, list, client.InNamespace(namespace)); err != nil {
		return nil, fmt.Errorf("list BGPAdvertisements: %w", err)
	}
	var out []string
	for i := range list.Items {
		adv := &list.Items[i]
		if adv.Spec.RouterRef.Name != routerName || isRuleAdvertisement(adv) {
			continue
		}
		if coversAny(adv.Spec.Prefixes, withdrawn) {
			out = append(out, adv.Name)
		}
	}
	sort.Strings(out)
	return out, nil
}

func familyName(a netip.Addr) string {
	if a.Is4() {
		return "v4"
	}
	return "v6"
}

// coversAny reports whether a prefix in prefixes covers one of addrs and is
// shorter than a host route.
func coversAny(prefixes []bgpv1alpha1.Prefix, addrs []netip.Addr) bool {
	for _, p := range prefixes {
		pfx, err := netip.ParsePrefix(string(p))
		if err != nil || pfx.Bits() == pfx.Addr().BitLen() {
			continue
		}
		for _, a := range addrs {
			if pfx.Contains(a) {
				return true
			}
		}
	}
	return false
}
