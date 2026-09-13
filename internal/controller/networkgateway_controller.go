// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	ctrlreconcile "sigs.k8s.io/controller-runtime/pkg/reconcile"

	"go.datum.net/galactic/internal/gateway"
	bgpv1alpha1 "go.datum.net/network/api/v1alpha1"
)

// GatewayEngine is the interface NetworkGatewayReconciler drives, satisfied by
// *gateway.Engine in production and a fake in tests. The engine has no kernel
// VRF or Geneve dependency, so nothing here sets up a link.
type GatewayEngine interface {
	// Reconcile converges the engine's live state toward desired.
	Reconcile(ctx context.Context, desired gateway.EngineState) (gateway.EngineStatus, error)

	// DatapathGeneration returns the datapath's current generation counter. It
	// must be captured before the NetworkRule CRDs are listed; see
	// ReconcileOrphans.
	DatapathGeneration() uint64

	// ReconcileOrphans removes rule_table state left behind by a mid-reconcile
	// crash. cutoff must come from DatapathGeneration, read before desired's
	// NetworkRule CRDs were listed, so an entry written during the listing
	// survives.
	ReconcileOrphans(ctx context.Context, desired gateway.EngineState, cutoff uint64) error

	// Stop tears down every currently-active rule.
	Stop(ctx context.Context) error
}

// NetworkGatewayReconciler reconciles the single NetworkGateway object whose
// spec.targetRef.name is this node. NetworkGateway is the node-scoped root
// object, as BGPRouter is for the router.
//
// Each pass does three things:
//
//  1. Assembles a gateway.EngineState from every accepted, non-deleting
//     NetworkRule in the namespace, resolving each backend's SRv6 uSID, and
//     converges the engine toward it. Under the anycast model every gateway
//     node in a PoP serves every accepted rule identically, so there is no
//     primary or secondary node to gate on.
//  2. Reconciles one BGPAdvertisement per rule per VIP address family, reusing
//     the l2vpn/evpn Type-5 IP-Prefix path unmodified. VRFID and Function stay
//     unset, since these advertisements need no SRv6 decap behavior, which
//     gives each originating node a distinct route distinguisher. That
//     distinctness, not BGP preference, is what keeps every node's
//     identical-prefix advertisement alive as an independent route, so no
//     local preference is set either.
//  3. Runs ReconcileOrphans for crash recovery.
type NetworkGatewayReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	Engine GatewayEngine

	NodeName string
}

const (
	// reasonEngineHealthy is the Ready condition reason for a fully
	// converged and fully advertised node.
	reasonEngineHealthy = "EngineHealthy"

	// reasonAdvertisementFailed is the Ready reason for a node whose engine
	// converged but which could not publish one or more of the
	// BGPAdvertisements that make it reachable. Such a node serves nothing, so
	// it must not report reasonEngineHealthy.
	reasonAdvertisementFailed = "AdvertisementFailed"

	// reasonTerminating is the Ready reason for a NetworkGateway being deleted,
	// whether observed on a live object carrying a deletion timestamp or
	// reconstructed for the case where the object is already gone.
	reasonTerminating = "Terminating"
)

// Reconcile reconciles a single NetworkGateway.
func (r *NetworkGatewayReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	gw := &bgpv1alpha1.NetworkGateway{}
	if err := r.Get(ctx, req.NamespacedName, gw); err != nil {
		if apierrors.IsNotFound(err) {
			// Every gateway node's process reconciles every NetworkGateway in
			// the namespace, so a sibling node's deletion reaches this
			// reconciler too, and the deleted object can no longer be read to
			// see whose it was. Ask instead whether some NetworkGateway still
			// targets this node: if one does, this node is untouched and its
			// engine must keep running. Stopping otherwise would let one
			// node's deletion tear down every other gateway node's data
			// plane.
			//
			// req.Name is the departed NetworkGateway's name, which by
			// convention is that node's name, the same identity
			// applyBGPAdvertisements names every advertisement with. NetworkGateway carries no finalizer, so this
			// reconciler never observes a live object with a deletion
			// timestamp for a node that has left: the object is gone by the
			// time any Get runs. Withdrawing here, keyed on req.Name rather
			// than r.NodeName, is what makes a departed node's
			// advertisements go away even though its own process is the one
			// most likely already gone.
			withdrawErr := withdrawNodeAdvertisements(ctx, r.Client, req.Namespace, req.Name)
			if withdrawErr != nil {
				logger.Error(withdrawErr, "withdraw BGPAdvertisements for departed gateway node", "node", req.Name)
			}

			stillOwned, checkErr := isGatewayNode(ctx, r.Client, req.Namespace, r.NodeName)
			if checkErr != nil {
				return ctrl.Result{}, errors.Join(withdrawErr, fmt.Errorf("check for this node's own NetworkGateway: %w", checkErr))
			}
			if stillOwned {
				return ctrl.Result{}, withdrawErr
			}
			if stopErr := r.Engine.Stop(ctx); stopErr != nil {
				logger.Error(stopErr, "stop gateway engine for deleted NetworkGateway", "networkGateway", req.NamespacedName)
			}
			return ctrl.Result{}, withdrawErr
		}
		return ctrl.Result{}, fmt.Errorf("get NetworkGateway %s: %w", req.NamespacedName, err)
	}

	// Skip gateways that do not target this node.
	if gw.Spec.TargetRef.Name != r.NodeName {
		return ctrl.Result{}, nil
	}

	if !gw.DeletionTimestamp.IsZero() {
		// Withdrawn before Engine.Stop, not after: the reverse order leaves a
		// window where this node's forwarding state is gone while BGP still
		// advertises it as a valid destination. This branch is not known to be
		// reachable while NetworkGateway carries no finalizer, since a
		// deletion removes the object before any Get here sees a live deletion
		// timestamp, but it costs nothing to keep correct.
		withdrawErr := withdrawNodeAdvertisements(ctx, r.Client, gw.Namespace, gw.Name)
		if withdrawErr != nil {
			logger.Error(withdrawErr, "withdraw BGPAdvertisements for terminating NetworkGateway",
				"networkGateway", req.NamespacedName)
		}
		if stopErr := r.Engine.Stop(ctx); stopErr != nil {
			logger.Error(stopErr, "stop gateway engine for terminating NetworkGateway", "networkGateway", req.NamespacedName)
		}
		gwCopy := gw.DeepCopy()
		setGatewayCondition(gwCopy, metav1.Condition{
			Type:    bgpv1alpha1.ConditionTypeReady,
			Status:  metav1.ConditionFalse,
			Reason:  reasonTerminating,
			Message: "NetworkGateway is being deleted",
		})
		if updateErr := r.Status().Update(ctx, gwCopy); updateErr != nil {
			logger.Error(updateErr, "update status for terminating NetworkGateway")
		}
		return ctrl.Result{}, withdrawErr
	}

	// Advertisement failures are collected rather than returned on the spot, so
	// one bad rule does not stop the others. They are then reported on the
	// object and returned, so controller-runtime retries with backoff instead
	// of leaving a node that advertised nothing claiming to be healthy.
	var advErrs []error

	// Crash-safety ordering contract (see GatewayEngine.ReconcileOrphans):
	// cutoff must be captured before desired's NetworkRule CRDs are listed.
	cutoff := r.Engine.DatapathGeneration()

	ruleList := &bgpv1alpha1.NetworkRuleList{}
	if err := r.List(ctx, ruleList, client.InNamespace(gw.Namespace)); err != nil {
		return ctrl.Result{}, fmt.Errorf("list NetworkRules for NetworkGateway %s: %w", req.NamespacedName, err)
	}

	routerName, err := r.routerNameForNode(ctx, gw.Namespace)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("resolve BGPRouter for node %s: %w", r.NodeName, err)
	}

	sidIndex, err := buildBackendSIDIndex(ctx, r.Client, gw.Namespace)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("build backend uSID index: %w", err)
	}

	desired := gateway.EngineState{Rules: make(map[string]gateway.DesiredRule)}
	type advertisementWork struct {
		rule    *bgpv1alpha1.NetworkRule
		desired gateway.DesiredRule
	}
	var work []advertisementWork

	for i := range ruleList.Items {
		rule := &ruleList.Items[i]
		if !rule.DeletionTimestamp.IsZero() {
			// Being torn down: excluded from desired state immediately, so
			// this node's rule_table converges toward gone without waiting on
			// NetworkRuleReconciler's finalizer to finish withdrawing BGP.
			continue
		}
		if !meta.IsStatusConditionTrue(rule.Status.Conditions, bgpv1alpha1.ConditionTypeAccepted) {
			continue // admission has not (yet) accepted this rule
		}

		dr, err := buildDesiredRule(rule, sidIndex)
		if err != nil {
			logger.Error(err, "build desired rule; skipping", "networkRule", rule.Name)
			continue
		}
		desired.Rules[dr.Key] = dr
		if routerName != "" {
			work = append(work, advertisementWork{rule: rule, desired: dr})
		}
	}

	status, err := r.Engine.Reconcile(ctx, desired)
	if err != nil {
		gwCopy := gw.DeepCopy()
		setGatewayCondition(gwCopy, metav1.Condition{
			Type:    bgpv1alpha1.ConditionTypeReady,
			Status:  metav1.ConditionFalse,
			Reason:  "EngineReconcileFailed",
			Message: err.Error(),
		})
		if updateErr := r.Status().Update(ctx, gwCopy); updateErr != nil {
			logger.Error(updateErr, "update NetworkGateway status after engine reconcile error")
		}
		return ctrl.Result{}, err
	}

	if routerName == "" {
		logger.Info("no BGPRouter targets this node; skipping BGPAdvertisement wiring", "node", r.NodeName)
	}
	for _, w := range work {
		if err := r.applyBGPAdvertisements(ctx, w.rule, w.desired, routerName); err != nil {
			logger.Error(err, "apply BGPAdvertisements for NetworkRule", "networkRule", w.rule.Name)
			advErrs = append(advErrs, fmt.Errorf("networkRule %s: %w", w.rule.Name, err))
		}
	}
	advErr := errors.Join(advErrs...)

	gwCopy := gw.DeepCopy()
	gwCopy.Status.ObservedGeneration = gw.Generation
	setGatewayCondition(gwCopy, readyConditionFor(status, advErr))
	if updateErr := r.Status().Update(ctx, gwCopy); updateErr != nil {
		logger.Error(updateErr, "update NetworkGateway status")
	}

	// Crash recovery. A failed sweep leaves orphaned rule_table state behind
	// until a later pass succeeds, so it is returned for retry, after the
	// status write above so the failure stays visible on the object.
	if err := r.Engine.ReconcileOrphans(ctx, desired, cutoff); err != nil {
		logger.Error(err, "reconcile orphaned rule_table state")
		return ctrl.Result{}, errors.Join(advErr, fmt.Errorf("reconcile orphaned rule_table state: %w", err))
	}

	return ctrl.Result{}, advErr
}

// readyConditionFor computes the Ready condition for a completed pass: engine
// health first, then advertisement failures. A node whose engine converged but
// whose routes never reached BGP serves no traffic, so it must not report
// reasonEngineHealthy.
func readyConditionFor(status gateway.EngineStatus, advErr error) metav1.Condition {
	switch {
	case !status.Healthy:
		return metav1.Condition{
			Type: bgpv1alpha1.ConditionTypeReady, Status: metav1.ConditionFalse,
			Reason: "EngineDegraded", Message: "one or more NetworkRules failed to apply",
		}
	case advErr != nil:
		return metav1.Condition{
			Type: bgpv1alpha1.ConditionTypeReady, Status: metav1.ConditionFalse,
			Reason: reasonAdvertisementFailed, Message: advErr.Error(),
		}
	default:
		return metav1.Condition{
			Type: bgpv1alpha1.ConditionTypeReady, Status: metav1.ConditionTrue,
			Reason: reasonEngineHealthy, Message: "gateway engine converged",
		}
	}
}

// buildDesiredRule converts rule into a gateway.DesiredRule, resolving each
// backend's SRv6 uSID through sidIndex. There is no kernel VRF or FIB
// dependency.
func buildDesiredRule(
	rule *bgpv1alpha1.NetworkRule, sidIndex *backendSIDIndex,
) (gateway.DesiredRule, error) {
	vips := make([]netip.Addr, 0, len(rule.Spec.VIPAddresses))
	for _, v := range rule.Spec.VIPAddresses {
		addr, err := netip.ParseAddr(v)
		if err != nil {
			return gateway.DesiredRule{}, fmt.Errorf("invalid VIP address %q: %w", v, err)
		}
		vips = append(vips, addr)
	}

	backends := make([]gateway.DesiredBackend, len(rule.Spec.Backends))
	for i, b := range rule.Spec.Backends {
		addr, err := netip.ParseAddr(b.Address)
		if err != nil {
			return gateway.DesiredRule{}, fmt.Errorf("invalid backend address %q: %w", b.Address, err)
		}
		usid, err := sidIndex.resolveUSID(addr, rule.Spec.VPCRef)
		if err != nil {
			return gateway.DesiredRule{}, fmt.Errorf("resolve backend %s: %w", addr, err)
		}
		//nolint:gosec // b.Port is CRD-validated to [1,65535] (Minimum/Maximum markers on NetworkRuleBackend.Port)
		backends[i] = gateway.DesiredBackend{Address: addr, Port: uint16(b.Port), USID: usid}
	}

	return gateway.DesiredRule{
		Key:              rule.Namespace + "/" + rule.Name,
		VPCRef:           rule.Spec.VPCRef,
		VPCAttachmentRef: rule.Spec.VPCAttachmentRef,
		VIPAddresses:     vips,
		Protocol:         string(rule.Spec.Protocol),
		//nolint:gosec // rule.Spec.Port is CRD-validated to [1,65535] (Minimum/Maximum markers on NetworkRuleSpec.Port)
		Port:     uint16(rule.Spec.Port),
		Backends: backends,
	}, nil
}

// routerNameForNode returns the name of the BGPRouter whose targetRef.name
// matches this node, or "" if none exists yet. A method wrapper around the
// package-level function of the same name.
func (r *NetworkGatewayReconciler) routerNameForNode(ctx context.Context, namespace string) (string, error) {
	return routerNameForNode(ctx, r.Client, namespace, r.NodeName)
}

// routerNameForNode returns the name of the BGPRouter whose targetRef.name
// matches nodeName, or "" if none exists yet. A free function so
// EgressShardReconciler can resolve the same "which BGPRouter is mine" lookup
// without duplicating it or reaching into another reconciler's method set.
func routerNameForNode(ctx context.Context, c client.Client, namespace, nodeName string) (string, error) {
	list := &bgpv1alpha1.BGPRouterList{}
	if err := c.List(ctx, list,
		client.InNamespace(namespace),
		client.MatchingFields{BGPRouterByTargetName: nodeName},
	); err != nil {
		return "", fmt.Errorf("list BGPRouters for node %s: %w", nodeName, err)
	}
	if len(list.Items) == 0 {
		return "", nil
	}
	return list.Items[0].Name, nil
}

// applyBGPAdvertisements reconciles the BGPAdvertisements for a single rule,
// one per non-empty VIP address family, with names qualified by r.NodeName.
//
// The node qualifier is required. This reconciler runs once per gateway node,
// and under the anycast model every gateway node advertises every accepted
// rule identically, so without it every node in a namespace would compute the
// same name for the same rule and race to own one shared object.
//
// No local preference is set. Every gateway node's route is equally preferred
// by construction, because each gets its own route distinguisher, which is what
// keeps the advertisements alive as independent routes instead of BGP
// collapsing them to a single best path.
//
// Every object created or touched here is labeled with networkRuleLabel,
// backfilled on existing objects too. That label is what lets rule teardown
// find every advertisement a rule ever caused on any gateway node, including
// one that has since left the namespace, without depending on this naming
// convention.
func (r *NetworkGatewayReconciler) applyBGPAdvertisements(
	ctx context.Context, rule *bgpv1alpha1.NetworkRule, desired gateway.DesiredRule, routerName string,
) error {
	v4Prefixes, v6Prefixes := prefixesByFamily(desired.VIPAddresses)

	groups := []struct {
		suffix   string
		prefixes []string
	}{
		{"v4", v4Prefixes},
		{"v6", v6Prefixes},
	}

	var firstErr error
	for _, g := range groups {
		if len(g.prefixes) == 0 {
			continue
		}
		name := rule.Name + "-" + r.NodeName + "-" + g.suffix
		// Built as l2vpn/evpn whatever the VIP's own family, since the runtime
		// never originates plain unicast advertisements. The per-family split
		// still matters because one EVPN IP-Prefix route's Prefix field is
		// single-family, so a dual-stack rule needs two advertisements.

		prefixes := make([]bgpv1alpha1.Prefix, len(g.prefixes))
		for i, p := range g.prefixes {
			prefixes[i] = bgpv1alpha1.Prefix(p)
		}

		adv := &bgpv1alpha1.BGPAdvertisement{}
		key := types.NamespacedName{Namespace: rule.Namespace, Name: name}
		err := r.Get(ctx, key, adv)
		switch {
		case apierrors.IsNotFound(err):
			adv = &bgpv1alpha1.BGPAdvertisement{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: rule.Namespace,
					Name:      name,
					Labels:    map[string]string{networkRuleLabel: rule.Name},
				},
				Spec: bgpv1alpha1.BGPAdvertisementSpec{
					RouterRef:     bgpv1alpha1.RouterRef{Name: routerName},
					AddressFamily: bgpv1alpha1.AddressFamily{AFI: bgpv1alpha1.AFIL2VPN, SAFI: bgpv1alpha1.SAFIEVPN},
					Prefixes:      prefixes,
				},
			}
			if createErr := r.Create(ctx, adv); createErr != nil && firstErr == nil {
				firstErr = fmt.Errorf("create BGPAdvertisement %s: %w", name, createErr)
			}
			continue
		case err != nil:
			if firstErr == nil {
				firstErr = fmt.Errorf("get BGPAdvertisement %s: %w", name, err)
			}
			continue
		}

		advCopy := adv.DeepCopy()
		// Backfill networkRuleLabel on an advertisement created before the
		// label existed, so teardown's label-selector list finds it too.
		if advCopy.Labels == nil {
			advCopy.Labels = map[string]string{}
		}
		advCopy.Labels[networkRuleLabel] = rule.Name
		advCopy.Spec.RouterRef = bgpv1alpha1.RouterRef{Name: routerName}
		advCopy.Spec.AddressFamily = bgpv1alpha1.AddressFamily{AFI: bgpv1alpha1.AFIL2VPN, SAFI: bgpv1alpha1.SAFIEVPN}
		advCopy.Spec.Prefixes = prefixes
		if updateErr := r.Update(ctx, advCopy); updateErr != nil && firstErr == nil {
			firstErr = fmt.Errorf("update BGPAdvertisement %s: %w", name, updateErr)
		}
	}
	return firstErr
}

// prefixesByFamily splits vips into IPv4 and IPv6 host-prefix strings
// (/32 or /128).
func prefixesByFamily(vips []netip.Addr) (v4, v6 []string) {
	for _, vip := range vips {
		prefix := netip.PrefixFrom(vip, vip.BitLen())
		if vip.Is4() {
			v4 = append(v4, prefix.String())
		} else {
			v6 = append(v6, prefix.String())
		}
	}
	return v4, v6
}

// SetupWithManager registers the NetworkGatewayReconciler with the manager.
func (r *NetworkGatewayReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&bgpv1alpha1.NetworkGateway{}).
		Watches(&bgpv1alpha1.NetworkRule{}, handler.EnqueueRequestsFromMapFunc(
			func(ctx context.Context, obj client.Object) []ctrlreconcile.Request {
				return ruleToGatewayRequests(ctx, r.Client, obj)
			}),
		).
		// Backend uSIDs resolve from BGPRouter, BGPAdvertisement, and
		// BGPVRFInstance, so all three must be watched. A backend whose owning
		// BGPAdvertisement does not exist yet at reconcile time, a real
		// startup race, fails that rule with "no BGPAdvertisement owned by VPC
		// ... found": the error is logged and the rule skipped rather than
		// requeued, so without these watches nothing would trigger another
		// reconcile and the rule would stay broken until an unrelated event.
		// Each broadcasts to every NetworkGateway in the namespace, since any
		// of them could be the one waiting on this object.
		Watches(&bgpv1alpha1.BGPRouter{}, handler.EnqueueRequestsFromMapFunc(
			func(ctx context.Context, obj client.Object) []ctrlreconcile.Request {
				return broadcastToGatewayRequests(ctx, r.Client, obj.GetNamespace(), "BGPRouter", obj.GetName())
			}),
		).
		Watches(&bgpv1alpha1.BGPAdvertisement{}, handler.EnqueueRequestsFromMapFunc(
			func(ctx context.Context, obj client.Object) []ctrlreconcile.Request {
				return broadcastToGatewayRequests(ctx, r.Client, obj.GetNamespace(), "BGPAdvertisement", obj.GetName())
			}),
		).
		Watches(&bgpv1alpha1.BGPVRFInstance{}, handler.EnqueueRequestsFromMapFunc(
			func(ctx context.Context, obj client.Object) []ctrlreconcile.Request {
				return broadcastToGatewayRequests(ctx, r.Client, obj.GetNamespace(), "BGPVRFInstance", obj.GetName())
			}),
		).
		Named("networkgateway").
		Complete(r)
}

// ruleToGatewayRequests maps a NetworkRule change to every NetworkGateway in
// its namespace. A NetworkRule carries no gatewayRef, and under the
// Active-Active model every gateway node in the rule's PoP must re-evaluate its
// own engine state whenever any rule changes, so the broadcast is intentional
// rather than a missing index.
func ruleToGatewayRequests(ctx context.Context, c client.Client, obj client.Object) []ctrlreconcile.Request {
	rule, ok := obj.(*bgpv1alpha1.NetworkRule)
	if !ok {
		return nil
	}
	return broadcastToGatewayRequests(ctx, c, rule.Namespace, "NetworkRule", rule.Name)
}

// broadcastToGatewayRequests lists every NetworkGateway in namespace and
// returns a reconcile request for each. It is the primitive the NetworkRule,
// BGPRouter, BGPAdvertisement, and BGPVRFInstance watches all build on.
// sourceKind and sourceName appear only in the list-failure log line.
func broadcastToGatewayRequests(
	ctx context.Context, c client.Client, namespace, sourceKind, sourceName string,
) []ctrlreconcile.Request {
	logger := log.FromContext(ctx)

	gwList := &bgpv1alpha1.NetworkGatewayList{}
	if err := c.List(ctx, gwList, client.InNamespace(namespace)); err != nil {
		logger.Error(err, "list NetworkGateways for change", "sourceKind", sourceKind, "sourceName", sourceName)
		return nil
	}
	reqs := make([]ctrlreconcile.Request, 0, len(gwList.Items))
	for _, gw := range gwList.Items {
		reqs = append(reqs, ctrlreconcile.Request{
			NamespacedName: types.NamespacedName{Namespace: gw.Namespace, Name: gw.Name},
		})
	}
	return reqs
}

// gatewayNodeNames returns the targetRef.name of every NetworkGateway in
// namespace, the pool of gateway nodes for this PoP.
func gatewayNodeNames(ctx context.Context, c client.Client, namespace string) ([]string, error) {
	list := &bgpv1alpha1.NetworkGatewayList{}
	if err := c.List(ctx, list, client.InNamespace(namespace)); err != nil {
		return nil, fmt.Errorf("list NetworkGateways: %w", err)
	}
	names := make([]string, 0, len(list.Items))
	for _, gw := range list.Items {
		names = append(names, gw.Spec.TargetRef.Name)
	}
	return names, nil
}

// isGatewayNode reports whether nodeName is one of namespace's registered
// gateway nodes. NetworkRuleReconciler uses it to scope its per-object
// lifecycle work to gateway-role nodes, so every other node's router process
// leaves NetworkRule objects alone.
func isGatewayNode(ctx context.Context, c client.Client, namespace, nodeName string) (bool, error) {
	names, err := gatewayNodeNames(ctx, c, namespace)
	if err != nil {
		return false, err
	}
	for _, n := range names {
		if n == nodeName {
			return true, nil
		}
	}
	return false, nil
}

// withdrawNodeAdvertisements deletes every BGPAdvertisement that gateway node
// nodeName created in namespace: each per-rule, per-address-family route it
// advertised, found by the "<rule>-<node>-v4"/"-v6" names applyBGPAdvertisements
// gives them.
//
// It selects by name rather than by label, the mirror image of how rule
// teardown works. That path lists every advertisement a rule caused, whatever
// node made it, because the namespace's current gateway membership no longer
// includes a node that has left. Here the gap runs the other way: nothing
// enumerates every rule a node ever advertised, least of all once the rule
// itself is deleted. Selecting by name needs no rule object, live or deleted,
// and no label backfill from a node that is already gone.
//
// nodeName is the departing node's identity, not the caller's. The caller may
// be any surviving gateway node's process, most likely because the departing
// node's process is already gone, which is why its NetworkGateway was deleted.
// Surviving nodes racing this same sweep is expected and harmless, since every
// delete is idempotent.
func withdrawNodeAdvertisements(ctx context.Context, c client.Client, namespace, nodeName string) error {
	advList := &bgpv1alpha1.BGPAdvertisementList{}
	if err := c.List(ctx, advList, client.InNamespace(namespace)); err != nil {
		return fmt.Errorf("list BGPAdvertisements for departed gateway node %s: %w", nodeName, err)
	}

	v4Suffix := "-" + nodeName + "-v4"
	v6Suffix := "-" + nodeName + "-v6"

	var errs []error
	for i := range advList.Items {
		adv := &advList.Items[i]
		if !strings.HasSuffix(adv.Name, v4Suffix) && !strings.HasSuffix(adv.Name, v6Suffix) {
			continue
		}
		if err := c.Delete(ctx, adv); err != nil && !apierrors.IsNotFound(err) {
			errs = append(errs, fmt.Errorf("withdraw BGPAdvertisement %s: %w", adv.Name, err))
		}
	}
	return errors.Join(errs...)
}
