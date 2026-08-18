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

// GatewayEngine is the interface NetworkGatewayReconciler drives, satisfied
// by *gateway.Engine in production and a fake in tests — the same
// interface-seam pattern galacticruntime.RuntimeManager provides for
// BGPRouterReconciler.
//
// Unlike an earlier, rejected design's identically-named
// interface, there is no SetVRFLink: this engine has no kernel VRF/Geneve
// dependency at all (design plan decision #4).
type GatewayEngine interface {
	// Reconcile converges the engine's live state toward desired.
	Reconcile(ctx context.Context, desired gateway.EngineState) (gateway.EngineStatus, error)

	// DatapathGeneration returns the datapath's current generation
	// counter. Must be captured before desired's NetworkRule CRDs are
	// listed — see ReconcileOrphans's doc comment.
	DatapathGeneration() uint64

	// ReconcileOrphans cleans up rule_table state left behind by a
	// mid-reconcile crash — see gateway.Engine.ReconcileOrphans. cutoff
	// must have been obtained from DatapathGeneration before desired's
	// NetworkRule CRDs were listed.
	ReconcileOrphans(ctx context.Context, desired gateway.EngineState, cutoff uint64) error

	// Stop tears down every currently-active rule.
	Stop(ctx context.Context) error
}

// NetworkGatewayReconciler reconciles the single NetworkGateway object for
// this node (spec.targetRef.name == NodeName), mirroring BGPRouterReconciler's
// "does real reconcile work" pattern — NetworkGateway is the node-scoped
// root object, exactly like BGPRouter.
//
// It does three things per reconcile:
//
//  1. Assembles a gateway.EngineState from every accepted, non-deleting
//     NetworkRule in this namespace — under DSR's anycast model (design
//     plan §0) every gateway node in a PoP serves every accepted rule
//     identically, with no primary/secondary distinction to gate on (an
//     earlier, Full-NAT-era version of this reconciler excluded rules with
//     no status.primaryNode assigned; that field and the active-passive
//     model it implemented no longer exist) — resolving each backend's
//     SRv6 uSID via buildBackendSIDIndex, and converges Engine toward it.
//  2. Reconciles a BGPAdvertisement per rule per VIP address family. This
//     reuses the BGP API's existing l2vpn/evpn Type-5 IP-Prefix
//     advertisement path end-to-end unmodified. VRFID/Function are left
//     unset: these advertisements need no SRv6 decap behavior of their
//     own (deriveRD falls back to "routerID:0", a different RD per
//     originating node — see the go/no-go anycast spike,
//     internal/runtime/gobgp/anycast_spike_test.go — which is exactly
//     what lets every gateway node's identical-prefix advertisement
//     survive as an independent, non-competing route rather than one
//     silently replacing another). No LocalPreference is set: unlike the
//     removed Full-NAT design's primary/secondary local-pref split, every
//     gateway node's route is equally preferred by construction — RD
//     independence, not BGP preference, is what keeps every node's route
//     alive over the iBGP/EVPN mesh.
//  3. Runs Engine.ReconcileOrphans for crash recovery.
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

	// reasonAdvertisementFailed is the Ready condition reason for a node
	// whose engine converged but which could not publish one or more of the
	// BGPAdvertisements that make that convergence reachable — its own
	// self-address route, or a rule's VIP route. Such a node serves
	// nothing, so it must not report reasonEngineHealthy (#365).
	reasonAdvertisementFailed = "AdvertisementFailed"

	// reasonTerminating is the Ready condition reason for a NetworkGateway
	// that is being deleted, whether observed via a live object still
	// carrying a DeletionTimestamp or reconstructed for the NotFound case
	// where the object is already gone (see Reconcile's two
	// withdrawNodeAdvertisements call sites).
	reasonTerminating = "Terminating"
)

// Reconcile reconciles a single NetworkGateway.
func (r *NetworkGatewayReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	gw := &bgpv1alpha1.NetworkGateway{}
	if err := r.Get(ctx, req.NamespacedName, gw); err != nil {
		if apierrors.IsNotFound(err) {
			// Every gateway node's process reconciles every NetworkGateway
			// in the namespace (SetupWithManager has no predicate), so a
			// sibling node's deletion reaches this reconciler too, and by
			// the time we get here the deleted object can no longer be
			// read to check whose it was. Ask instead whether *some*
			// NetworkGateway still targets this node: if one does, this
			// node's own object is untouched and its engine must keep
			// running. Only stop when this node no longer has a
			// NetworkGateway of its own -- otherwise one node's deletion
			// tears down every other gateway node's data plane too (#364).
			//
			// req.Name is the departed NetworkGateway's own name, which by
			// this repo's own convention (every NetworkGateway fixture and
			// deployment overlay) is always that node's node name -- the
			// same identity applyBGPAdvertisements/publishSelfAddress
			// already used to name every advertisement it created. This is
			// the reachable path for #406: without a finalizer on
			// NetworkGateway (there is none), this reconciler never
			// observes a live object with a deletion timestamp for a node
			// that has already left -- the object is simply gone by the
			// time any process's Get runs, on whichever node's process
			// happens to handle the event. Withdrawing here, keyed on
			// req.Name rather than r.NodeName, is what makes that node's
			// own advertisements go away even though its own process is
			// the one most likely already gone.
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

	// Node check: skip gateways that don't target this node, mirroring
	// BGPRouterReconciler/internal/reconcile.Reconciler.BuildDesiredRouter's
	// own targetRef.Name check.
	if gw.Spec.TargetRef.Name != r.NodeName {
		return ctrl.Result{}, nil
	}

	if !gw.DeletionTimestamp.IsZero() {
		// Withdrawn before Engine.Stop, not after: the reverse order would
		// leave a window where this node's forwarding state is already
		// gone but BGP still advertises it as a valid destination -- the
		// exact blackhole #406 reports, just moved one step earlier
		// instead of eliminated. This branch is not known to be reachable
		// today (NetworkGateway carries no finalizer, so a deletion
		// ordinarily removes the object before any Get here observes a
		// live DeletionTimestamp -- see the NotFound branch above, which
		// is), but it costs nothing to keep it correct in case a finalizer
		// is added later or another controller races this Get.
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

	// Advertisement failures are collected rather than returned on the spot:
	// the rest of the pass still runs (one bad rule must not stop the
	// others), then they are reported on the object as
	// reasonAdvertisementFailed and returned, so controller-runtime retries
	// with backoff instead of leaving a node that advertised nothing
	// claiming EngineHealthy (#365).
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
			// Being torn down: exclude from desired state immediately so
			// this node's rule_table state converges towards "gone"
			// without waiting on NetworkRuleReconciler's finalizer to
			// finish the BGP-withdrawal step first (see that reconciler's
			// doc comment on why the two aren't cross-node-synchronized).
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

	// Crash recovery (see GatewayEngine.ReconcileOrphans): a failed sweep
	// leaves orphaned rule_table state behind until some later pass
	// succeeds, so it is returned for retry too, after the status write
	// above so the failure is still visible on the object.
	if err := r.Engine.ReconcileOrphans(ctx, desired, cutoff); err != nil {
		logger.Error(err, "reconcile orphaned rule_table state")
		return ctrl.Result{}, errors.Join(advErr, fmt.Errorf("reconcile orphaned rule_table state: %w", err))
	}

	return ctrl.Result{}, advErr
}

// readyConditionFor computes the Ready condition for a completed pass:
// engine health first, then advertisement failures — a node whose engine
// converged but whose routes never reached BGP serves no traffic, so it
// must not report reasonEngineHealthy (#365).
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
// backend's SRv6 uSID via sidIndex (design plan decision #5) — there is no
// kernel VRF/FIB dependency here at all (decision #4), unlike an earlier,
// rejected design's identically-named function.
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
// matches this node, or "" if none exists yet. Thin wrapper around the
// package-level routerNameForNode, kept as a method so existing call sites
// and tests don't need to change.
func (r *NetworkGatewayReconciler) routerNameForNode(ctx context.Context, namespace string) (string, error) {
	return routerNameForNode(ctx, r.Client, namespace, r.NodeName)
}

// routerNameForNode returns the name of the BGPRouter whose targetRef.name
// matches nodeName, or "" if none exists yet. Extracted as a free function
// (originally a NetworkGatewayReconciler method only) so
// NAT66ShardReconciler's own shard-SID advertisement (nat66shard_controller.go)
// can resolve the same "which BGPRouter is mine" lookup without either
// duplicating it or reaching into a sibling reconciler's method set.
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

// applyBGPAdvertisements reconciles the BGPAdvertisement object(s) for a
// single rule — one per non-empty VIP address family, name-qualified by
// r.NodeName. The node qualifier is required, not cosmetic: this reconciler
// runs once per gateway node, and under DSR's anycast model every gateway
// node advertises every accepted rule it holds identically (see this file's
// package doc comment) — without the node qualifier, every gateway node in
// a namespace would compute the exact same name for the same rule and race
// to create/update a single shared object, the same AlreadyExists failure
// mode the removed Full-NAT/primary-secondary design already hit live.
//
// No LocalPreference is set on these advertisements: unlike that removed
// design (which split PrimaryLocalPref/SecondaryLocalPref to pick one
// "best" node), every gateway node's route here is equally preferred by
// construction — each one gets its own distinct Route Distinguisher
// (paths.go's deriveRD, RFC 4364 §4.3.2), which is what keeps every node's
// advertisement alive as an independent, non-competing route rather than
// BGP collapsing them to a single best path (see the go/no-go anycast
// spike, internal/runtime/gobgp/anycast_spike_test.go).
//
// Every object created or touched here is also labeled with
// networkRuleLabel (backfilled on existing objects too), which is what lets
// networkrule_controller.go's teardown find every advertisement this rule
// ever caused across every gateway node — including one for a node that
// has since left the namespace — without depending on this naming
// convention at all; see networkRuleLabel's doc comment.
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
		// This advertisement is built as l2vpn/evpn regardless of the VIP's
		// own IPv4/IPv6 family — see this reconciler's doc comment for why
		// (plain ipv4/ipv6-unicast BGPAdvertisements are never actually
		// originated by the runtime). The per-family split still matters
		// because a single EVPN IP-Prefix route's own Prefix field is
		// single-family (see internal/runtime/gobgp/paths.go's
		// gatewayForPrefix), so a dual-stack rule needs two advertisements.

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
		// Backfills networkRuleLabel on an advertisement created before this
		// label existed, so teardown's label-selector List (see
		// networkrule_controller.go's reconcileDelete) finds it too — self-
		// healing, not just a create-time concern.
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
		// buildBackendSIDIndex (via buildDesiredRule) resolves each rule's
		// backend uSID from BGPRouter/BGPAdvertisement/BGPVRFInstance, but
		// none of those were ever watched -- only NetworkRule/NetworkGateway
		// themselves. A backend whose owning BGPAdvertisement doesn't exist
		// yet at reconcile time (a real, observed startup race: this
		// reconciler's own initial reconcile can run before
		// NetworkRuleReconciler/galactic-router have created and
		// re-reconciled it) permanently fails that rule with "no
		// BGPAdvertisement owned by VPC ... found" -- buildDesiredRule's
		// error is logged and the rule is skipped, not requeued, and
		// nothing the reconciler *does* watch ever changes afterward, so
		// the rule stays broken until something unrelated (a NetworkRule
		// edit, a pod restart) happens to trigger another reconcile. These
		// three watches close that gap the same way NetworkRule's own
		// watch does: broadcast to every NetworkGateway in the namespace,
		// since any of them could be the one whose backend resolution was
		// waiting on this exact object.
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

// ruleToGatewayRequests maps a NetworkRule change to every NetworkGateway
// in its namespace. Unlike peerToRouterRequests (which targets exactly the
// BGPPeer's own routerRef), a NetworkRule carries no gatewayRef — the
// Active-Active BGP model means every gateway node in a rule's PoP
// (namespace, in this containerlab-style one-PoP-per-cluster deployment)
// must re-evaluate its own local-pref and engine state whenever any rule
// changes, so this is an intentional broadcast rather than a missing index.
func ruleToGatewayRequests(ctx context.Context, c client.Client, obj client.Object) []ctrlreconcile.Request {
	rule, ok := obj.(*bgpv1alpha1.NetworkRule)
	if !ok {
		return nil
	}
	return broadcastToGatewayRequests(ctx, c, rule.Namespace, "NetworkRule", rule.Name)
}

// broadcastToGatewayRequests lists every NetworkGateway in namespace and
// returns a reconcile request for each — the shared primitive
// ruleToGatewayRequests and SetupWithManager's BGPRouter/BGPAdvertisement/
// BGPVRFInstance watches all build on. sourceKind/sourceName are for the
// list-failure log line only.
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
// namespace — the pool of gateway nodes for this PoP that
// gateway.AssignPrimaryNode chooses from.
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
// gateway nodes. NetworkRuleReconciler uses this to scope its per-object
// lifecycle work (finalizer, primary_node assignment) to gateway-role nodes
// only — every other node's galactic-router process leaves NetworkRule
// objects alone.
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

// withdrawNodeAdvertisements deletes every BGPAdvertisement that gateway
// node nodeName created in namespace: every per-rule, per-address-family
// route it advertised (named "<rule>-<node>-v4"/"-v6" -- see
// applyBGPAdvertisements). An earlier, Full-NAT-era version of this
// function also withdrew a "<node>-selfaddr" self-address route
// (publishSelfAddress); DSR's anycast model has no self-address to
// publish at all (no gateway node rewrites addresses, so none needs its
// own reachable SNAT source advertised — see this file's package doc
// comment), so that name pattern no longer applies here.
//
// This is issue #367's teardown fix in reverse. That fix
// (networkRuleLabel, networkrule_controller.go's reconcileDelete)
// withdraws every advertisement a *rule* caused, no matter which node
// created it, discovered by List + label selector rather than
// reconstructed names because the namespace's *current* gateway-node
// membership no longer includes a node that has since left. The same
// blind spot exists here in the other direction: a rule's own
// advertisement is name-qualified by the node that created it, but
// nothing lists "every rule this node ever advertised" the way
// networkRuleLabel lists "every node that ever advertised this rule" --
// especially once the rule itself has been deleted and left no object to
// enumerate backwards from. Selecting by NAME rather than by a new label
// sidesteps that: it needs no rule object, live or deleted, and no label
// backfill pass from a node that is gone by the time this runs -- the
// exact self-healing gap issue #406's own "label backfill" note flags for
// networkRuleLabel would otherwise repeat here for a brand new label.
//
// Called with the departing node's own identity, not r.NodeName: the
// caller may be running on any surviving gateway node's process (every
// gateway node's process reconciles every NetworkGateway in the
// namespace, see Reconcile's NotFound branch), most likely because the
// departing node's own process is already gone -- that is exactly why
// its NetworkGateway object got deleted in the first place. Concurrent
// callers across surviving nodes racing this same sweep for the same
// departed node is expected and harmless: every delete here is
// idempotent (not-found is not an error).
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
