// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

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
// It does four things per reconcile:
//
//  1. Publishes SRv6Address into status and advertises it into BGP (a
//     plain /128 host prefix, no VRFID/Function — see
//     publishSelfAddress's doc comment for why computing it dynamically
//     from this node's own BGPRouter at the reserved uSID Argument 0, as
//     the NetworkGateway CRD's own doc comment describes as the eventual
//     design, is deliberately deferred rather than half-built here).
//  2. Assembles a gateway.EngineState from every accepted, non-deleting
//     NetworkRule in this namespace (both primary- and secondary-assigned —
//     the Active-Active BGP model requires every gateway node in a PoP to
//     serve every rule, see gateway.LocalPreference), resolving each
//     backend's SRv6 uSID via buildBackendSIDIndex, and converges Engine
//     toward it.
//  3. Reconciles a BGPAdvertisement per rule per VIP address family, with
//     Spec.LocalPreference computed by gateway.LocalPreference. This reuses
//     the BGP API's existing l2vpn/evpn Type-5 IP-Prefix advertisement path
//     end-to-end unmodified: internal/reconcile/reconcile.go's
//     BuildDesiredRouter already passes BGPAdvertisement.Spec.LocalPreference
//     straight through to model.DesiredAdvertisement.LocalPreference, and
//     internal/runtime/gobgp/paths.go's buildEVPNPaths already attaches it
//     as a BGP LOCAL_PREF path attribute — no changes were needed in either
//     file. (Plain ipv4/ipv6-unicast BGPAdvertisements are accepted by
//     internal/reconcile/reconcile.go's validateAFI but are never actually
//     originated by internal/runtime/gobgp/runtime.go's Apply — only
//     l2vpn/evpn advertisements reach applyEVPN — which is why these
//     advertisements are built as l2vpn/evpn rather than plain unicast.)
//     VRFID/Function are left unset: these advertisements need no SRv6
//     decap behavior of their own (deriveRD falls back to "routerID:0"),
//     they exist purely to distribute "which gateway node currently holds
//     this VIP, at what preference" over the existing iBGP/EVPN mesh.
//  4. Runs Engine.ReconcileOrphans for crash recovery.
type NetworkGatewayReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	Engine GatewayEngine

	NodeName string

	// SRv6Address is this node's own SRv6-reachable address, used as the
	// Full-NAT SNAT source (config.GatewayConfig.SRv6Address, already the
	// address the running datapath was configured with — see
	// cmd/galactic-gateway/gateway.go's setupGatewayDatapath). This
	// reconciler publishes it, it does not compute it; see
	// publishSelfAddress's doc comment.
	SRv6Address string
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
			stillOwned, checkErr := isGatewayNode(ctx, r.Client, req.Namespace, r.NodeName)
			if checkErr != nil {
				return ctrl.Result{}, fmt.Errorf("check for this node's own NetworkGateway: %w", checkErr)
			}
			if stillOwned {
				return ctrl.Result{}, nil
			}
			if stopErr := r.Engine.Stop(ctx); stopErr != nil {
				logger.Error(stopErr, "stop gateway engine for deleted NetworkGateway", "networkGateway", req.NamespacedName)
			}
			return ctrl.Result{}, nil
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
		if stopErr := r.Engine.Stop(ctx); stopErr != nil {
			logger.Error(stopErr, "stop gateway engine for terminating NetworkGateway", "networkGateway", req.NamespacedName)
		}
		gwCopy := gw.DeepCopy()
		setGatewayCondition(gwCopy, metav1.Condition{
			Type:    bgpv1alpha1.ConditionTypeReady,
			Status:  metav1.ConditionFalse,
			Reason:  "Terminating",
			Message: "NetworkGateway is being deleted",
		})
		if updateErr := r.Status().Update(ctx, gwCopy); updateErr != nil {
			logger.Error(updateErr, "update status for terminating NetworkGateway")
		}
		return ctrl.Result{}, nil
	}

	// Advertisement failures are collected rather than returned on the spot:
	// the rest of the pass still runs (one bad rule must not stop the
	// others), then they are reported on the object as
	// reasonAdvertisementFailed and returned, so controller-runtime retries
	// with backoff instead of leaving a node that advertised nothing
	// claiming EngineHealthy (#365).
	var advErrs []error
	if err := r.publishSelfAddress(ctx, gw); err != nil {
		logger.Error(err, "publish gateway self-address", "networkGateway", req.NamespacedName)
		advErrs = append(advErrs, fmt.Errorf("publish self-address: %w", err))
	}

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
		if rule.Status.PrimaryNode == "" {
			continue // not yet assigned by NetworkRuleReconciler
		}
		if !meta.IsStatusConditionTrue(rule.Status.Conditions, bgpv1alpha1.ConditionTypeAccepted) {
			continue // admission has not (yet) accepted this rule
		}

		localPref := gateway.LocalPreference(r.NodeName, rule.Status.PrimaryNode)
		dr, err := buildDesiredRule(rule, sidIndex, localPref)
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

// publishSelfAddress sets gw.Status.SRv6Address to r.SRv6Address and
// ensures a BGPAdvertisement exists distributing it as a /128 host route.
//
// The NetworkGateway CRD's own doc comment describes SRv6Address as
// eventually computed by "the engine" from this node's own BGPRouter
// locator/node-ID at the reserved uSID Argument 0 (uformat.go's
// ArgumentMin=0x001 — Argument 0 is reserved specifically so it is never
// registered into any tenant's vrf_table). That computation is genuinely
// new: srv6.ComputeSID unconditionally rejects argument==0 (it exists to
// serve tenant-VRF SID derivation, where 0 must never be assigned), so
// deriving the Argument-0 address requires a second, narrower encode path
// bypassing that guard — real work this phase intentionally does not
// build. Today SRv6Address is instead supplied via operator config
// (config.GatewayConfig.SRv6Address) and is the exact value
// cmd/galactic-gateway/gateway.go's setupGatewayDatapath already wrote into
// the running datapath's gw_config_table; this method's only job is to
// publish that already-authoritative value into the CRD and into BGP, so
// there is exactly one source of truth rather than two that could drift.
//
// This advertisement carries no VRFID/Function, unlike a backend Pod's own
// advertisement: SRv6Address is not reached via a per-tenant VRF decap at
// all (see the CRD doc comment's "must never be registered into any
// tenant VRF" guarantee) — it is a plain node-reachability route, the same
// shape as any other host's own loopback prefix.
func (r *NetworkGatewayReconciler) publishSelfAddress(ctx context.Context, gw *bgpv1alpha1.NetworkGateway) error {
	if r.SRv6Address == "" {
		return nil // this galactic-router process is not gateway-role
	}

	routerName, err := r.routerNameForNode(ctx, gw.Namespace)
	if err != nil {
		return fmt.Errorf("resolve BGPRouter for node %s: %w", r.NodeName, err)
	}

	if gw.Status.SRv6Address != r.SRv6Address {
		// Updated in place, not through a copy: Reconcile writes the Ready
		// condition from this same object afterwards, and a copy would leave
		// it holding a stale resourceVersion — losing that write to a
		// conflict on exactly the pass whose outcome matters most (#365).
		gw.Status.SRv6Address = r.SRv6Address
		if err := r.Status().Update(ctx, gw); err != nil {
			return fmt.Errorf("update NetworkGateway status.sRv6Address: %w", err)
		}
	}

	if routerName == "" {
		return nil // nothing to advertise into yet
	}

	addr, err := netip.ParseAddr(r.SRv6Address)
	if err != nil {
		return fmt.Errorf("parse gateway SRv6 address %q: %w", r.SRv6Address, err)
	}
	prefix := netip.PrefixFrom(addr, addr.BitLen())

	name := gw.Name + "-selfaddr"
	adv := &bgpv1alpha1.BGPAdvertisement{}
	key := types.NamespacedName{Namespace: gw.Namespace, Name: name}
	getErr := r.Get(ctx, key, adv)
	switch {
	case apierrors.IsNotFound(getErr):
		adv = &bgpv1alpha1.BGPAdvertisement{
			ObjectMeta: metav1.ObjectMeta{Namespace: gw.Namespace, Name: name},
			Spec: bgpv1alpha1.BGPAdvertisementSpec{
				RouterRef:     bgpv1alpha1.RouterRef{Name: routerName},
				AddressFamily: bgpv1alpha1.AddressFamily{AFI: bgpv1alpha1.AFIL2VPN, SAFI: bgpv1alpha1.SAFIEVPN},
				Prefixes:      []bgpv1alpha1.Prefix{bgpv1alpha1.Prefix(prefix.String())},
			},
		}
		if createErr := r.Create(ctx, adv); createErr != nil {
			return fmt.Errorf("create self-address BGPAdvertisement %s: %w", name, createErr)
		}
		return nil
	case getErr != nil:
		return fmt.Errorf("get self-address BGPAdvertisement %s: %w", name, getErr)
	}

	advCopy := adv.DeepCopy()
	advCopy.Spec.RouterRef = bgpv1alpha1.RouterRef{Name: routerName}
	advCopy.Spec.AddressFamily = bgpv1alpha1.AddressFamily{AFI: bgpv1alpha1.AFIL2VPN, SAFI: bgpv1alpha1.SAFIEVPN}
	advCopy.Spec.Prefixes = []bgpv1alpha1.Prefix{bgpv1alpha1.Prefix(prefix.String())}
	if updateErr := r.Update(ctx, advCopy); updateErr != nil {
		return fmt.Errorf("update self-address BGPAdvertisement %s: %w", name, updateErr)
	}
	return nil
}

// buildDesiredRule converts rule into a gateway.DesiredRule, resolving each
// backend's SRv6 uSID via sidIndex (design plan decision #5) — there is no
// kernel VRF/FIB dependency here at all (decision #4), unlike an earlier,
// rejected design's identically-named function.
func buildDesiredRule(
	rule *bgpv1alpha1.NetworkRule, sidIndex *backendSIDIndex, localPref uint32,
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
		usid, err := sidIndex.resolveUSID(addr)
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
		Port:      uint16(rule.Spec.Port),
		Backends:  backends,
		LocalPref: localPref,
		IsPrimary: localPref == gateway.PrimaryLocalPref,
	}, nil
}

// routerNameForNode returns the name of the BGPRouter whose targetRef.name
// matches this node, or "" if none exists yet.
func (r *NetworkGatewayReconciler) routerNameForNode(ctx context.Context, namespace string) (string, error) {
	list := &bgpv1alpha1.BGPRouterList{}
	if err := r.List(ctx, list,
		client.InNamespace(namespace),
		client.MatchingFields{BGPRouterByTargetName: r.NodeName},
	); err != nil {
		return "", fmt.Errorf("list BGPRouters for node %s: %w", r.NodeName, err)
	}
	if len(list.Items) == 0 {
		return "", nil
	}
	return list.Items[0].Name, nil
}

// applyBGPAdvertisements reconciles the BGPAdvertisement object(s) for a
// single rule — one per non-empty VIP address family, name-qualified by
// r.NodeName, per bgpAdvertisementNamesForRule's naming convention (shared
// with networkrule_controller.go's teardown logic, so both sides always
// agree on which objects exist for a given rule). The node qualifier is
// required, not cosmetic: this reconciler runs once per gateway node
// (Active-Active — every gateway node advertises every rule it holds, at
// its own local preference, see this file's package doc comment), so
// without it every gateway node in a namespace would compute the exact
// same name for the same rule and race to create/update a single shared
// object — confirmed live the first time a rule's primary node differed
// from the first node to reconcile it: the second node's Create failed
// with AlreadyExists on every pass, forever, and only the first node's
// advertisement (and therefore only its BGP path) ever existed.
func (r *NetworkGatewayReconciler) applyBGPAdvertisements(
	ctx context.Context, rule *bgpv1alpha1.NetworkRule, desired gateway.DesiredRule, routerName string,
) error {
	v4Prefixes, v6Prefixes := prefixesByFamily(desired.VIPAddresses)
	localPref := int32(desired.LocalPref) //nolint:gosec // LocalPreference is bounded to {50,100}

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
				ObjectMeta: metav1.ObjectMeta{Namespace: rule.Namespace, Name: name},
				Spec: bgpv1alpha1.BGPAdvertisementSpec{
					RouterRef:       bgpv1alpha1.RouterRef{Name: routerName},
					AddressFamily:   bgpv1alpha1.AddressFamily{AFI: bgpv1alpha1.AFIL2VPN, SAFI: bgpv1alpha1.SAFIEVPN},
					Prefixes:        prefixes,
					LocalPreference: &localPref,
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
		advCopy.Spec.RouterRef = bgpv1alpha1.RouterRef{Name: routerName}
		advCopy.Spec.AddressFamily = bgpv1alpha1.AddressFamily{AFI: bgpv1alpha1.AFIL2VPN, SAFI: bgpv1alpha1.SAFIEVPN}
		advCopy.Spec.Prefixes = prefixes
		advCopy.Spec.LocalPreference = &localPref
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
	logger := log.FromContext(ctx)

	gwList := &bgpv1alpha1.NetworkGatewayList{}
	if err := c.List(ctx, gwList, client.InNamespace(rule.Namespace)); err != nil {
		logger.Error(err, "list NetworkGateways for NetworkRule change", "networkRule", rule.Name)
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
