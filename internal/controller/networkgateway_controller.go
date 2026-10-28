// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	ctrlreconcile "sigs.k8s.io/controller-runtime/pkg/reconcile"

	cloudv1alpha1 "go.datum.net/galactic/api/cloud/v1alpha1"
	bgpv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	"go.datum.net/galactic/internal/gateway"
)

// GatewayEngine is the interface NetworkGatewayReconciler drives, satisfied by
// *gateway.Engine in production and a fake in tests. The engine has no kernel
// VRF or Geneve dependency, so nothing here sets up a link.
type GatewayEngine interface {
	// Reconcile converges the engine's live state toward desired.
	Reconcile(ctx context.Context, desired gateway.EngineState) (gateway.EngineStatus, error)

	// DatapathGeneration returns the datapath's current generation counter. It
	// must be captured before the NetworkService CRDs are listed; see
	// ReconcileOrphans.
	DatapathGeneration() uint64

	// ReconcileOrphans removes vip_table state left behind by a mid-reconcile
	// crash. cutoff must come from DatapathGeneration, read before desired's
	// NetworkService CRDs were listed, so an entry written during the listing
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
//     NetworkService in the namespace, resolving each backend's SRv6 uSID, and
//     converges the engine toward it. Under the anycast model every gateway
//     node in a PoP serves every accepted rule identically, so there is no
//     primary or secondary node to gate on. A deleting rule stays in that
//     state, unadvertised, until its BGPAdvertisements are gone and
//     ruleDrainDelay has passed, so its route is withdrawn before the
//     datapath drops it.
//  2. Reconciles one BGPAdvertisement per loaded rule per VIP address family,
//     reusing the l2vpn/evpn Type-5 IP-Prefix path unmodified. A rule that
//     failed to build or that the engine did not load has this node's
//     advertisements withdrawn instead, so the fabric never sends a VIP's
//     traffic to a node with nothing loaded for it. Each rule's
//     "<node>/Programmed" condition records which happened. VRFID and Function stay
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

	// APIReader reads from the API server, bypassing the informer cache.
	// sweepOrphanedAdvertisements uses it to confirm a rule is really gone
	// before withdrawing this node's route for it. Required.
	APIReader client.Reader

	// Disabled is set when this node's datapath is turned off by
	// configuration. The reconciler then keeps every one of this node's VIP
	// advertisements withdrawn and reports the node not ready, so the fabric
	// stops sending VIP traffic to a node that will not load-balance it. The
	// engine is never driven.
	Disabled bool

	// ReturnPath, set only with Disabled, keeps the node forwarding replies
	// from every rule's VIPs while it serves none: a backend node can still
	// send replies through it. Nil means the node has no return program.
	ReturnPath ReturnAddrSyncer

	// IPv4VIPs loads a rule's IPv4 VIPs into the engine alongside its IPv6
	// ones (config.EnvGatewayIPv4VIPs), over the rule's IPv6 backends,
	// whose nodes translate its flows, and advertises one once its
	// backends' ServiceVIPBindings are Bound; see buildDesiredRule and
	// applyBGPAdvertisements. Off, no IPv4 VIP is loaded or advertised.
	IPv4VIPs bool

	// BackendHealth leaves a backend its node reports Unhealthy out of a rule
	// with a healthCheck (config.EnvGatewayBackendHealth), while every
	// NetworkGateway in the namespace reports BackendHealthFiltering, which
	// this node then reports too; see passHealthGate.
	BackendHealth bool

	// EnsureIPv4Forwarding turns on the IPv4 forwarding the datapath's IPv4
	// FIB lookups need. Each pass calls it before the engine loads any IPv4
	// VIP, so a node that serves none never changes its IPv4 forwarding. It
	// must be idempotent; an error fails the pass before the engine is
	// driven, so no IPv4 VIP loads, and is not yet advertised, on a node
	// whose replies to it would be dropped. Nil means nothing to turn on.
	EnsureIPv4Forwarding func() error

	// Scope is which NetworkServices this node serves and which
	// NetworkGateways it trusts. With Scope.ProjectServices on, a
	// NetworkGateway outside Scope.GatewayNamespace is ignored.
	Scope ServiceScope

	// drain keeps a deleted rule loaded until its route is withdrawn. See
	// ruleDrainTracker.
	drain ruleDrainTracker

	// now returns the current time. Nil means time.Now; tests set it to step
	// past ruleDrainDelay.
	now func() time.Time
}

const (
	// reasonEngineHealthy is the Ready condition reason for a fully
	// converged and fully advertised node.
	reasonEngineHealthy = "EngineHealthy"

	// reasonEngineDegraded is the Ready reason for a node whose engine
	// failed to load or remove one or more rules.
	reasonEngineDegraded = "EngineDegraded"

	// reasonAdvertisementFailed is the Ready reason for a node whose engine
	// converged but which could not publish one or more of the
	// BGPAdvertisements that make it reachable. Such a node serves nothing, so
	// it must not report reasonEngineHealthy.
	reasonAdvertisementFailed = "AdvertisementFailed"

	// reasonDatapathDisabled is the Ready reason while this node's datapath is
	// turned off by configuration.
	reasonDatapathDisabled = "DatapathDisabled"

	// reasonIPv4ForwardingFailed is the Ready reason, and each affected
	// rule's IPv4Served reason, while this node cannot turn on the IPv4
	// forwarding its IPv4 VIPs need, so they are left out and IPv6 is served.
	reasonIPv4ForwardingFailed = "IPv4ForwardingFailed"

	// reasonProgrammed is the per-node Programmed reason for a rule this
	// node's engine loaded.
	reasonProgrammed = "Programmed"

	// reasonLoadFailed is the per-node Programmed reason for a rule this
	// node's engine refused, for example over quota or with an address the
	// datapath does not accept.
	reasonLoadFailed = "LoadFailed"

	// reasonInvalidRule is the per-node Programmed reason for a rule that
	// could not be turned into engine state, for example because none of its
	// backends' uSIDs resolve.
	reasonInvalidRule = "InvalidRule"

	// reasonBackendsUnresolved is the per-node Programmed reason for a rule
	// this node's engine loaded without one or more backends whose uSID did
	// not resolve, for example while a backend pod is being recreated, or
	// that an older rule serves on the same backend port. The rule keeps
	// serving through the rest.
	reasonBackendsUnresolved = "BackendsUnresolved"

	// reasonNoServedVIP is the per-node Programmed reason for a rule whose
	// every VIP is IPv4 while IPv4VIPs is off, so nothing is loaded or
	// advertised for it.
	reasonNoServedVIP = "NoServedVIP"

	// reasonIPv4NotAdvertised is the per-node IPv4Served reason for a rule
	// whose IPv4 VIP this node loaded over Bound backends, with IPv4VIPs set,
	// but whose route it could not publish: no BGPRouter targets the node, or
	// the advertisement failed, which the NetworkGateway's Ready condition
	// reports.
	reasonIPv4NotAdvertised = "NotAdvertised"

	// reasonAdvertised is the per-node Advertised reason, with status True,
	// for a rule whose BGPAdvertisements this node published.
	reasonAdvertised = "Advertised"

	// reasonNotProgrammed is the per-node Advertised reason for a rule this
	// node did not load, so it withdrew the rule's routes.
	reasonNotProgrammed = "NotProgrammed"

	// reasonAdvertisementPending is the per-node Advertised reason for a rule
	// whose BGPAdvertisements this node published but galactic-router does not
	// report advertised yet.
	reasonAdvertisementPending = "AdvertisementPending"

	// reasonNoRouter is the per-node Advertised reason for a rule this node
	// loaded but cannot advertise, because no BGPRouter targets the node or
	// more than one does.
	reasonNoRouter = "NoRouter"

	// reasonIPv4Advertised is the per-node IPv4Served reason, with status
	// True, for a rule whose IPv4 VIP this node loaded over only the eligible
	// backends whose ServiceVIPBinding is Bound, at least one, and advertises.
	reasonIPv4Advertised = "Advertised"

	// reasonIPv4BindingsNotBound is the per-node IPv4Served reason for a rule
	// whose IPv4 VIP this node loaded over its eligible backends, none
	// of whose ServiceVIPBindings is Bound yet, so it is not advertised. The
	// VIP is loaded so that galactic-router writes those bindings
	// (ipv4LoadedOnSomeNode).
	reasonIPv4BindingsNotBound = "BindingsNotBound"

	// reasonIPv4NoBackend is the per-node IPv4Served reason for a rule whose
	// IPv4 VIPs IPv4VIPs would load but none of whose selected attachments has
	// an IPv6 address that resolves to a backend for them, so they are left
	// out.
	reasonIPv4NoBackend = "NoBackend"

	// reasonIPv4MultipleVIPs is the per-node IPv4Served reason for a rule
	// with more than one IPv4 VIP while IPv4VIPs is on. None of them is
	// loaded, and the rule's IPv6 VIPs serve without them.
	reasonIPv4MultipleVIPs = "MultipleVIPs"

	// reasonIPv4NotLoaded is the per-node IPv4Served reason for a rule whose
	// IPv4 VIPs IPv4VIPs would load, but which this node did not load at all,
	// for example because the engine refused it.
	reasonIPv4NotLoaded = "NotLoaded"

	// reasonUnservedProtocol is the per-node Programmed reason for a rule
	// whose protocol the datapath does not serve, so nothing is loaded or
	// advertised for it.
	reasonUnservedProtocol = "UnservedProtocol"

	// reasonIPv4Unsupported is the per-node IPv4Served reason for a rule with
	// one or more IPv4 VIPs while IPv4VIPs is off. They are left out of the
	// engine and never advertised, and the rule's IPv6 VIPs serve without
	// them.
	reasonIPv4Unsupported = "Unsupported"

	// reasonTerminating is the Ready reason for a NetworkGateway being deleted,
	// whether observed on a live object carrying a deletion timestamp or
	// reconstructed for the case where the object is already gone.
	reasonTerminating = "Terminating"
)

// ipv4LoadedReasons are the IPv4Served reasons that mean the reporting
// gateway node has the rule's IPv4 VIP loaded. galactic-router writes a
// rule's IPv4 bindings only while some node reports one of them
// (ipv4LoadedOnSomeNode).
var ipv4LoadedReasons = map[string]bool{
	reasonIPv4NotAdvertised:    true,
	reasonIPv4Advertised:       true,
	reasonIPv4BindingsNotBound: true,
}

// ipv4LoadedOnSomeNode reports whether any gateway node's IPv4Served
// condition on rule says it loaded the rule's IPv4 VIP.
func ipv4LoadedOnSomeNode(rule *bgpv1alpha1.NetworkService) bool {
	for _, c := range rule.Status.Conditions {
		if strings.HasSuffix(c.Type, "/"+conditionTypeIPv4Served) && ipv4LoadedReasons[c.Reason] {
			return true
		}
	}
	return false
}

// ipv4Family is what buildDesiredRule did with a rule's IPv4 VIPs.
type ipv4Family int

const (
	// ipv4Off: IPv4VIPs is off, so they are left out.
	ipv4Off ipv4Family = iota
	// ipv4Loaded: they are in the rule's engine state, over only the eligible
	// IPv6 backends whose ServiceVIPBinding for them is Bound, at least one,
	// so they may be advertised.
	ipv4Loaded
	// ipv4Unbound: they are in the rule's engine state, over every eligible
	// backend, none of whose ServiceVIPBindings is Bound yet, so they
	// are not advertised.
	ipv4Unbound
	// ipv4NoBackend: no IPv6 backend resolves for them, so they are left out.
	ipv4NoBackend
	// ipv4MultipleVIPs: the rule has more than one, so they are left out.
	ipv4MultipleVIPs
	// ipv4NotLoaded: the rule failed to build or load before or apart from
	// its IPv4 VIPs.
	ipv4NotLoaded
	// ipv4NoForwarding: they would load, but this node's IPv4 forwarding
	// could not be turned on, so they are left out for this pass
	// (ensureIPv4Forwarding).
	ipv4NoForwarding
)

// Reconcile reconciles a single NetworkGateway.
//
// A NetworkGateway outside the trusted gateway namespace is not one: a project
// able to create it must not make its own services trusted, and its deletion
// must not stop this node's engine. It is ignored.
func (r *NetworkGatewayReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	if !r.Scope.trustsGateway(req.Namespace) {
		return ctrl.Result{}, nil
	}
	return r.reconcileGateway(ctx, req)
}

// reconcileGateway reconciles a single trusted NetworkGateway.
func (r *NetworkGatewayReconciler) reconcileGateway(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
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
				logger.Error(withdrawErr, "withdraw BGPAdvertisements for departed gateway node", "nodeName", req.Name)
			}
			if clearErr := clearNodeRuleConditions(ctx, r.Client, r.Scope, req.Namespace, req.Name); clearErr != nil {
				logger.Error(clearErr, "clear Programmed conditions for departed gateway node", "nodeName", req.Name)
				withdrawErr = errors.Join(withdrawErr, clearErr)
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
			r.drain.reset()
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
		if clearErr := clearNodeRuleConditions(ctx, r.Client, r.Scope, gw.Namespace, gw.Name); clearErr != nil {
			logger.Error(clearErr, "clear Programmed conditions for terminating NetworkGateway",
				"networkGateway", req.NamespacedName)
			withdrawErr = errors.Join(withdrawErr, clearErr)
		}
		if stopErr := r.Engine.Stop(ctx); stopErr != nil {
			logger.Error(stopErr, "stop gateway engine for terminating NetworkGateway", "networkGateway", req.NamespacedName)
		}
		r.drain.reset()
		gwCopy := gw.DeepCopy()
		gwCopy.Status.BackendHealthFiltering = r.BackendHealth
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

	if r.Disabled {
		withdrawErr := errors.Join(
			withdrawNodeAdvertisements(ctx, r.Client, gw.Namespace, r.NodeName),
			clearNodeRuleConditions(ctx, r.Client, r.Scope, gw.Namespace, r.NodeName),
			r.syncReturnPath(ctx, gw.Namespace),
		)
		gwCopy := gw.DeepCopy()
		gwCopy.Status.BackendHealthFiltering = r.BackendHealth
		gwCopy.Status.ObservedGeneration = gw.Generation
		setGatewayCondition(gwCopy, metav1.Condition{
			Type:    bgpv1alpha1.ConditionTypeReady,
			Status:  metav1.ConditionFalse,
			Reason:  reasonDatapathDisabled,
			Message: fmt.Sprintf("The edge gateway datapath on node %s is turned off", r.NodeName),
		})
		if updateErr := r.Status().Update(ctx, gwCopy); updateErr != nil {
			logger.Error(updateErr, "update status for disabled NetworkGateway")
		}
		return ctrl.Result{}, withdrawErr
	}

	// Crash-safety ordering contract (see GatewayEngine.ReconcileOrphans):
	// cutoff must be captured before desired's NetworkService CRDs are listed.
	cutoff := r.Engine.DatapathGeneration()

	served, allRules, err := r.Scope.listServedNetworkServices(ctx, r.Client, gw.Namespace)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("list NetworkServices for NetworkGateway %s: %w", req.NamespacedName, err)
	}

	// An ambiguous router only blocks advertisement wiring; the datapath
	// below is still programmed, as it is when no router exists yet.
	routerName, routerErr := r.routerNameForNode(ctx, gw.Namespace)
	if routerErr != nil && !errors.Is(routerErr, errAmbiguousRouter) {
		return ctrl.Result{}, fmt.Errorf("resolve BGPRouter for node %s: %w", r.NodeName, routerErr)
	}

	sidIndex, err := buildBackendSIDIndex(ctx, r.Client, gw.Namespace)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("build backend uSID index: %w", err)
	}

	// One list for the whole pass, so each rule selects its backends from its
	// own VPC's attachments (gatherRules groups them) without another list call.
	attachments, err := listVPCAttachments(ctx, r.Client)
	if err != nil {
		return ctrl.Result{}, err
	}

	desired, outcomes, requeueAfter, err := r.gatherRules(ctx, gw.Namespace, served, allRules, attachments, sidIndex)
	if err != nil {
		return ctrl.Result{}, err
	}

	desired, fwdErr := r.ensureIPv4Forwarding(desired, outcomes)
	status, err := r.reconcileEngine(ctx, gw, desired)
	if err != nil {
		return ctrl.Result{}, errors.Join(fwdErr, err)
	}

	switch {
	case routerErr != nil:
		logger.Error(routerErr, "skipping BGPAdvertisement wiring", "nodeName", r.NodeName)
	case routerName == "":
		logger.Info("no BGPRouter targets this node; skipping BGPAdvertisement wiring", "nodeName", r.NodeName)
	}

	advErr, ruleStatusErr := r.publishRuleOutcomes(ctx, gw.Namespace, outcomes, status, routerName)

	gwCopy := gw.DeepCopy()
	gwCopy.Status.BackendHealthFiltering = r.BackendHealth
	gwCopy.Status.ObservedGeneration = gw.Generation
	ready := readyConditionFor(status, advErr)
	if fwdErr != nil {
		ready = metav1.Condition{
			Type:    bgpv1alpha1.ConditionTypeReady,
			Status:  metav1.ConditionFalse,
			Reason:  reasonIPv4ForwardingFailed,
			Message: fwdErr.Error() + "; IPv4 VIPs are left out until it succeeds, and IPv6 VIPs are served",
		}
	}
	setGatewayCondition(gwCopy, ready)
	if updateErr := r.Status().Update(ctx, gwCopy); updateErr != nil {
		logger.Error(updateErr, "update NetworkGateway status")
	}

	sweepErr := r.sweepOrphanedAdvertisements(ctx, gw.Namespace, served)
	if sweepErr != nil {
		logger.Error(sweepErr, "withdraw advertisements for deleted NetworkServices")
	}

	// Crash recovery. A failed sweep leaves orphaned vip_table state behind
	// until a later pass succeeds, so it is returned for retry, after the
	// status write above so the failure stays visible on the object.
	if err := r.Engine.ReconcileOrphans(ctx, desired, cutoff); err != nil {
		logger.Error(err, "reconcile orphaned vip_table state")
		return ctrl.Result{}, errors.Join(fwdErr, advErr, ruleStatusErr, sweepErr,
			fmt.Errorf("reconcile orphaned vip_table state: %w", err))
	}

	if err := errors.Join(fwdErr, advErr, ruleStatusErr, sweepErr); err != nil {
		return ctrl.Result{}, err
	}
	requeueAfter = healthExpiryRequeue(allRules, requeueAfter)

	// Nothing else is sure to trigger the pass that drops a held rule once
	// its drain delay ends, so ask for it.
	return ctrl.Result{RequeueAfter: requeueAfter}, nil
}

// ReturnAddrSyncer sets the VIP addresses a node's return program claims
// replies from. gateway.KernelReturnPath is the real implementation.
type ReturnAddrSyncer interface {
	SyncReturnAddrs(addrs []netip.Addr) error
}

// syncReturnPath points r.ReturnPath at every VIP address the rules the
// namespace's gateways serve list, whatever their state, less those of a
// tenant rule that is not accepted: a rule another gateway node serves can
// send replies through this one, and claiming an address carries no traffic
// to the node. IPv4 VIPs are included only with IPv4VIPs on, once IPv4
// forwarding is, since edge_return's IPv4 FIB lookup needs it; an IPv4 VIP
// that cannot be claimed is left out and the error returned.
func (r *NetworkGatewayReconciler) syncReturnPath(ctx context.Context, namespace string) error {
	if r.ReturnPath == nil {
		return nil
	}
	rules, _, err := r.Scope.listServedNetworkServices(ctx, r.Client, namespace)
	if err != nil {
		return fmt.Errorf("list NetworkServices for the return path: %w", err)
	}
	var v6, v4 []netip.Addr
	for i := range rules {
		if ruleIsTenant(&rules[i], namespace) &&
			!meta.IsStatusConditionTrue(rules[i].Status.Conditions, bgpv1alpha1.ConditionTypeAccepted) {
			continue
		}
		for _, v := range rules[i].Spec.VIPAddresses {
			addr, err := netip.ParseAddr(v)
			switch {
			case err != nil:
			case !isIPv4VIP(addr):
				v6 = append(v6, addr)
			case r.IPv4VIPs:
				v4 = append(v4, addr.Unmap())
			}
		}
	}
	var fwdErr error
	if len(v4) > 0 && r.EnsureIPv4Forwarding != nil {
		if err := r.EnsureIPv4Forwarding(); err != nil {
			fwdErr = fmt.Errorf("turn on IPv4 forwarding for the return path; IPv4 VIP replies are not claimed: %w", err)
			v4 = nil
		}
	}
	addrs := append(v6, v4...)
	slices.SortFunc(addrs, netip.Addr.Compare)
	if err := r.ReturnPath.SyncReturnAddrs(slices.Compact(addrs)); err != nil {
		return errors.Join(fwdErr, fmt.Errorf("sync the return path's VIP addresses: %w", err))
	}
	return fwdErr
}

// reconcileEngine converges the engine on desired. A failure is recorded on
// gw's Ready condition and returned.
func (r *NetworkGatewayReconciler) reconcileEngine(
	ctx context.Context, gw *bgpv1alpha1.NetworkGateway, desired gateway.EngineState,
) (gateway.EngineStatus, error) {
	status, err := r.Engine.Reconcile(ctx, desired)
	if err != nil {
		gwCopy := gw.DeepCopy()
		gwCopy.Status.BackendHealthFiltering = r.BackendHealth
		setGatewayCondition(gwCopy, metav1.Condition{
			Type:    bgpv1alpha1.ConditionTypeReady,
			Status:  metav1.ConditionFalse,
			Reason:  "EngineReconcileFailed",
			Message: err.Error(),
		})
		if updateErr := r.Status().Update(ctx, gwCopy); updateErr != nil {
			log.FromContext(ctx).Error(updateErr, "update NetworkGateway status after engine reconcile error")
		}
		return gateway.EngineStatus{}, err
	}
	return status, nil
}

// ensureIPv4Forwarding turns on this node's IPv4 forwarding before the engine
// loads desired, when desired holds an IPv4 VIP (EnsureIPv4Forwarding), and
// returns the state to load. When it cannot be turned on, IPv4 fails closed
// for this pass only: every IPv4 VIP and its backends are left out of the
// returned state, each affected outcome is marked ipv4NoForwarding so its
// -v4 route is not published, and the error is returned for the caller to
// report and retry. IPv6 VIPs are loaded and advertised as usual. A rule left
// with no VIP is dropped from the state and reported as serving none.
func (r *NetworkGatewayReconciler) ensureIPv4Forwarding(
	desired gateway.EngineState, outcomes []ruleOutcome,
) (gateway.EngineState, error) {
	if !r.IPv4VIPs || r.EnsureIPv4Forwarding == nil || !loadsIPv4VIP(desired) {
		return desired, nil
	}
	fwdErr := r.EnsureIPv4Forwarding()
	if fwdErr == nil {
		return desired, nil
	}
	fwdErr = fmt.Errorf("turn on IPv4 forwarding for this node's IPv4 VIPs: %w", fwdErr)

	stripped := gateway.EngineState{Rules: make(map[string]gateway.DesiredRule, len(desired.Rules))}
	for key, rule := range desired.Rules {
		rule.VIPAddresses = slices.DeleteFunc(slices.Clone(rule.VIPAddresses), isIPv4VIP)
		rule.IPv4Backends = nil
		if len(rule.VIPAddresses) > 0 {
			stripped.Rules[key] = rule
		}
	}
	for i := range outcomes {
		o := &outcomes[i]
		if o.ipv4 != ipv4Loaded && o.ipv4 != ipv4Unbound {
			continue
		}
		o.ipv4 = ipv4NoForwarding
		rule, kept := stripped.Rules[o.desired.Key]
		if kept {
			o.desired = rule
		} else if !o.draining {
			o.buildErr = fmt.Errorf("%w: %w", errIPv4ForwardingUnavailable, fwdErr)
		}
	}
	return stripped, fwdErr
}

// loadsIPv4VIP reports whether desired holds any IPv4 VIP for the engine to
// load.
func loadsIPv4VIP(desired gateway.EngineState) bool {
	for _, rule := range desired.Rules {
		if slices.ContainsFunc(rule.VIPAddresses, isIPv4VIP) {
			return true
		}
	}
	return false
}

// passBindings returns namespace's generated bindings for one pass, which IPv4
// VIPs are balanced over and advertised by and backend health is read from,
// or nil while IPv4VIPs and BackendHealth are both off, when nothing reads
// them.
func (r *NetworkGatewayReconciler) passBindings(ctx context.Context, namespace string) (serviceBindings, error) {
	if !r.IPv4VIPs && !r.BackendHealth {
		return nil, nil
	}
	return listServiceBindings(ctx, r.Client, namespace)
}

// gatherRules builds this pass's engine state and rule outcomes from rules,
// every NetworkService the gateways in namespace serve, and settles the drain
// tracker against it. allRules holds every NetworkService in the cluster, which
// compete for backends and VIPs. attachments holds every VPCAttachment in the
// cluster; each rule selects from those in its own VPC (groupAttachmentsByVPC).
// A rule that is not accepted gets an outcome that withdraws this node's
// advertisements for it, so a tenant rule that loses its acceptance stops
// drawing traffic here. It reads the namespace's
// generated bindings once, while IPv4VIPs or BackendHealth is on
// (passBindings), and whether health applies (passHealthGate). It returns how
// long until a held rule's drain delay ends, or zero.
func (r *NetworkGatewayReconciler) gatherRules(
	ctx context.Context, namespace string, rules, allRules []bgpv1alpha1.NetworkService,
	attachments []*cloudv1alpha1.VPCAttachment, sidIndex *backendSIDIndex,
) (gateway.EngineState, []ruleOutcome, time.Duration, error) {
	logger := log.FromContext(ctx)
	desired := gateway.EngineState{Rules: make(map[string]gateway.DesiredRule)}

	bindings, err := r.passBindings(ctx, namespace)
	if err != nil {
		return desired, nil, 0, err
	}
	health, err := r.passHealthGate(ctx, namespace)
	if err != nil {
		return desired, nil, 0, err
	}

	// Every accepted, non-deleting rule gets an outcome, including one that
	// failed to build: the engine drops it from the datapath, so the outcome
	// is what withdraws its advertisement and records why it is not loaded.
	// A draining rule gets one too, marked so nothing is published for it.
	var outcomes []ruleOutcome

	// live holds every listed rule that is not being deleted, so the drain
	// tracker can tell a deleted rule from one that merely stopped building.
	live := make(map[string]bool, len(rules))

	// Every rule competes for its backends with every other rule in the
	// cluster, the same set each backend node's binding writer compares.
	owners := ruleBackendOwners(allRules, attachments, namespace)
	vipLost := tenantVIPConflicts(allRules, namespace)
	byVPC := groupAttachmentsByVPC(attachments)

	for i := range rules {
		rule := &rules[i]
		if !rule.DeletionTimestamp.IsZero() {
			// Being torn down. NetworkServiceReconciler's finalizer owns the
			// rule's advertisements: reconcileDelete deletes every one
			// carrying networkRuleLabel, whichever node made it. Until they
			// are all gone the route may still draw traffic here, so the rule
			// stays loaded as draining, which advertises nothing and leaves
			// the Programmed condition alone. Once they are gone, the drain
			// tracker keeps it for ruleDrainDelay so the withdrawal can reach
			// every peer before the datapath drops it.
			o, draining, err := r.drainingOutcome(ctx, namespace, rule, byVPC[rule.Spec.VPCRef], sidIndex, owners,
				bindings, health)
			if err != nil {
				return desired, nil, 0, err
			}
			if draining {
				desired.Rules[o.desired.Key] = o.desired
				outcomes = append(outcomes, o)
			}
			continue
		}
		live[rule.Namespace+"/"+rule.Name] = true
		if !meta.IsStatusConditionTrue(rule.Status.Conditions, bgpv1alpha1.ConditionTypeAccepted) {
			// Not accepted yet, or no longer: no NetworkGateway serves it, or
			// a tenant rule failed its ownership check. Nothing is loaded, and
			// whatever this node advertised for it is withdrawn.
			outcomes = append(outcomes, ruleOutcome{rule: rule, unaccepted: true})
			continue
		}
		if ruleIsTenant(rule, namespace) {
			if ok, vip := r.Scope.vipsInPool(rule); !ok {
				err := fmt.Errorf("%w: %s", errVIPOutsidePool, vip)
				outcomes = append(outcomes, ruleOutcome{rule: rule, buildErr: err, ipv4: ipv4Off})
				continue
			}
		}
		if owner, lost := vipLost[client.ObjectKeyFromObject(rule)]; lost {
			err := fmt.Errorf("%w: NetworkService %s already serves one of its VIP addresses on %s port %d",
				errVIPClaimed, owner, rule.Spec.Protocol, rule.Spec.Port)
			outcomes = append(outcomes, ruleOutcome{rule: rule, buildErr: err, ipv4: ipv4Off})
			continue
		}

		dr, unresolved, ipv4, rh, err := buildDesiredRule(rule, byVPC[rule.Spec.VPCRef], sidIndex, owners, r.IPv4VIPs,
			bindings, health, namespace)
		if err != nil {
			logger.Error(err, "build desired rule; skipping", "networkRule", rule.Name)
			outcomes = append(outcomes, ruleOutcome{rule: rule, buildErr: err, ipv4: ipv4})
			continue
		}
		if len(unresolved) > 0 {
			logger.Info("loading rule without unresolved backends", "networkRule", rule.Name, "unresolved", unresolved)
		}
		if len(rh.unhealthy) > 0 {
			logger.Info("loading rule without unhealthy backends", "networkRule", rule.Name, "unhealthy", rh.unhealthy)
		}
		desired.Rules[dr.Key] = dr
		outcomes = append(outcomes, ruleOutcome{
			rule: rule, desired: dr, unresolved: unresolved, ipv4: ipv4, health: rh,
		})
	}

	return desired, outcomes, r.drain.settle(r.clock(), namespace, desired.Rules, live), nil
}

// clock returns the current time from r.now, or time.Now when unset.
func (r *NetworkGatewayReconciler) clock() time.Time {
	if r.now != nil {
		return r.now()
	}
	return time.Now()
}

// drainingOutcome reports whether the deleting rule must stay loaded because
// some BGPAdvertisement carrying its networkRuleLabel still exists, on any
// node, and returns its draining outcome if so. A rule whose finalizer is
// already gone has finished teardown and never drains.
//
// The rule is rebuilt as usual. If it no longer builds, for example because
// its backends were deleted with it, the rule as this node last loaded it is
// kept instead. If this node never loaded it, there is nothing to keep.
// attachments, bindings and health are as for buildDesiredRule.
func (r *NetworkGatewayReconciler) drainingOutcome(
	ctx context.Context, objNS string, rule *bgpv1alpha1.NetworkService, attachments []*cloudv1alpha1.VPCAttachment,
	sidIndex *backendSIDIndex, owners backendOwners, bindings serviceBindings, health healthGate,
) (ruleOutcome, bool, error) {
	if !controllerutil.ContainsFinalizer(rule, networkRuleFinalizer) {
		return ruleOutcome{}, false, nil
	}
	advList := &bgpv1alpha1.BGPAdvertisementList{}
	if err := r.List(ctx, advList, ruleSelector(rule, objNS)); err != nil {
		return ruleOutcome{}, false, fmt.Errorf("list BGPAdvertisements for deleting NetworkService %s/%s: %w",
			rule.Namespace, rule.Name, err)
	}
	if len(advList.Items) == 0 {
		return ruleOutcome{}, false, nil
	}

	dr, _, _, _, err := buildDesiredRule(rule, attachments, sidIndex, owners, r.IPv4VIPs, bindings, health, objNS)
	if err != nil {
		var ok bool
		if dr, ok = r.drain.lastLoaded(rule.Namespace + "/" + rule.Name); !ok {
			return ruleOutcome{}, false, nil
		}
	}
	return ruleOutcome{rule: rule, desired: dr, draining: true}, true, nil
}

// ruleOutcome is one accepted NetworkService's result from a reconcile pass: the
// engine state it built, or why it could not be built. unresolved lists the
// backends left out of desired because their uSID did not resolve.
type ruleOutcome struct {
	rule       *bgpv1alpha1.NetworkService
	desired    gateway.DesiredRule
	unresolved []string
	buildErr   error

	// ipv4 is what became of the rule's IPv4 VIPs, for its IPv4Served
	// condition.
	ipv4 ipv4Family

	// health is what backend health did to the rule's backends.
	health ruleHealth

	// draining marks a deleting rule kept loaded until its route is
	// withdrawn. Nothing is advertised or written to its status.
	draining bool

	// unaccepted marks a rule that is not accepted: nothing is loaded for
	// it, this node's advertisements for it are withdrawn, and nothing is
	// written to its status.
	unaccepted bool
}

// publishRuleOutcomes advertises every rule the engine loaded, withdraws this
// node's advertisements for every other rule, and records the result on each
// rule's Programmed condition for this node. Conditions of gateway nodes that
// no NetworkGateway in namespace targets are removed with it
// (departedGatewayNodes).
//
// Failures are collected rather than returned on the spot, so one bad rule
// does not stop the others. Advertisement failures come back as advErr, which
// the caller reports on the NetworkGateway and returns, so controller-runtime
// retries with backoff instead of leaving a node that advertised nothing
// claiming to be healthy. Rule status failures come back separately as
// statusErr: they are retried too, but say nothing about whether this node
// serves traffic, so they stay out of the Ready condition.
func (r *NetworkGatewayReconciler) publishRuleOutcomes(
	ctx context.Context, namespace string, outcomes []ruleOutcome, status gateway.EngineStatus, routerName string,
) (advErr, statusErr error) {
	logger := log.FromContext(ctx)

	// A failed lookup only skips pruning other nodes' conditions this pass.
	var statusErrs []error
	departed, err := r.departedGatewayNodes(ctx, namespace, outcomes)
	if err != nil {
		statusErrs = append(statusErrs, err)
	}

	// The engine reports one status per desired rule. Only a rule it loaded
	// is advertised: a route for anything else draws traffic this node drops.
	loadErrs := make(map[string]string, len(status.Rules))
	for _, s := range status.Rules {
		if !s.Applied || s.Error != "" {
			loadErrs[s.Key] = s.Error
		}
	}

	var advErrs []error
	for _, o := range outcomes {
		if o.draining {
			continue
		}
		if o.unaccepted {
			if err := withdrawRuleAdvertisements(ctx, r.Client, o.rule, namespace, r.NodeName); err != nil {
				logger.Error(err, "withdraw BGPAdvertisements for unaccepted NetworkService", "networkRule", o.rule.Name)
				advErrs = append(advErrs, fmt.Errorf("networkRule %s: %w", o.rule.Name, err))
			}
			if hasNodeRuleConditions(o.rule, r.NodeName) {
				key := client.ObjectKeyFromObject(o.rule)
				if err := clearRuleNodeConditions(ctx, r.Client, r.Scope, key, r.NodeName); err != nil {
					statusErrs = append(statusErrs, fmt.Errorf("networkRule %s status: %w", o.rule.Name, err))
				}
			}
			continue
		}
		cond := programmedCondition(r.NodeName, o, loadErrs)
		// The rule's IPv4 VIP is advertised only when this node loaded it over
		// only its Bound backends, at least one (ipv4Loaded), and the rule
		// loaded.
		advertiseIPv4 := r.IPv4VIPs && o.ipv4 == ipv4Loaded
		var publishErr error
		var pending []string
		switch {
		case cond.Status != metav1.ConditionTrue:
			if err := withdrawRuleAdvertisements(ctx, r.Client, o.rule, namespace, r.NodeName); err != nil {
				logger.Error(err, "withdraw BGPAdvertisements for unloaded NetworkService", "networkRule", o.rule.Name)
				advErrs = append(advErrs, fmt.Errorf("networkRule %s: %w", o.rule.Name, err))
			}
		case routerName != "":
			if err := r.applyBGPAdvertisements(ctx, namespace, o.rule, o.desired, routerName, advertiseIPv4); err != nil {
				logger.Error(err, "apply BGPAdvertisements for NetworkService", "networkRule", o.rule.Name)
				advErrs = append(advErrs, fmt.Errorf("networkRule %s: %w", o.rule.Name, err))
				publishErr = err
				break
			}
			var err error
			if pending, err = r.uninstalledAdvertisements(ctx, namespace, o.rule, o.desired, advertiseIPv4); err != nil {
				statusErrs = append(statusErrs, fmt.Errorf("networkRule %s: %w", o.rule.Name, err))
			}
		}

		published := cond.Status == metav1.ConditionTrue && routerName != "" && publishErr == nil
		adv := advertisedCondition(r.NodeName, cond.Status == metav1.ConditionTrue, routerName, publishErr, pending)
		ipv4 := ipv4ServedCondition(r.NodeName, o.rule, o.ipv4, cond.Status == metav1.ConditionTrue, published)
		if err := r.setRuleConditions(ctx, o.rule, cond, adv, ipv4, departed); err != nil {
			logger.Error(err, "update NetworkService conditions", "networkRule", o.rule.Name)
			statusErrs = append(statusErrs, fmt.Errorf("networkRule %s status: %w", o.rule.Name, err))
		}
	}
	return errors.Join(advErrs...), errors.Join(statusErrs...)
}

// programmedCondition returns node's Programmed condition for o. loadErrs maps
// each rule key the engine did not load to its error.
func programmedCondition(node string, o ruleOutcome, loadErrs map[string]string) metav1.Condition {
	cond := metav1.Condition{
		Type:    programmedConditionType(node),
		Status:  metav1.ConditionTrue,
		Reason:  reasonProgrammed,
		Message: "loaded on node " + node,
	}
	if o.buildErr != nil {
		cond.Status, cond.Reason = metav1.ConditionFalse, reasonInvalidRule
		switch {
		case errors.Is(o.buildErr, errNoServedVIP), errors.Is(o.buildErr, errIPv4ForwardingUnavailable):
			cond.Reason = reasonNoServedVIP
		case errors.Is(o.buildErr, errUnservedProtocol):
			cond.Reason = reasonUnservedProtocol
		case errors.Is(o.buildErr, errVIPClaimed):
			cond.Reason = reasonVIPClaimed
		case errors.Is(o.buildErr, errVIPOutsidePool):
			cond.Reason = reasonVIPOutsidePool
		case errors.Is(o.buildErr, errNoHealthyBackends):
			cond.Reason = reasonNoHealthyBackends
		}
		cond.Message = fmt.Sprintf("not loaded on node %s: %v", node, o.buildErr)
		return cond
	}
	if loadErr, failed := loadErrs[o.desired.Key]; failed {
		if loadErr == "" {
			loadErr = "the engine did not load it"
		}
		cond.Status, cond.Reason = metav1.ConditionFalse, reasonLoadFailed
		cond.Message = fmt.Sprintf("not loaded on node %s: %s", node, loadErr)
		return cond
	}
	loaded := len(o.desired.Backends) + len(o.desired.IPv4Backends)
	left := len(o.unresolved)
	if !o.health.noneHealthy {
		left += len(o.health.unhealthy)
	}
	var details []string
	if len(o.unresolved) > 0 {
		details = append(details, "unresolved: "+cappedList(o.unresolved))
	}
	switch {
	case o.health.noneHealthy:
		details = append(details, "every backend is Unhealthy, so all are kept: "+cappedList(o.health.unhealthy))
	case len(o.health.unhealthy) > 0:
		details = append(details, "unhealthy: "+cappedList(o.health.unhealthy))
	case o.health.notApplied != "":
		details = append(details, "health checks not applied: "+o.health.notApplied)
	}
	switch {
	case len(o.unresolved) > 0:
		cond.Reason = reasonBackendsUnresolved
	case o.health.noneHealthy:
		cond.Reason = reasonNoHealthyBackends
	case len(o.health.unhealthy) > 0:
		cond.Reason = reasonBackendsUnhealthy
	case o.health.notApplied != "":
		cond.Reason = reasonHealthChecksNotApplied
	default:
		return cond
	}
	cond.Message = fmt.Sprintf("loaded on node %s with %d of %d backends; %s",
		node, loaded, loaded+left, strings.Join(details, "; "))
	return cond
}

// advertisedCondition returns node's Advertised condition for a rule: True
// once node published the rule's BGPAdvertisements and galactic-router reports
// each one advertised, and otherwise False with why. programmed is whether
// node's engine loaded the rule, routerName the BGPRouter the advertisements
// hang off ("" when none targets node, or more than one does), publishErr the
// error from publishing them, and pending the published advertisements not
// reported advertised yet (uninstalledAdvertisements).
func advertisedCondition(
	node string, programmed bool, routerName string, publishErr error, pending []string,
) metav1.Condition {
	cond := metav1.Condition{
		Type:    advertisedConditionType(node),
		Status:  metav1.ConditionFalse,
		Reason:  reasonNotProgrammed,
		Message: "not advertised from node " + node + ": the rule is not loaded there",
	}
	switch {
	case !programmed:
	case publishErr != nil:
		cond.Reason = reasonAdvertisementFailed
		cond.Message = fmt.Sprintf("not advertised from node %s: %v", node, publishErr)
	case routerName == "":
		cond.Reason = reasonNoRouter
		cond.Message = "not advertised from node " + node + ": no single BGPRouter targets the node"
	case len(pending) > 0:
		cond.Reason = reasonAdvertisementPending
		cond.Message = fmt.Sprintf("published from node %s, but galactic-router does not report %s advertised yet",
			node, cappedList(pending))
	default:
		cond.Status, cond.Reason = metav1.ConditionTrue, reasonAdvertised
		cond.Message = "advertised from node " + node
	}
	return cond
}

// uninstalledAdvertisements returns the names of this node's BGPAdvertisements
// for rule that applyBGPAdvertisements published from desired, with the
// IPv4 one only when advertiseIPv4, but that galactic-router does not report
// advertised for their current generation yet. One missing from the cache
// counts as not advertised.
func (r *NetworkGatewayReconciler) uninstalledAdvertisements(
	ctx context.Context, objNS string, rule *bgpv1alpha1.NetworkService, desired gateway.DesiredRule,
	advertiseIPv4 bool,
) ([]string, error) {
	v4, v6 := prefixesByFamily(desired.VIPAddresses)
	var families []string
	if advertiseIPv4 && len(v4) > 0 {
		families = append(families, "v4")
	}
	if len(v6) > 0 {
		families = append(families, "v6")
	}
	var pending []string
	for _, family := range families {
		name := ruleKeyAdvertisementName(client.ObjectKeyFromObject(rule), objNS, r.NodeName, family)
		adv := &bgpv1alpha1.BGPAdvertisement{}
		err := r.Get(ctx, types.NamespacedName{Namespace: objNS, Name: name}, adv)
		switch {
		case apierrors.IsNotFound(err):
			pending = append(pending, name)
		case err != nil:
			return nil, fmt.Errorf("get BGPAdvertisement %s: %w", name, err)
		case !advertisementInstalled(adv):
			pending = append(pending, name)
		}
	}
	return pending, nil
}

// advertisementInstalled reports whether galactic-router reports adv
// advertised for its current generation.
func advertisementInstalled(adv *bgpv1alpha1.BGPAdvertisement) bool {
	c := meta.FindStatusCondition(adv.Status.Conditions, ConditionAdvertised)
	return c != nil && c.Status == metav1.ConditionTrue && c.ObservedGeneration == adv.Generation
}

// cappedList joins the first maxReadyFailures items with ", ", followed by a
// count of the rest, so a long list stays under the metav1.Condition message
// limit.
func cappedList(items []string) string {
	if len(items) <= maxReadyFailures {
		return strings.Join(items, ", ")
	}
	return fmt.Sprintf("%s and %d more",
		strings.Join(items[:maxReadyFailures], ", "), len(items)-maxReadyFailures)
}

// maxReadyFailures caps how many failed rules the Ready message names, so a
// pass with many failures stays under the metav1.Condition message limit.
const maxReadyFailures = 10

// readyConditionFor computes the Ready condition for a completed pass: engine
// health first, then advertisement failures. A node whose engine converged but
// whose routes never reached BGP serves no traffic, so it must not report
// reasonEngineHealthy. The engine failures named in the message are those the
// engine failed to load; a rule that failed to build never reaches the engine
// and is reported on the rule's own Programmed condition instead.
func readyConditionFor(status gateway.EngineStatus, advErr error) metav1.Condition {
	switch {
	case !status.Healthy:
		var failures []string
		for _, s := range status.Rules {
			if s.Error != "" {
				failures = append(failures, s.Key+": "+s.Error)
			}
		}
		more := 0
		if len(failures) > maxReadyFailures {
			more = len(failures) - maxReadyFailures
			failures = failures[:maxReadyFailures]
		}
		msg := "NetworkServices failed to apply: " + strings.Join(failures, "; ")
		if more > 0 {
			msg += fmt.Sprintf(" and %d more", more)
		}
		return metav1.Condition{
			Type: bgpv1alpha1.ConditionTypeReady, Status: metav1.ConditionFalse,
			Reason:  reasonEngineDegraded,
			Message: msg,
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

// programmedConditionType returns the NetworkService condition type that records
// whether node's engine loaded the rule. NetworkService status is shared by every
// gateway node in the namespace while loading is per node, so each node owns
// its own condition type and never overwrites another node's result.
func programmedConditionType(node string) string {
	return node + "/" + bgpv1alpha1.ConditionTypeProgrammed
}

// advertisedConditionType returns the NetworkService condition type that
// records whether node published the rule's routes. Like
// programmedConditionType, each gateway node owns its own.
func advertisedConditionType(node string) string {
	return node + "/" + conditionTypeAdvertised
}

// ipv4ServedConditionType returns the NetworkService condition type that records
// whether node serves the rule's IPv4 VIPs. Like programmedConditionType, each
// gateway node owns its own.
func ipv4ServedConditionType(node string) string {
	return node + "/" + conditionTypeIPv4Served
}

// conditionTypeIPv4Served is the suffix of every node's IPv4Served condition
// type.
const conditionTypeIPv4Served = "IPv4Served"

// conditionTypeAdvertised is the suffix of every gateway node's Advertised
// condition type, and the type of the rule's summary of them
// (summaryConditions).
const conditionTypeAdvertised = "Advertised"

// ipv4ServedCondition returns node's IPv4Served condition for rule, or nil
// when rule has no IPv4 VIP, in which case the condition is removed. Its
// reason says what became of the IPv4 VIP on node: ipv4 from buildDesiredRule,
// programmed whether node's engine loaded the rule, and advertised whether
// node published the rule's routes. It is True, with reasonIPv4Advertised,
// only when node loaded the IPv4 VIP over Bound backends and advertises it.
// ipv4LoadedReasons lists the reasons that mean the VIP is loaded.
func ipv4ServedCondition(
	node string, rule *bgpv1alpha1.NetworkService, ipv4 ipv4Family, programmed, advertised bool,
) *metav1.Condition {
	if !hasIPv4VIP(rule) {
		return nil
	}
	if (ipv4 == ipv4Loaded || ipv4 == ipv4Unbound) && !programmed {
		ipv4 = ipv4NotLoaded
	}
	status := metav1.ConditionFalse
	var reason, message string
	switch ipv4 {
	case ipv4Loaded:
		if advertised {
			status, reason = metav1.ConditionTrue, reasonIPv4Advertised
			message = fmt.Sprintf("IPv4 VIP is loaded and advertised on node %s over the backends whose "+
				"ServiceVIPBindings are Bound", node)
			break
		}
		reason = reasonIPv4NotAdvertised
		message = fmt.Sprintf("IPv4 VIP is loaded on node %s but its route is not published: no BGPRouter "+
			"targets the node or the advertisement failed; the node's Advertised condition says which", node)
	case ipv4Unbound:
		reason = reasonIPv4BindingsNotBound
		message = fmt.Sprintf("IPv4 VIP is loaded on node %s but not advertised: none of its backends' "+
			"ServiceVIPBindings is Bound yet; the backend nodes' BackendsBound conditions say why", node)
	case ipv4NoBackend:
		reason = reasonIPv4NoBackend
		message = fmt.Sprintf("IPv4 VIPs are not loaded on node %s: no selected attachment has an IPv6 "+
			"address that resolves to a backend this rule serves for them", node)
	case ipv4MultipleVIPs:
		reason = reasonIPv4MultipleVIPs
		message = fmt.Sprintf("IPv4 VIPs are not loaded or advertised on node %s: the rule has more than "+
			"one, and a backend node translates only one IPv4 VIP per rule; the IPv6 VIP serves without them", node)
	case ipv4NoForwarding:
		reason = reasonIPv4ForwardingFailed
		message = fmt.Sprintf("IPv4 VIPs are not loaded on node %s: its IPv4 forwarding could not be turned "+
			"on; the NetworkGateway's Ready condition says why, and the IPv6 VIP serves without them", node)
	case ipv4NotLoaded:
		reason = reasonIPv4NotLoaded
		message = fmt.Sprintf("IPv4 VIPs are not loaded on node %s: the rule is not loaded", node)
	default:
		reason = reasonIPv4Unsupported
		message = fmt.Sprintf("IPv4 VIPs are not served on node %s: IPv4 VIPs are turned off there, so they "+
			"are not loaded or advertised, and the rule's IPv6 VIPs serve without them", node)
	}
	return &metav1.Condition{
		Type: ipv4ServedConditionType(node), Status: status, Reason: reason, Message: message,
	}
}

// setRuleConditions writes programmed, advertised and, when non-nil, ipv4 to
// rule's status in one update, and removes node's IPv4Served condition when
// ipv4 is nil. In the same update it removes the Programmed, Advertised and
// IPv4Served conditions of every node in departed (departedGatewayNodes), so a
// gateway node that left without its conditions being cleared, for example
// while no other gateway was running to see its NetworkGateway go, cannot keep
// a stale IPv4Served condition telling the backend nodes to keep their IPv4
// bindings (ipv4LoadedOnSomeNode). It skips the write when nothing changed.
// Every write fans out to every gateway node through the NetworkService watch,
// so an unconditional write would never settle.
//
// Every gateway node and NetworkServiceReconciler write the same status, so a
// write retries on conflict against a fresh read. A rule deleted mid-pass
// has nothing left to record and counts as success.
func (r *NetworkGatewayReconciler) setRuleConditions(
	ctx context.Context, rule *bgpv1alpha1.NetworkService, programmed, advertised metav1.Condition,
	ipv4 *metav1.Condition, departed map[string]bool,
) error {
	key := client.ObjectKeyFromObject(rule)
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		current := &bgpv1alpha1.NetworkService{}
		if err := r.Get(ctx, key, current); err != nil {
			return err
		}
		c := programmed
		c.ObservedGeneration = current.Generation
		changed := meta.SetStatusCondition(&current.Status.Conditions, c)
		a := advertised
		a.ObservedGeneration = current.Generation
		changed = meta.SetStatusCondition(&current.Status.Conditions, a) || changed
		if ipv4 != nil {
			c4 := *ipv4
			c4.ObservedGeneration = current.Generation
			changed = meta.SetStatusCondition(&current.Status.Conditions, c4) || changed
		} else {
			changed = meta.RemoveStatusCondition(&current.Status.Conditions, ipv4ServedConditionType(r.NodeName)) || changed
		}
		changed = removeDepartedNodeConditions(&current.Status.Conditions, departed) || changed
		if !changed {
			return nil
		}
		return r.Status().Update(ctx, current)
	})
	if apierrors.IsNotFound(err) {
		return nil
	}
	return err
}

// removeDepartedNodeConditions removes from conditions the Programmed,
// Advertised and IPv4Served conditions of every node in departed, and reports
// whether it removed any. Other node-scoped conditions, such as a backend
// node's BackendsBound, are left alone.
func removeDepartedNodeConditions(conditions *[]metav1.Condition, departed map[string]bool) bool {
	var gone []string
	for _, c := range *conditions {
		if node, ok := gatewayNodeConditionNode(c.Type); ok && departed[node] {
			gone = append(gone, c.Type)
		}
	}
	for _, t := range gone {
		meta.RemoveStatusCondition(conditions, t)
	}
	return len(gone) > 0
}

// gatewayNodeConditionNode returns the node of a gateway node's Programmed,
// Advertised or IPv4Served condition type, and false for any other type.
func gatewayNodeConditionNode(condType string) (string, bool) {
	node, kind, ok := strings.Cut(condType, "/")
	if !ok || (kind != bgpv1alpha1.ConditionTypeProgrammed && kind != conditionTypeAdvertised &&
		kind != conditionTypeIPv4Served) {
		return "", false
	}
	return node, true
}

// departedGatewayNodes returns the nodes other than this one whose Programmed,
// Advertised or IPv4Served condition some rule in outcomes carries but that no
// NetworkGateway in namespace targets. A node missing from the cached
// NetworkGateway list is confirmed against the API server through APIReader
// before it counts, so a cache that has not yet seen a new gateway node's
// NetworkGateway never strips that node's conditions. The uncached list runs
// only when the cache suggests a node has departed.
func (r *NetworkGatewayReconciler) departedGatewayNodes(
	ctx context.Context, namespace string, outcomes []ruleOutcome,
) (map[string]bool, error) {
	cached, err := gatewayNodeNames(ctx, r.Client, namespace)
	if err != nil {
		return nil, err
	}
	live := make(map[string]bool, len(cached)+1)
	live[r.NodeName] = true
	for _, n := range cached {
		live[n] = true
	}
	candidates := map[string]bool{}
	for _, o := range outcomes {
		for _, c := range o.rule.Status.Conditions {
			if node, ok := gatewayNodeConditionNode(c.Type); ok && !live[node] {
				candidates[node] = true
			}
		}
	}
	if len(candidates) == 0 {
		return nil, nil
	}
	list := &bgpv1alpha1.NetworkGatewayList{}
	if err := r.APIReader.List(ctx, list, client.InNamespace(namespace)); err != nil {
		return nil, fmt.Errorf("list NetworkGateways from the API server: %w", err)
	}
	for _, gw := range list.Items {
		delete(candidates, gw.Spec.TargetRef.Name)
	}
	return candidates, nil
}

// clearNodeRuleConditions removes node's Programmed, Advertised and IPv4Served
// conditions from every NetworkService the gateways in namespace serve, for a
// node that no longer
// serves any of them, and recomputes the rule's summary conditions in the same
// write: when node was the last gateway node, no reconciler is left to do it.
// A write retries on conflict against a fresh read, and a rule deleted
// mid-pass counts as cleared.
func clearNodeRuleConditions(ctx context.Context, c client.Client, scope ServiceScope, namespace, node string) error {
	rules, _, err := scope.listServedNetworkServices(ctx, c, namespace)
	if err != nil {
		return fmt.Errorf("list NetworkServices to clear node %s conditions: %w", node, err)
	}
	nodes, err := gatewayNodeNames(ctx, c, namespace)
	if err != nil {
		return fmt.Errorf("list gateway nodes to clear node %s conditions: %w", node, err)
	}
	var errs []error
	for i := range rules {
		key := client.ObjectKeyFromObject(&rules[i])
		if err := clearNodeConditions(ctx, c, key, node, nodes); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// clearRuleNodeConditions removes node's Programmed, Advertised and IPv4Served
// conditions from the rule known by key, which node no longer serves, and
// recomputes its summary conditions over the gateway nodes serving it.
func clearRuleNodeConditions(
	ctx context.Context, c client.Client, scope ServiceScope, key client.ObjectKey, node string,
) error {
	nodes, err := scope.servingGatewayNodeNames(ctx, c, key.Namespace)
	if err != nil {
		return fmt.Errorf("list gateway nodes to clear node %s conditions: %w", node, err)
	}
	return clearNodeConditions(ctx, c, key, node, nodes)
}

// clearNodeConditions removes node's Programmed, Advertised and IPv4Served
// conditions from the rule known by key and recomputes its summary conditions
// over nodes in the same write. A write retries on conflict against a fresh
// read, and a rule deleted mid-pass counts as cleared.
func clearNodeConditions(
	ctx context.Context, c client.Client, key client.ObjectKey, node string, nodes []string,
) error {
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		current := &bgpv1alpha1.NetworkService{}
		if err := c.Get(ctx, key, current); err != nil {
			return err
		}
		if !removeNodeRuleConditions(&current.Status.Conditions, node) {
			return nil
		}
		if current.DeletionTimestamp.IsZero() {
			applySummaryConditions(current, nodes)
		}
		return c.Status().Update(ctx, current)
	})
	if err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("clear node %s condition on NetworkService %s: %w", node, key.Name, err)
	}
	return nil
}

// removeNodeRuleConditions removes node's Programmed, Advertised and
// IPv4Served conditions from conditions, and reports whether any was there.
func removeNodeRuleConditions(conditions *[]metav1.Condition, node string) bool {
	removed := meta.RemoveStatusCondition(conditions, programmedConditionType(node))
	removed = meta.RemoveStatusCondition(conditions, advertisedConditionType(node)) || removed
	return meta.RemoveStatusCondition(conditions, ipv4ServedConditionType(node)) || removed
}

// hasNodeRuleConditions reports whether rule carries node's Programmed,
// Advertised or IPv4Served condition.
func hasNodeRuleConditions(rule *bgpv1alpha1.NetworkService, node string) bool {
	for _, t := range []string{
		programmedConditionType(node), advertisedConditionType(node), ipv4ServedConditionType(node),
	} {
		if meta.FindStatusCondition(rule.Status.Conditions, t) != nil {
			return true
		}
	}
	return false
}

// withdrawRuleAdvertisements deletes the BGPAdvertisements node created for
// rule, one per address family, so the fabric stops sending the rule's VIP
// traffic to a node that has not loaded it.
func withdrawRuleAdvertisements(
	ctx context.Context, c client.Client, rule *bgpv1alpha1.NetworkService, objNS, node string,
) error {
	return pruneRuleAdvertisements(ctx, c, rule, objNS, node, nil)
}

// pruneRuleAdvertisements deletes every BGPAdvertisement node created for rule
// whose name is not in keep. It selects by networkRuleLabel and deletes those
// isNodeAdvertisement accepts for node, so it never deletes another rule/node
// pair's object by rebuilding a name.
//
// It also deletes an advertisement with no gatewayNodeLabel that carries
// node's legacyRuleAdvertisementName. Releases up to v0.5.3 labelled their
// advertisements with networkRuleLabel alone, so without this the first
// release with ruleAdvertisementName would leave each one advertised beside
// its renamed replacement, and withdrawing the rule from the node would miss
// it.
func pruneRuleAdvertisements(
	ctx context.Context, c client.Client, rule *bgpv1alpha1.NetworkService, objNS, node string, keep map[string]bool,
) error {
	advList := &bgpv1alpha1.BGPAdvertisementList{}
	if err := c.List(ctx, advList, ruleSelector(rule, objNS)); err != nil {
		return fmt.Errorf("list BGPAdvertisements for NetworkService %s: %w", rule.Name, err)
	}

	var errs []error
	for i := range advList.Items {
		adv := &advList.Items[i]
		if keep[adv.Name] {
			continue
		}
		if !isNodeAdvertisement(adv, node) && !isUnlabelledLegacyAdvertisement(adv, rule.Name, node) {
			continue
		}
		if err := c.Delete(ctx, adv); err != nil && !apierrors.IsNotFound(err) {
			errs = append(errs, fmt.Errorf("withdraw BGPAdvertisement %s: %w", adv.Name, err))
		}
	}
	return errors.Join(errs...)
}

// errNoServedVIP is buildDesiredRule's error for a rule whose every VIP is
// IPv4 while IPv4VIPs is off, leaving nothing to load.
var errNoServedVIP = errors.New("every VIP is IPv4, and IPv4 VIPs are turned off on this node")

// errIPv4ForwardingUnavailable is the build error of a rule whose every VIP is
// IPv4 on a pass where this node's IPv4 forwarding could not be turned on, so
// it serves none of them (ensureIPv4Forwarding).
var errIPv4ForwardingUnavailable = errors.New("every VIP is IPv4, and this node's IPv4 forwarding is not on")

// isIPv4VIP reports whether vip is an IPv4 address, written plainly or as an
// IPv4-mapped IPv6 address. Both forms load as the plain IPv4 address when
// IPv4VIPs is on.
func isIPv4VIP(vip netip.Addr) bool {
	return vip.Unmap().Is4()
}

// hasIPv4VIP reports whether rule lists an IPv4 VIP in either form isIPv4VIP
// accepts. Addresses that do not parse are left to buildDesiredRule, which
// rejects them.
func hasIPv4VIP(rule *bgpv1alpha1.NetworkService) bool {
	for _, v := range rule.Spec.VIPAddresses {
		if addr, err := netip.ParseAddr(v); err == nil && isIPv4VIP(addr) {
			return true
		}
	}
	return false
}

// buildDesiredRule converts rule into a gateway.DesiredRule. Its backends are
// the IPv6 addresses of the VPCAttachments rule's BackendSelector picks from
// attachments (selectRuleBackends), one list per VIP family, since another
// rule can own a backend's claim for one family and not the other: Backends
// for the IPv6 VIPs and, when they load, IPv4Backends for the IPv4 VIPs, whose
// backend nodes translate them to IPv6. Each is resolved through sidIndex to the SRv6 uSID of the node
// its attachment reports, with that backend's own slot (backendSID), so a node
// hosting several of the rule's backends can tell which one Maglev chose.
// There is no kernel VRF or FIB dependency.
//
// A selected attachment that is not a backend yet, a backend owners assigns to
// another rule, or a backend whose uSID does not resolve, is left out and
// returned in unresolved, so the rule keeps serving through the rest. A
// backend owned by another rule is left out because its node writes no
// binding for this rule, so a flow sent to it would be dropped there. A backend pod being recreated is enough to cause
// this, since its BGPAdvertisement is gone until the new pod is attached.
// Every gateway node resolves from the same API objects and the Maglev table
// depends only on the backend set, so nodes that see the same objects build
// the same table. A family whose backends all fail is left out, its VIPs
// unloaded, and only when no family has a backend does the rule fail, so it
// is withdrawn rather than advertised with nothing behind it. An invalid VIP
// or selector, a second IPv6 VIP, or a protocol or port the datapath does not
// serve (rulePorts), fails the rule outright, since that is a spec error
// rather than a passing state.
//
// IPv4 VIPs, plain or IPv4-mapped (isIPv4VIP), are left out unless serveIPv4
// is set. Without it the rule's IPv6 VIPs serve without them, and a rule with
// no other VIP fails with errNoServedVIP. With it they load beside the IPv6
// ones, over the IPv6 backends whose ServiceVIPBinding for the IPv4 VIP in
// bindings is Bound (serviceBindings.unbound); the rest are returned in
// unresolved, so a flow never reaches a backend that cannot answer it. While
// none is Bound the VIP loads over every eligible backend, so that the backend
// nodes write their bindings, and ipv4 is ipv4Unbound, which keeps it
// unadvertised. A rule with more than one IPv4 VIP, like one whose IPv4 VIP has
// no backend, serves its IPv6 VIPs without them. ipv4 says which of these
// happened to the rule's IPv4 VIPs; see ipv4Family.
//
// For a rule with a healthCheck, while health applies, each family then leaves
// out the backends whose binding for that family's VIP reports them Unhealthy
// (serviceBindings.unhealthy), unless that is every one of them: a family
// whose backends are all Unhealthy keeps them all, since an empty table would
// drop every flow. rh says what health did. A family still waiting for its
// first Bound binding is not filtered.
func buildDesiredRule(
	rule *bgpv1alpha1.NetworkService, attachments []*cloudv1alpha1.VPCAttachment,
	sidIndex *backendSIDIndex, owners backendOwners, serveIPv4 bool, bindings serviceBindings, health healthGate,
	objNS string,
) (dr gateway.DesiredRule, unresolved []string, ipv4 ipv4Family, rh ruleHealth, err error) {
	if failClosedHealth(rule) && !health.apply {
		return gateway.DesiredRule{}, nil, ipv4Off, ruleHealth{notApplied: health.why},
			fmt.Errorf("fail-closed backend health is unavailable: %s", health.why)
	}

	ipv4 = ipv4Off
	if serveIPv4 {
		ipv4 = ipv4NotLoaded
	}
	port, _, err := rulePorts(rule)
	if err != nil {
		return gateway.DesiredRule{}, nil, ipv4, rh, err
	}
	var v6VIPs, v4VIPs []netip.Addr
	var withheld int
	for _, v := range rule.Spec.VIPAddresses {
		addr, err := netip.ParseAddr(v)
		if err != nil {
			return gateway.DesiredRule{}, nil, ipv4, rh, fmt.Errorf("invalid VIP address %q: %w", v, err)
		}
		if !isIPv4VIP(addr) {
			v6VIPs = append(v6VIPs, addr)
			continue
		}
		if !serveIPv4 {
			withheld++
			continue
		}
		// The datapath keys an IPv4 VIP by its plain form and refuses the
		// IPv4-mapped one, so load the address unmapped.
		v4VIPs = append(v4VIPs, addr.Unmap())
	}
	if len(v6VIPs) == 0 && len(v4VIPs) == 0 && withheld > 0 {
		return gateway.DesiredRule{}, nil, ipv4, rh, errNoServedVIP
	}

	translated, err := ruleTranslatedVIPs(rule)
	if err != nil {
		return gateway.DesiredRule{}, nil, ipv4, rh, err
	}
	var firstFamilyError error
	if len(v4VIPs) > 0 && translated.v4Err != nil {
		// A backend node translates only one IPv4 VIP per rule, so none of
		// them is served; the IPv6 VIPs still are.
		ipv4, firstFamilyError, v4VIPs = ipv4MultipleVIPs, translated.v4Err, nil
	}

	var (
		vips       []netip.Addr
		v6Backends []gateway.DesiredBackend
		v4Backends []gateway.DesiredBackend
	)
	for _, f := range []struct {
		family   addrFamily
		vips     []netip.Addr
		backends *[]gateway.DesiredBackend
	}{
		{familyIPv6, v6VIPs, &v6Backends},
		{familyIPv4, v4VIPs, &v4Backends},
	} {
		if len(f.vips) == 0 {
			continue
		}
		vip := f.vips[0]
		var unbound func(ruleBackend) string
		if f.family == familyIPv4 {
			unbound = func(b ruleBackend) string { return bindings.unbound(rule, objNS, vip, b) }
		}
		var unhealthy func(ruleBackend) bool
		if rule.Spec.HealthCheck != nil && health.apply {
			unhealthy = func(b ruleBackend) bool { return bindings.unhealthy(rule, objNS, vip, b) }
		}
		fam, err := resolveFamilyBackends(rule, attachments, sidIndex, owners, f.family, objNS, unbound, unhealthy)
		unresolved = append(unresolved, fam.unresolved...)
		rh.unhealthy = append(rh.unhealthy, fam.unhealthy...)
		rh.noneHealthy = rh.noneHealthy || fam.noneHealthy
		if err != nil {
			var selErr *backendSelectionError
			if !errors.As(err, &selErr) {
				return gateway.DesiredRule{}, nil, ipv4, rh, err
			}
			if firstFamilyError == nil {
				firstFamilyError = err
			}
			if f.family == familyIPv4 {
				ipv4 = ipv4NoBackend
			}
			continue
		}
		vips = append(vips, f.vips...)
		*f.backends = fam.backends
		if f.family == familyIPv4 {
			ipv4 = ipv4Loaded
			if fam.noneBound {
				ipv4 = ipv4Unbound
			}
		}
	}
	if len(vips) == 0 {
		return gateway.DesiredRule{}, nil, ipv4, rh, firstFamilyError
	}
	if rule.Spec.HealthCheck != nil && !health.apply {
		rh.notApplied = health.why
	}
	sort.Strings(rh.unhealthy)

	return gateway.DesiredRule{
		Key:          rule.Namespace + "/" + rule.Name,
		VPCRef:       rule.Spec.VPCRef,
		VIPAddresses: vips,
		Protocol:     string(rule.Spec.Protocol),
		Port:         port,
		Affinity:     string(rule.Spec.SessionAffinity),
		Backends:     v6Backends,
		IPv4Backends: v4Backends,
	}, unresolved, ipv4, rh, nil
}

// backendSelectionError is resolveFamilyBackends' error for a family none of
// whose selected backends can take a flow. It is not a spec error: the
// family's VIPs are left unloaded until a backend appears.
type backendSelectionError struct{ err error }

func (e *backendSelectionError) Error() string { return e.err.Error() }
func (e *backendSelectionError) Unwrap() error { return e.err }

// familyBackends is what resolveFamilyBackends returns for one VIP family.
type familyBackends struct {
	// backends are the family's Maglev input.
	backends []gateway.DesiredBackend

	// unresolved lists the selected attachments and backends left out, as
	// status messages.
	unresolved []string

	// noneBound is set when no resolved backend's binding is Bound yet, so
	// backends holds every resolved backend.
	noneBound bool

	// unhealthy lists the backends left out as Unhealthy, as "address:port".
	unhealthy []string

	// noneHealthy is set when every candidate backend is Unhealthy, so
	// backends keeps them all.
	noneHealthy bool
}

// resolveFamilyBackends returns rule's backends of family, each resolved to its
// node's uSID with its slot, and the selected attachments and backends that are
// not part of it, as status messages. An invalid selector is returned as is.
// When no backend resolves it returns a *backendSelectionError saying why.
//
// A non-nil unbound returns why a resolved backend's ServiceVIPBinding is not
// Bound, or "" when it is. Only Bound backends are returned then, and the rest
// join unresolved; while none is Bound, every resolved backend is returned and
// noneBound is set.
//
// A non-nil unhealthy reports whether a backend is Unhealthy. Those backends
// are left out and listed in unhealthy, unless every remaining backend is
// Unhealthy, when all are kept and noneHealthy is set. It does not apply while
// noneBound is set.
func resolveFamilyBackends(
	rule *bgpv1alpha1.NetworkService, attachments []*cloudv1alpha1.VPCAttachment,
	sidIndex *backendSIDIndex, owners backendOwners, family addrFamily, objNS string,
	unbound func(ruleBackend) string, unhealthy func(ruleBackend) bool,
) (familyBackends, error) {
	sel, err := selectRuleBackends(rule, attachments, owners, family, objNS)
	if err != nil {
		return familyBackends{}, err
	}
	var out familyBackends
	out.unresolved = sel.pending
	for _, c := range sel.claimed {
		out.unresolved = append(out.unresolved, c.String())
	}

	type resolved struct {
		rb ruleBackend
		db gateway.DesiredBackend
	}
	all := make([]resolved, 0, len(sel.backends))
	bound := make([]resolved, 0, len(sel.backends))
	var held []string
	var firstResolveErr error
	for _, b := range sel.backends {
		usid, err := sidIndex.resolveUSID(b.addr, rule.Spec.VPCRef, b.node)
		if err == nil {
			usid, err = backendSID(usid, b.addr, b.port)
		}
		if err != nil {
			if firstResolveErr == nil {
				firstResolveErr = fmt.Errorf("resolve backend %s: %w", b, err)
			}
			out.unresolved = append(out.unresolved, b.String())
			continue
		}
		r := resolved{rb: b, db: gateway.DesiredBackend{Address: b.addr, Port: b.port, USID: usid}}
		all = append(all, r)
		if unbound == nil {
			continue
		}
		if why := unbound(b); why != "" {
			held = append(held, b.String()+": "+why)
			continue
		}
		bound = append(bound, r)
	}
	if len(all) > 0 {
		candidates := all
		switch {
		case unbound == nil:
		case len(bound) > 0:
			candidates = bound
			out.unresolved = append(out.unresolved, held...)
		default:
			out.noneBound = true
			if !failClosedHealth(rule) {
				unhealthy = nil
			}
		}
		if unhealthy != nil {
			healthy := make([]resolved, 0, len(candidates))
			for _, c := range candidates {
				if unhealthy(c.rb) {
					out.unhealthy = append(out.unhealthy, c.rb.String())
					continue
				}
				healthy = append(healthy, c)
			}
			if len(healthy) == 0 {
				if failClosedHealth(rule) {
					return out, &backendSelectionError{err: errNoHealthyBackends}
				}
				out.noneHealthy = true
			} else {
				candidates = healthy
			}
		}
		out.backends = make([]gateway.DesiredBackend, 0, len(candidates))
		for _, c := range candidates {
			out.backends = append(out.backends, c.db)
		}
		return out, nil
	}
	switch {
	case firstResolveErr != nil:
		err = fmt.Errorf("none of %d backends resolves: %w", len(out.unresolved), firstResolveErr)
	case len(sel.claimed) > 0 && len(sel.pending) == 0:
		err = fmt.Errorf("every selected backend is served by an older rule: %s", cappedList(out.unresolved))
	case len(out.unresolved) > 0:
		err = fmt.Errorf("no selected attachment is a backend yet: %s", cappedList(out.unresolved))
	default:
		err = fmt.Errorf("backendSelector matches no VPCAttachment in VPC %s", rule.Spec.VPCRef)
	}
	return familyBackends{unresolved: out.unresolved}, &backendSelectionError{err: err}
}

// routerNameForNode returns the name of this node's Galactic-owned
// BGPRouter, or "" if none exists yet. A method wrapper around the
// package-level function of the same name.
func (r *NetworkGatewayReconciler) routerNameForNode(ctx context.Context, namespace string) (string, error) {
	return routerNameForNode(ctx, r.Client, namespace, r.NodeName)
}

// errAmbiguousRouter reports more than one Galactic-owned BGPRouter on a
// node.
var errAmbiguousRouter = errors.New("ambiguous BGP config")

// routerNameForNode returns the name of the Galactic-owned BGPRouter whose
// targetRef.name matches nodeName, or "" if none exists yet. Routers that
// name a routerClassName belong to another implementation (the fabric
// underlay) and are skipped. More than one Galactic-owned router on the node
// is an error rather than an arbitrary pick, since the caller attaches
// advertisements to the result. A free function so EgressShardReconciler can
// resolve the same "which BGPRouter is mine" lookup without duplicating it or
// reaching into another reconciler's method set.
func routerNameForNode(ctx context.Context, c client.Client, namespace, nodeName string) (string, error) {
	list := &bgpv1alpha1.BGPRouterList{}
	if err := c.List(ctx, list,
		client.InNamespace(namespace),
		client.MatchingFields{BGPRouterByTargetName: nodeName},
	); err != nil {
		return "", fmt.Errorf("list BGPRouters for node %s: %w", nodeName, err)
	}
	owned := bgpv1alpha1.LegacyOwnedRouters(list.Items)
	switch len(owned) {
	case 0:
		return "", nil
	case 1:
		return owned[0].Name, nil
	default:
		names := make([]string, 0, len(owned))
		for _, rt := range owned {
			names = append(names, rt.Name)
		}
		sort.Strings(names)
		return "", fmt.Errorf("%w: node %s has %d BGPRouters (%s)",
			errAmbiguousRouter, nodeName, len(owned), strings.Join(names, ", "))
	}
}

// applyBGPAdvertisements reconciles the BGPAdvertisements for a single rule,
// one per non-empty VIP address family, named by ruleAdvertisementName.
// The IPv4 family is advertised only with advertiseIPv4, which the caller sets
// when this node loaded the rule's IPv4 VIP over only the eligible backends
// whose ServiceVIPBinding is Bound, at least one. Without it this node's "-v4"
// advertisement is deleted first, before and whatever the outcome of the
// other families' writes, so the route goes as soon as the gate closes.
// Once every one is applied, it deletes any other advertisement this node made
// for the rule: one for a family whose VIPs are gone, or one under a name from
// an earlier naming scheme.
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
// Every object created or touched here is labeled with networkRuleLabel and
// gatewayNodeLabel, both backfilled on existing objects too. networkRuleLabel
// is what lets rule teardown find every advertisement a rule ever caused on any
// gateway node, including one that has since left the namespace, without
// depending on this naming convention. gatewayNodeLabel lets
// withdrawNodeAdvertisements find every advertisement one node made, whatever
// rule caused it.
//
// Each lives in objNS, the gateway's namespace, beside the BGPRouter it hangs
// off. One for a rule in objNS also carries an owner reference to rule, again
// backfilled, so Kubernetes garbage collection deletes it once the rule is
// gone; a tenant rule's cannot, and relies on teardown and the sweep. That covers
// an advertisement created from a stale cache after reconcileDelete listed the
// rule's advertisements: teardown never sees it, and without the reference
// nothing would ever withdraw it. The reference is not a controller reference
// and leaves blockOwnerDeletion unset, so it neither blocks the rule's deletion
// nor needs extra RBAC. A rule that is already being deleted gets nothing
// created or updated at all.
func (r *NetworkGatewayReconciler) applyBGPAdvertisements(
	ctx context.Context, objNS string, rule *bgpv1alpha1.NetworkService, desired gateway.DesiredRule,
	routerName string, advertiseIPv4 bool,
) error {
	if !rule.DeletionTimestamp.IsZero() {
		return nil
	}
	v4Prefixes, v6Prefixes := prefixesByFamily(desired.VIPAddresses)
	if !advertiseIPv4 {
		// The gate is closed. Withdraw this node's -v4 route now rather than
		// through the prune below, which waits for every other family's write
		// to succeed.
		v4Prefixes = nil
		if err := r.withdrawIPv4Advertisement(ctx, objNS, rule); err != nil {
			return err
		}
	}

	groups := []struct {
		suffix   string
		prefixes []string
	}{
		{"v4", v4Prefixes},
		{"v6", v6Prefixes},
	}

	var firstErr error
	keep := map[string]bool{}
	for _, g := range groups {
		if len(g.prefixes) == 0 {
			continue
		}
		name := ruleKeyAdvertisementName(client.ObjectKeyFromObject(rule), objNS, r.NodeName, g.suffix)
		keep[name] = true
		// Built as l2vpn/evpn whatever the VIP's own family, since the runtime
		// never originates plain unicast advertisements. The per-family split
		// still matters because one EVPN IP-Prefix route's Prefix field is
		// single-family, so a dual-stack rule needs two advertisements.

		prefixes := make([]bgpv1alpha1.Prefix, len(g.prefixes))
		for i, p := range g.prefixes {
			prefixes[i] = bgpv1alpha1.Prefix(p)
		}

		adv := &bgpv1alpha1.BGPAdvertisement{}
		key := types.NamespacedName{Namespace: objNS, Name: name}
		err := r.Get(ctx, key, adv)
		switch {
		case apierrors.IsNotFound(err):
			adv = &bgpv1alpha1.BGPAdvertisement{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: objNS,
					Name:      name,
					Labels:    ruleLabels(rule, objNS),
				},
				Spec: bgpv1alpha1.BGPAdvertisementSpec{
					RouterRef:     bgpv1alpha1.RouterRef{Name: routerName},
					AddressFamily: bgpv1alpha1.AddressFamily{AFI: bgpv1alpha1.AFIL2VPN, SAFI: bgpv1alpha1.SAFIEVPN},
					Prefixes:      prefixes,
				},
			}
			adv.Labels[gatewayNodeLabel] = gatewayNodeLabelValue(r.NodeName)
			if refErr := setRuleOwner(rule, adv, r.Scheme); refErr != nil {
				if firstErr == nil {
					firstErr = fmt.Errorf("set owner reference on BGPAdvertisement %s: %w", name, refErr)
				}
				continue
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
		// Set networkRuleLabel and gatewayNodeLabel on every pass, so rule
		// teardown's and node withdrawal's label-selector lists find the
		// object.
		setRuleLabels(advCopy, rule, objNS)
		advCopy.Labels[gatewayNodeLabel] = gatewayNodeLabelValue(r.NodeName)
		// Backfill the owner reference the same way, so garbage collection
		// covers an advertisement created before it was set.
		if refErr := setRuleOwner(rule, advCopy, r.Scheme); refErr != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("set owner reference on BGPAdvertisement %s: %w", name, refErr)
			}
			continue
		}
		advCopy.Spec.RouterRef = bgpv1alpha1.RouterRef{Name: routerName}
		advCopy.Spec.AddressFamily = bgpv1alpha1.AddressFamily{AFI: bgpv1alpha1.AFIL2VPN, SAFI: bgpv1alpha1.SAFIEVPN}
		advCopy.Spec.Prefixes = prefixes
		if updateErr := r.Update(ctx, advCopy); updateErr != nil && firstErr == nil {
			firstErr = fmt.Errorf("update BGPAdvertisement %s: %w", name, updateErr)
		}
	}
	if firstErr != nil {
		// Leave older advertisements in place until their replacements exist,
		// so a failed create never leaves the rule unadvertised.
		return firstErr
	}
	return pruneRuleAdvertisements(ctx, r.Client, rule, objNS, r.NodeName, keep)
}

// withdrawIPv4Advertisement deletes the "-v4" advertisement this node made for
// rule, if any. It deletes only an object isNodeAdvertisement accepts for this
// node, so it never removes another node's route.
func (r *NetworkGatewayReconciler) withdrawIPv4Advertisement(
	ctx context.Context, objNS string, rule *bgpv1alpha1.NetworkService,
) error {
	adv := &bgpv1alpha1.BGPAdvertisement{}
	key := types.NamespacedName{
		Namespace: objNS,
		Name:      ruleKeyAdvertisementName(client.ObjectKeyFromObject(rule), objNS, r.NodeName, "v4"),
	}
	if err := r.Get(ctx, key, adv); err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("get BGPAdvertisement %s: %w", key.Name, err)
	}
	if !isNodeAdvertisement(adv, r.NodeName) || !generatedFor(adv, rule) {
		return nil
	}
	if err := r.Delete(ctx, adv); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("withdraw BGPAdvertisement %s: %w", key.Name, err)
	}
	return nil
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
	b := ctrl.NewControllerManagedBy(mgr).
		For(&bgpv1alpha1.NetworkGateway{}).
		Watches(&bgpv1alpha1.NetworkService{}, handler.EnqueueRequestsFromMapFunc(
			func(ctx context.Context, obj client.Object) []ctrlreconcile.Request {
				return ruleToGatewayRequests(ctx, r.Client, r.Scope, obj)
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
		//
		// Backend resolution reads only these objects' specs, so status-only
		// updates are filtered out, and advertisements that can never locate a
		// backend (the gateway's own VIP advertisements among them) are
		// filtered out entirely. Every pod attach still writes one that passes;
		// the engine then skips every rule whose resolved state is unchanged.
		Watches(&bgpv1alpha1.BGPRouter{}, handler.EnqueueRequestsFromMapFunc(
			func(ctx context.Context, obj client.Object) []ctrlreconcile.Request {
				return broadcastToGatewayRequests(ctx, r.Client, obj.GetNamespace(), "BGPRouter", obj.GetName())
			}),
			builder.WithPredicates(predicate.GenerationChangedPredicate{}),
		).
		Watches(&bgpv1alpha1.BGPAdvertisement{}, handler.EnqueueRequestsFromMapFunc(
			func(ctx context.Context, obj client.Object) []ctrlreconcile.Request {
				return broadcastToGatewayRequests(ctx, r.Client, obj.GetNamespace(), "BGPAdvertisement", obj.GetName())
			}),
			builder.WithPredicates(backendAdvertisementPredicate()),
		).
		Watches(&bgpv1alpha1.BGPVRFInstance{}, handler.EnqueueRequestsFromMapFunc(
			func(ctx context.Context, obj client.Object) []ctrlreconcile.Request {
				return broadcastToGatewayRequests(ctx, r.Client, obj.GetNamespace(), "BGPVRFInstance", obj.GetName())
			}),
			builder.WithPredicates(predicate.GenerationChangedPredicate{}),
		).
		// A rule's backends are the VPCAttachments its selector picks, so an
		// attachment appearing, moving node, changing address or changing
		// labels changes some rule's backend set. Attachments live in tenant
		// namespaces, not the gateway's, so every NetworkGateway is
		// re-queued. Their address and node come from spec and status alike,
		// so the predicate compares the fields selectRuleBackends reads on
		// both rather than the generation, and drops updates that change
		// only conditions or other status; the engine skips every rule whose
		// resolved state is unchanged.
		Watches(&cloudv1alpha1.VPCAttachment{}, handler.EnqueueRequestsFromMapFunc(
			func(ctx context.Context, obj client.Object) []ctrlreconcile.Request {
				return allGatewayRequests(ctx, r.Client, "VPCAttachment", obj.GetNamespace()+"/"+obj.GetName())
			}),
			builder.WithPredicates(vpcAttachmentBackendChanged()),
		)
	if r.IPv4VIPs || r.BackendHealth {
		// A rule's IPv4 VIP is balanced over, and advertised for, only the
		// backends whose bindings are Bound, and a rule with a healthCheck
		// over only the backends no binding reports Unhealthy, so a binding
		// appearing, going, changing, becoming Bound or not, or changing its
		// health changes some rule. Bindings live in the gateways' namespace.
		// With neither IPv4VIPs nor BackendHealth nothing reads them, and the
		// gateway needs no access to them.
		b = b.Watches(&bgpv1alpha1.ServiceVIPBinding{}, handler.EnqueueRequestsFromMapFunc(
			func(ctx context.Context, obj client.Object) []ctrlreconcile.Request {
				return broadcastToGatewayRequests(ctx, r.Client, obj.GetNamespace(), "ServiceVIPBinding", obj.GetName())
			}),
			builder.WithPredicates(bindingReadinessChanged(r.BackendHealth)),
		)
	}
	if r.BackendHealth {
		// Health applies only while every NetworkGateway in the namespace
		// reports BackendHealthFiltering, so a gateway appearing, going, or
		// changing that report re-queues every gateway in the namespace, not
		// only its own node's.
		b = b.Watches(&bgpv1alpha1.NetworkGateway{}, handler.EnqueueRequestsFromMapFunc(
			func(ctx context.Context, obj client.Object) []ctrlreconcile.Request {
				return broadcastToGatewayRequests(ctx, r.Client, obj.GetNamespace(), "NetworkGateway", obj.GetName())
			}),
			builder.WithPredicates(gatewayHealthFilteringChanged()),
		)
	}
	return b.Named("networkgateway").Complete(r)
}

// backendAdvertisementPredicate passes only BGPAdvertisement events a pass can
// act on.
//
// buildBackendSIDIndex ignores an advertisement without both VRFID and
// Function, so a create or delete of one is dropped. An update passes when its
// spec changed and either side carries both, so an advertisement gaining or
// losing them still triggers a pass.
//
// The gateway's own VIP advertisements carry networkRuleLabel and neither
// field. Their creates come from this reconciler and are dropped, but a delete
// or a spec edit passes, so the next pass restores what was lost. So does a
// status write that changes whether galactic-router reports one advertised
// (installedChanged), which the node's Advertised condition on the rule
// follows.
func backendAdvertisementPredicate() predicate.Predicate {
	return predicate.Funcs{
		CreateFunc: func(e event.CreateEvent) bool { return locatesBackend(e.Object) },
		DeleteFunc: func(e event.DeleteEvent) bool {
			return locatesBackend(e.Object) || isRuleAdvertisement(e.Object)
		},
		UpdateFunc: func(e event.UpdateEvent) bool {
			if e.ObjectOld == nil || e.ObjectNew == nil {
				return false
			}
			if e.ObjectOld.GetGeneration() == e.ObjectNew.GetGeneration() {
				// A status write matters only when it changes whether a rule
				// advertisement is installed, which its gateway node reports
				// on the rule's Advertised condition.
				return isRuleAdvertisement(e.ObjectNew) && installedChanged(e.ObjectOld, e.ObjectNew)
			}
			return locatesBackend(e.ObjectOld) || locatesBackend(e.ObjectNew) ||
				isRuleAdvertisement(e.ObjectOld) || isRuleAdvertisement(e.ObjectNew)
		},
		GenericFunc: func(e event.GenericEvent) bool { return locatesBackend(e.Object) },
	}
}

// installedChanged reports whether old and updated, two versions of one
// BGPAdvertisement, differ in advertisementInstalled.
func installedChanged(old, updated client.Object) bool {
	o, ok1 := old.(*bgpv1alpha1.BGPAdvertisement)
	n, ok2 := updated.(*bgpv1alpha1.BGPAdvertisement)
	return ok1 && ok2 && advertisementInstalled(o) != advertisementInstalled(n)
}

// locatesBackend reports whether obj is a BGPAdvertisement buildBackendSIDIndex
// would consider: one carrying both a VRFID and a Function.
func locatesBackend(obj client.Object) bool {
	adv, ok := obj.(*bgpv1alpha1.BGPAdvertisement)
	return ok && adv.Spec.VRFID != nil && adv.Spec.Function != nil
}

// isRuleAdvertisement reports whether obj is a gateway VIP advertisement made
// for a NetworkService.
func isRuleAdvertisement(obj client.Object) bool {
	_, ok := obj.GetLabels()[networkRuleLabel]
	return ok
}

// ruleToGatewayRequests maps a NetworkService change to every NetworkGateway
// serving it (servingGateways). A NetworkService carries no gatewayRef, and every gateway node
// advertises every VIP identically (anycast), so every gateway node in the
// rule's PoP must re-evaluate its own engine state whenever any rule changes.
// The broadcast is intentional rather than a missing index.
func ruleToGatewayRequests(
	ctx context.Context, c client.Client, scope ServiceScope, obj client.Object,
) []ctrlreconcile.Request {
	rule, ok := obj.(*bgpv1alpha1.NetworkService)
	if !ok {
		return nil
	}
	gws, err := scope.servingGateways(ctx, c, rule.Namespace)
	if err != nil {
		log.FromContext(ctx).Error(err, "list NetworkGateways for change", "sourceKind", "NetworkService",
			"sourceName", rule.Name)
		return nil
	}
	reqs := make([]ctrlreconcile.Request, 0, len(gws))
	for i := range gws {
		reqs = append(reqs, ctrlreconcile.Request{NamespacedName: client.ObjectKeyFromObject(&gws[i])})
	}
	return reqs
}

// broadcastToGatewayRequests lists every NetworkGateway in namespace and
// returns a reconcile request for each. It is the primitive the NetworkService,
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

// allGatewayRequests returns a reconcile request for every NetworkGateway in
// every namespace, for a change to an object that lives outside the gateways'
// namespace, such as a tenant's VPCAttachment.
func allGatewayRequests(ctx context.Context, c client.Client, sourceKind, sourceName string) []ctrlreconcile.Request {
	return broadcastToGatewayRequests(ctx, c, metav1.NamespaceAll, sourceKind, sourceName)
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
// gateway nodes. NetworkServiceReconciler uses it to scope its per-object
// lifecycle work to gateway-role nodes, so every other node's router process
// leaves NetworkService objects alone.
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

// ruleAdvertisementHashLen is how many hex characters of a rule/node pair's
// SHA-256 ruleAdvertisementName keeps.
const ruleAdvertisementHashLen = 10

// ruleAdvertisementName returns the name of the BGPAdvertisement node creates
// for rule's family ("v4" or "v6"): a readable "<rule>-<node>" prefix, a short
// hash of the rule and node names, and the family.
//
// The hash is what keeps names distinct. Both names may contain dashes, so
// "<rule>-<node>" alone maps rule "a-b" on node "c" and rule "a" on node "b-c"
// to the same name, and the two nodes would then fight over one object (issue
// #762). The hash input joins the names with "/", which neither can contain.
// The prefix is cut to keep the result within an object name's 253 characters
// and trimmed to end in an alphanumeric.
func ruleAdvertisementName(rule, node, family string) string {
	return ruleKeyAdvertisementName(types.NamespacedName{Name: rule}, "", node, family)
}

// ruleKeyAdvertisementName is ruleAdvertisementName for the rule known by
// key whose advertisements live in objNS. A tenant rule's prefix leads with
// its namespace and its hash covers "<namespace>/<rule>/<node>", so it never
// matches a name a rule in objNS gets.
func ruleKeyAdvertisementName(key types.NamespacedName, objNS, node, family string) string {
	hashKey, rulePrefix := ruleNameKey(key, objNS)
	sum := sha256.Sum256([]byte(hashKey + "/" + node))
	suffix := "-" + hex.EncodeToString(sum[:])[:ruleAdvertisementHashLen] + "-" + family
	prefix := rulePrefix + "-" + node
	if maxPrefix := validation.DNS1123SubdomainMaxLength - len(suffix); len(prefix) > maxPrefix {
		prefix = prefix[:maxPrefix]
	}
	prefix = strings.TrimRightFunc(prefix, func(c rune) bool {
		return (c < 'a' || c > 'z') && (c < '0' || c > '9')
	})
	return prefix + suffix
}

// legacyRuleAdvertisementName is the "<rule>-<node>-<family>" name releases
// before issue #762 gave a rule's advertisement. isNodeAdvertisement still
// accepts it so the first apply after an upgrade deletes those objects, and
// node withdrawal still finds one left by a node that never ran this release.
func legacyRuleAdvertisementName(rule, node, family string) string {
	return rule + "-" + node + "-" + family
}

// isUnlabelledLegacyAdvertisement reports whether adv carries no
// gatewayNodeLabel and is named legacyRuleAdvertisementName for rule and node:
// an advertisement a release up to v0.5.3 created for the pair.
func isUnlabelledLegacyAdvertisement(adv *bgpv1alpha1.BGPAdvertisement, rule, node string) bool {
	if _, ok := adv.Labels[gatewayNodeLabel]; ok {
		return false
	}
	return adv.Name == legacyRuleAdvertisementName(rule, node, "v4") ||
		adv.Name == legacyRuleAdvertisementName(rule, node, "v6")
}

// isNodeAdvertisement reports whether adv is one applyBGPAdvertisements created
// on node nodeName: it carries gatewayNodeLabel set to
// gatewayNodeLabelValue(nodeName) and networkRuleLabel, and is named by
// ruleAdvertisementName or legacyRuleAdvertisementName for that rule and node.
// An advertisement missing either label is never claimed, whatever its name.
func isNodeAdvertisement(adv *bgpv1alpha1.BGPAdvertisement, nodeName string) bool {
	if adv.Labels[gatewayNodeLabel] != gatewayNodeLabelValue(nodeName) {
		return false
	}
	key, ok := ruleKeyFromLabels(adv)
	if !ok {
		return false
	}
	tenant := key.Namespace != adv.Namespace
	for _, family := range []string{"v4", "v6"} {
		if adv.Name == ruleKeyAdvertisementName(key, adv.Namespace, nodeName, family) ||
			(!tenant && adv.Name == legacyRuleAdvertisementName(key.Name, nodeName, family)) {
			return true
		}
	}
	return false
}

// sweepOrphanedAdvertisements deletes this node's BGPAdvertisements for rules
// that no longer exist. rules is every NetworkService the gateways in
// namespace serve, as this pass listed them.
//
// This node can create an advertisement from a cache that has not yet seen its
// rule's deletion timestamp, after NetworkServiceReconciler's teardown has already
// removed the finalizer. Teardown never sees that advertisement. Without this
// sweep it would stay advertised, with no node serving the rule, until
// Kubernetes garbage collection follows its owner reference. Here it is
// withdrawn on the pass where this node's cache drops the rule, the same pass
// that unloads the rule from the datapath.
//
// A rule missing from rules is looked up through APIReader first and kept if it
// still exists, so a cache that has not yet seen a new rule never withdraws a
// live route. The exception is a project rule's advertisement while
// Scope.ProjectServices is off: nothing serves that rule any more, so its
// route is withdrawn whether or not the rule exists.
func (r *NetworkGatewayReconciler) sweepOrphanedAdvertisements(
	ctx context.Context, namespace string, rules []bgpv1alpha1.NetworkService,
) error {
	known := make(map[types.NamespacedName]bool, len(rules))
	for i := range rules {
		known[client.ObjectKeyFromObject(&rules[i])] = true
	}

	advList := &bgpv1alpha1.BGPAdvertisementList{}
	if err := r.List(ctx, advList,
		client.InNamespace(namespace),
		client.MatchingLabels{gatewayNodeLabel: gatewayNodeLabelValue(r.NodeName)},
	); err != nil {
		return fmt.Errorf("list BGPAdvertisements for gateway node %s: %w", r.NodeName, err)
	}

	var errs []error
	for i := range advList.Items {
		adv := &advList.Items[i]
		if !isNodeAdvertisement(adv, r.NodeName) {
			continue
		}
		ruleName, _ := ruleKeyFromLabels(adv)
		if known[ruleName] {
			continue
		}
		unserved := !r.Scope.ProjectServices && ruleName.Namespace != adv.Namespace
		err := r.APIReader.Get(ctx, ruleName, &bgpv1alpha1.NetworkService{})
		switch {
		case unserved:
		case err == nil:
			continue
		case !apierrors.IsNotFound(err):
			errs = append(errs, fmt.Errorf("check NetworkService %s for BGPAdvertisement %s: %w", ruleName, adv.Name, err))
			continue
		}
		if err := r.Delete(ctx, adv); err != nil && !apierrors.IsNotFound(err) {
			errs = append(errs, fmt.Errorf("withdraw BGPAdvertisement %s for deleted NetworkService %s: %w",
				adv.Name, ruleName, err))
		}
	}
	return errors.Join(errs...)
}

// withdrawNodeAdvertisements deletes every BGPAdvertisement that gateway node
// nodeName created in namespace: each per-rule, per-address-family route it
// advertised. It lists by gatewayNodeLabel and deletes those that
// isNodeAdvertisement accepts, so it needs no NetworkService object, live or
// deleted, and never matches by name suffix. An advertisement without
// gatewayNodeLabel is not withdrawn and has to be deleted by hand.
//
// nodeName is the departing node's identity, not the caller's: the caller may
// be any surviving gateway node's process. Concurrent sweeps are harmless
// because every delete is idempotent.
func withdrawNodeAdvertisements(ctx context.Context, c client.Client, namespace, nodeName string) error {
	advList := &bgpv1alpha1.BGPAdvertisementList{}
	if err := c.List(ctx, advList,
		client.InNamespace(namespace),
		client.MatchingLabels{gatewayNodeLabel: gatewayNodeLabelValue(nodeName)},
	); err != nil {
		return fmt.Errorf("list BGPAdvertisements for departed gateway node %s: %w", nodeName, err)
	}

	var errs []error
	for i := range advList.Items {
		adv := &advList.Items[i]
		if !isNodeAdvertisement(adv, nodeName) {
			continue
		}
		if err := c.Delete(ctx, adv); err != nil && !apierrors.IsNotFound(err) {
			errs = append(errs, fmt.Errorf("withdraw BGPAdvertisement %s: %w", adv.Name, err))
		}
	}
	return errors.Join(errs...)
}
