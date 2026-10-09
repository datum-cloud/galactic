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

	cloudv1alpha1 "go.datum.net/cloud/api/v1alpha1"
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

	// ReconcileOrphans removes vip_table state left behind by a mid-reconcile
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
	// not resolve, for example while a backend pod is being recreated. The
	// rule keeps serving through the rest.
	reasonBackendsUnresolved = "BackendsUnresolved"

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
			if clearErr := clearNodeRuleConditions(ctx, r.Client, req.Namespace, req.Name); clearErr != nil {
				logger.Error(clearErr, "clear Programmed conditions for departed gateway node", "node", req.Name)
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
		if clearErr := clearNodeRuleConditions(ctx, r.Client, gw.Namespace, gw.Name); clearErr != nil {
			logger.Error(clearErr, "clear Programmed conditions for terminating NetworkGateway",
				"networkGateway", req.NamespacedName)
			withdrawErr = errors.Join(withdrawErr, clearErr)
		}
		if stopErr := r.Engine.Stop(ctx); stopErr != nil {
			logger.Error(stopErr, "stop gateway engine for terminating NetworkGateway", "networkGateway", req.NamespacedName)
		}
		r.drain.reset()
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

	if r.Disabled {
		withdrawErr := errors.Join(
			withdrawNodeAdvertisements(ctx, r.Client, gw.Namespace, r.NodeName),
			clearNodeRuleConditions(ctx, r.Client, gw.Namespace, r.NodeName),
		)
		gwCopy := gw.DeepCopy()
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

	desired, outcomes, requeueAfter, err := r.gatherRules(ctx, gw.Namespace, ruleList.Items, sidIndex)
	if err != nil {
		return ctrl.Result{}, err
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

	advErr, ruleStatusErr := r.publishRuleOutcomes(ctx, outcomes, status, routerName)

	gwCopy := gw.DeepCopy()
	gwCopy.Status.ObservedGeneration = gw.Generation
	setGatewayCondition(gwCopy, readyConditionFor(status, advErr))
	if updateErr := r.Status().Update(ctx, gwCopy); updateErr != nil {
		logger.Error(updateErr, "update NetworkGateway status")
	}

	sweepErr := r.sweepOrphanedAdvertisements(ctx, gw.Namespace, ruleList.Items)
	if sweepErr != nil {
		logger.Error(sweepErr, "withdraw advertisements for deleted NetworkRules")
	}

	// Crash recovery. A failed sweep leaves orphaned vip_table state behind
	// until a later pass succeeds, so it is returned for retry, after the
	// status write above so the failure stays visible on the object.
	if err := r.Engine.ReconcileOrphans(ctx, desired, cutoff); err != nil {
		logger.Error(err, "reconcile orphaned vip_table state")
		return ctrl.Result{}, errors.Join(advErr, ruleStatusErr, sweepErr,
			fmt.Errorf("reconcile orphaned vip_table state: %w", err))
	}

	if err := errors.Join(advErr, ruleStatusErr, sweepErr); err != nil {
		return ctrl.Result{}, err
	}
	// Nothing else is sure to trigger the pass that drops a held rule once
	// its drain delay ends, so ask for it.
	return ctrl.Result{RequeueAfter: requeueAfter}, nil
}

// gatherRules builds this pass's engine state and rule outcomes from rules,
// every NetworkRule in namespace, and settles the drain tracker against it. It
// returns how long until a held rule's drain delay ends, or zero.
func (r *NetworkGatewayReconciler) gatherRules(
	ctx context.Context, namespace string, rules []bgpv1alpha1.NetworkRule, sidIndex *backendSIDIndex,
) (gateway.EngineState, []ruleOutcome, time.Duration, error) {
	logger := log.FromContext(ctx)
	desired := gateway.EngineState{Rules: make(map[string]gateway.DesiredRule)}

	// Every accepted, non-deleting rule gets an outcome, including one that
	// failed to build: the engine drops it from the datapath, so the outcome
	// is what withdraws its advertisement and records why it is not loaded.
	// A draining rule gets one too, marked so nothing is published for it.
	var outcomes []ruleOutcome

	// live holds every listed rule that is not being deleted, so the drain
	// tracker can tell a deleted rule from one that merely stopped building.
	live := make(map[string]bool, len(rules))

	for i := range rules {
		rule := &rules[i]
		if !rule.DeletionTimestamp.IsZero() {
			// Being torn down. NetworkRuleReconciler's finalizer owns the
			// rule's advertisements: reconcileDelete deletes every one
			// carrying networkRuleLabel, whichever node made it. Until they
			// are all gone the route may still draw traffic here, so the rule
			// stays loaded as draining, which advertises nothing and leaves
			// the Programmed condition alone. Once they are gone, the drain
			// tracker keeps it for ruleDrainDelay so the withdrawal can reach
			// every peer before the datapath drops it.
			o, draining, err := r.drainingOutcome(ctx, rule, sidIndex)
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
			// No gateway node has accepted this rule yet. Once accepted, a rule
			// loses Accepted only when no NetworkGateway is left in the
			// namespace (updateAcceptedCondition), and each node's NotFound
			// branch has then already withdrawn its advertisements and cleared
			// its Programmed condition, so this loop gives the rule no outcome.
			continue
		}

		dr, unresolved, err := buildDesiredRule(rule, sidIndex)
		if err != nil {
			logger.Error(err, "build desired rule; skipping", "networkRule", rule.Name)
			outcomes = append(outcomes, ruleOutcome{rule: rule, buildErr: err})
			continue
		}
		if len(unresolved) > 0 {
			logger.Info("loading rule without unresolved backends", "networkRule", rule.Name, "unresolved", unresolved)
		}
		desired.Rules[dr.Key] = dr
		outcomes = append(outcomes, ruleOutcome{rule: rule, desired: dr, unresolved: unresolved})
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
func (r *NetworkGatewayReconciler) drainingOutcome(
	ctx context.Context, rule *bgpv1alpha1.NetworkRule, sidIndex *backendSIDIndex,
) (ruleOutcome, bool, error) {
	if !controllerutil.ContainsFinalizer(rule, networkRuleFinalizer) {
		return ruleOutcome{}, false, nil
	}
	advList := &bgpv1alpha1.BGPAdvertisementList{}
	if err := r.List(ctx, advList,
		client.InNamespace(rule.Namespace),
		client.MatchingLabels{networkRuleLabel: rule.Name},
	); err != nil {
		return ruleOutcome{}, false, fmt.Errorf("list BGPAdvertisements for deleting NetworkRule %s/%s: %w",
			rule.Namespace, rule.Name, err)
	}
	if len(advList.Items) == 0 {
		return ruleOutcome{}, false, nil
	}

	dr, _, err := buildDesiredRule(rule, sidIndex)
	if err != nil {
		var ok bool
		if dr, ok = r.drain.lastLoaded(rule.Namespace + "/" + rule.Name); !ok {
			return ruleOutcome{}, false, nil
		}
	}
	return ruleOutcome{rule: rule, desired: dr, draining: true}, true, nil
}

// ruleOutcome is one accepted NetworkRule's result from a reconcile pass: the
// engine state it built, or why it could not be built. unresolved lists the
// backends left out of desired because their uSID did not resolve.
type ruleOutcome struct {
	rule       *bgpv1alpha1.NetworkRule
	desired    gateway.DesiredRule
	unresolved []string
	buildErr   error

	// draining marks a deleting rule kept loaded until its route is
	// withdrawn. Nothing is advertised or written to its status.
	draining bool
}

// publishRuleOutcomes advertises every rule the engine loaded, withdraws this
// node's advertisements for every other rule, and records the result on each
// rule's Programmed condition for this node.
//
// Failures are collected rather than returned on the spot, so one bad rule
// does not stop the others. Advertisement failures come back as advErr, which
// the caller reports on the NetworkGateway and returns, so controller-runtime
// retries with backoff instead of leaving a node that advertised nothing
// claiming to be healthy. Rule status failures come back separately as
// statusErr: they are retried too, but say nothing about whether this node
// serves traffic, so they stay out of the Ready condition.
func (r *NetworkGatewayReconciler) publishRuleOutcomes(
	ctx context.Context, outcomes []ruleOutcome, status gateway.EngineStatus, routerName string,
) (advErr, statusErr error) {
	logger := log.FromContext(ctx)

	// The engine reports one status per desired rule. Only a rule it loaded
	// is advertised: a route for anything else draws traffic this node drops.
	loadErrs := make(map[string]string, len(status.Rules))
	for _, s := range status.Rules {
		if !s.Applied || s.Error != "" {
			loadErrs[s.Key] = s.Error
		}
	}

	var advErrs, statusErrs []error
	for _, o := range outcomes {
		if o.draining {
			continue
		}
		cond := programmedCondition(r.NodeName, o, loadErrs)
		switch {
		case cond.Status != metav1.ConditionTrue:
			if err := withdrawRuleAdvertisements(ctx, r.Client, o.rule, r.NodeName); err != nil {
				logger.Error(err, "withdraw BGPAdvertisements for unloaded NetworkRule", "networkRule", o.rule.Name)
				advErrs = append(advErrs, fmt.Errorf("networkRule %s: %w", o.rule.Name, err))
			}
		case routerName != "":
			if err := r.applyBGPAdvertisements(ctx, o.rule, o.desired, routerName); err != nil {
				logger.Error(err, "apply BGPAdvertisements for NetworkRule", "networkRule", o.rule.Name)
				advErrs = append(advErrs, fmt.Errorf("networkRule %s: %w", o.rule.Name, err))
			}
		}

		if err := r.setRuleProgrammed(ctx, o.rule, cond); err != nil {
			logger.Error(err, "update NetworkRule Programmed condition", "networkRule", o.rule.Name)
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
	if len(o.unresolved) > 0 {
		cond.Reason = reasonBackendsUnresolved
		cond.Message = fmt.Sprintf("loaded on node %s with %d of %d backends; unresolved: %s",
			node, len(o.desired.Backends), len(o.desired.Backends)+len(o.unresolved),
			cappedList(o.unresolved, maxReadyFailures))
	}
	return cond
}

// cappedList joins the first max items with ", ", followed by a count of the
// rest, so a long list stays under the metav1.Condition message limit.
func cappedList(items []string, max int) string {
	if len(items) <= max {
		return strings.Join(items, ", ")
	}
	return fmt.Sprintf("%s and %d more", strings.Join(items[:max], ", "), len(items)-max)
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
		msg := "NetworkRules failed to apply: " + strings.Join(failures, "; ")
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

// programmedConditionType returns the NetworkRule condition type that records
// whether node's engine loaded the rule. NetworkRule status is shared by every
// gateway node in the namespace while loading is per node, so each node owns
// its own condition type and never overwrites another node's result.
func programmedConditionType(node string) string {
	return node + "/" + bgpv1alpha1.ConditionTypeProgrammed
}

// setRuleProgrammed writes cond to rule's status, skipping the write when
// nothing changed. Every write fans out to every gateway node through the
// NetworkRule watch, so an unconditional write would never settle.
//
// Every gateway node and NetworkRuleReconciler write the same status, so a
// write retries on conflict against a fresh read. A rule deleted mid-pass
// has nothing left to record and counts as success.
func (r *NetworkGatewayReconciler) setRuleProgrammed(
	ctx context.Context, rule *bgpv1alpha1.NetworkRule, cond metav1.Condition,
) error {
	key := client.ObjectKeyFromObject(rule)
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		current := &bgpv1alpha1.NetworkRule{}
		if err := r.Get(ctx, key, current); err != nil {
			return err
		}
		c := cond
		c.ObservedGeneration = current.Generation
		if !meta.SetStatusCondition(&current.Status.Conditions, c) {
			return nil
		}
		return r.Status().Update(ctx, current)
	})
	if apierrors.IsNotFound(err) {
		return nil
	}
	return err
}

// clearNodeRuleConditions removes node's Programmed condition from every
// NetworkRule in namespace, for a node that no longer serves any of them. A
// write retries on conflict against a fresh read, and a rule deleted
// mid-pass counts as cleared.
func clearNodeRuleConditions(ctx context.Context, c client.Client, namespace, node string) error {
	list := &bgpv1alpha1.NetworkRuleList{}
	if err := c.List(ctx, list, client.InNamespace(namespace)); err != nil {
		return fmt.Errorf("list NetworkRules to clear node %s conditions: %w", node, err)
	}
	var errs []error
	for i := range list.Items {
		key := client.ObjectKeyFromObject(&list.Items[i])
		err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			current := &bgpv1alpha1.NetworkRule{}
			if err := c.Get(ctx, key, current); err != nil {
				return err
			}
			if !meta.RemoveStatusCondition(&current.Status.Conditions, programmedConditionType(node)) {
				return nil
			}
			return c.Status().Update(ctx, current)
		})
		if err != nil && !apierrors.IsNotFound(err) {
			errs = append(errs, fmt.Errorf("clear node %s condition on NetworkRule %s: %w", node, key.Name, err))
		}
	}
	return errors.Join(errs...)
}

// withdrawRuleAdvertisements deletes the BGPAdvertisements node created for
// rule, one per address family, so the fabric stops sending the rule's VIP
// traffic to a node that has not loaded it.
func withdrawRuleAdvertisements(
	ctx context.Context, c client.Client, rule *bgpv1alpha1.NetworkRule, node string,
) error {
	return pruneRuleAdvertisements(ctx, c, rule, node, nil)
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
	ctx context.Context, c client.Client, rule *bgpv1alpha1.NetworkRule, node string, keep map[string]bool,
) error {
	advList := &bgpv1alpha1.BGPAdvertisementList{}
	if err := c.List(ctx, advList,
		client.InNamespace(rule.Namespace),
		client.MatchingLabels{networkRuleLabel: rule.Name},
	); err != nil {
		return fmt.Errorf("list BGPAdvertisements for NetworkRule %s: %w", rule.Name, err)
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

// buildDesiredRule converts rule into a gateway.DesiredRule. Its backends are
// the IPv6 addresses of the VPCAttachments rule's BackendSelector picks from
// sidIndex's attachments (selectRuleBackends), each resolved through sidIndex to the
// SRv6 uSID of the node its attachment reports, with that backend's own slot
// (backendSID), so a node hosting several of the rule's backends can tell which
// one Maglev chose. There is no kernel VRF or FIB dependency.
//
// A selected attachment that is not a backend yet, or a backend whose uSID
// does not resolve, is left out and returned in unresolved, so the rule keeps
// serving through the rest. A backend pod being recreated is enough to cause
// this, since its BGPAdvertisement is gone until the new pod is attached.
// Every gateway node resolves from the same API objects and the Maglev table
// depends only on the backend set, so nodes that see the same objects build
// the same table. Only when nothing resolves does the rule fail, so it is
// withdrawn rather than advertised with nothing behind it. An invalid VIP or
// selector fails the rule outright, since that is a spec error rather than a
// passing state.
func buildDesiredRule(
	rule *bgpv1alpha1.NetworkRule, sidIndex *backendSIDIndex,
) (dr gateway.DesiredRule, unresolved []string, err error) {
	vips := make([]netip.Addr, 0, len(rule.Spec.VIPAddresses))
	for _, v := range rule.Spec.VIPAddresses {
		addr, err := netip.ParseAddr(v)
		if err != nil {
			return gateway.DesiredRule{}, nil, fmt.Errorf("invalid VIP address %q: %w", v, err)
		}
		vips = append(vips, addr)
	}

	if _, _, err := ruleTranslatedVIP(rule); err != nil {
		return gateway.DesiredRule{}, nil, err
	}

	selected, unresolved, err := selectRuleBackends(rule, sidIndex.attachments)
	if err != nil {
		return gateway.DesiredRule{}, nil, err
	}

	backends := make([]gateway.DesiredBackend, 0, len(selected))
	var firstResolveErr error
	for _, b := range selected {
		usid, err := sidIndex.resolveUSID(b.addr, rule.Spec.VPCRef, b.node)
		if err == nil {
			usid, err = backendSID(usid, b.addr, b.port)
		}
		if err != nil {
			if firstResolveErr == nil {
				firstResolveErr = fmt.Errorf("resolve backend %s: %w", b, err)
			}
			unresolved = append(unresolved, b.String())
			continue
		}
		backends = append(backends, gateway.DesiredBackend{Address: b.addr, Port: b.port, USID: usid})
	}
	if len(backends) == 0 {
		switch {
		case firstResolveErr != nil:
			return gateway.DesiredRule{}, nil, fmt.Errorf("none of %d backends resolves: %w", len(unresolved), firstResolveErr)
		case len(unresolved) > 0:
			return gateway.DesiredRule{}, nil, fmt.Errorf("no selected attachment is a backend yet: %s",
				cappedList(unresolved, maxReadyFailures))
		default:
			return gateway.DesiredRule{}, nil, fmt.Errorf("backendSelector matches no VPCAttachment in VPC %s",
				rule.Spec.VPCRef)
		}
	}

	return gateway.DesiredRule{
		Key:          rule.Namespace + "/" + rule.Name,
		VPCRef:       rule.Spec.VPCRef,
		VIPAddresses: vips,
		Protocol:     string(rule.Spec.Protocol),
		//nolint:gosec // rule.Spec.Port is CRD-validated to [1,65535] (Minimum/Maximum markers on NetworkRuleSpec.Port)
		Port:     uint16(rule.Spec.Port),
		Backends: backends,
	}, unresolved, nil
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
// one per non-empty VIP address family, named by ruleAdvertisementName. Once
// every one is applied, it deletes any other advertisement this node made for
// the rule: one for a family whose VIPs are gone, or one under a name from an
// earlier naming scheme.
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
// Each also carries an owner reference to rule, again backfilled, so
// Kubernetes garbage collection deletes it once the rule is gone. That covers
// an advertisement created from a stale cache after reconcileDelete listed the
// rule's advertisements: teardown never sees it, and without the reference
// nothing would ever withdraw it. The reference is not a controller reference
// and leaves blockOwnerDeletion unset, so it neither blocks the rule's deletion
// nor needs extra RBAC. A rule that is already being deleted gets nothing
// created or updated at all.
func (r *NetworkGatewayReconciler) applyBGPAdvertisements(
	ctx context.Context, rule *bgpv1alpha1.NetworkRule, desired gateway.DesiredRule, routerName string,
) error {
	if !rule.DeletionTimestamp.IsZero() {
		return nil
	}
	v4Prefixes, v6Prefixes := prefixesByFamily(desired.VIPAddresses)

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
		name := ruleAdvertisementName(rule.Name, r.NodeName, g.suffix)
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
		key := types.NamespacedName{Namespace: rule.Namespace, Name: name}
		err := r.Get(ctx, key, adv)
		switch {
		case apierrors.IsNotFound(err):
			adv = &bgpv1alpha1.BGPAdvertisement{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: rule.Namespace,
					Name:      name,
					Labels: map[string]string{
						networkRuleLabel: rule.Name,
						gatewayNodeLabel: gatewayNodeLabelValue(r.NodeName),
					},
				},
				Spec: bgpv1alpha1.BGPAdvertisementSpec{
					RouterRef:     bgpv1alpha1.RouterRef{Name: routerName},
					AddressFamily: bgpv1alpha1.AddressFamily{AFI: bgpv1alpha1.AFIL2VPN, SAFI: bgpv1alpha1.SAFIEVPN},
					Prefixes:      prefixes,
				},
			}
			if refErr := controllerutil.SetOwnerReference(rule, adv, r.Scheme); refErr != nil {
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
		if advCopy.Labels == nil {
			advCopy.Labels = map[string]string{}
		}
		advCopy.Labels[networkRuleLabel] = rule.Name
		advCopy.Labels[gatewayNodeLabel] = gatewayNodeLabelValue(r.NodeName)
		// Backfill the owner reference the same way, so garbage collection
		// covers an advertisement created before it was set.
		if refErr := controllerutil.SetOwnerReference(rule, advCopy, r.Scheme); refErr != nil {
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
	return pruneRuleAdvertisements(ctx, r.Client, rule, r.NodeName, keep)
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
		).
		Named("networkgateway").
		Complete(r)
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
// or a spec edit passes, so the next pass restores what was lost.
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
				return false
			}
			return locatesBackend(e.ObjectOld) || locatesBackend(e.ObjectNew) ||
				isRuleAdvertisement(e.ObjectOld) || isRuleAdvertisement(e.ObjectNew)
		},
		GenericFunc: func(e event.GenericEvent) bool { return locatesBackend(e.Object) },
	}
}

// locatesBackend reports whether obj is a BGPAdvertisement buildBackendSIDIndex
// would consider: one carrying both a VRFID and a Function.
func locatesBackend(obj client.Object) bool {
	adv, ok := obj.(*bgpv1alpha1.BGPAdvertisement)
	return ok && adv.Spec.VRFID != nil && adv.Spec.Function != nil
}

// isRuleAdvertisement reports whether obj is a gateway VIP advertisement made
// for a NetworkRule.
func isRuleAdvertisement(obj client.Object) bool {
	_, ok := obj.GetLabels()[networkRuleLabel]
	return ok
}

// ruleToGatewayRequests maps a NetworkRule change to every NetworkGateway in
// its namespace. A NetworkRule carries no gatewayRef, and every gateway node
// advertises every VIP identically (anycast), so every gateway node in the
// rule's PoP must re-evaluate its own engine state whenever any rule changes.
// The broadcast is intentional rather than a missing index.
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
	sum := sha256.Sum256([]byte(rule + "/" + node))
	suffix := "-" + hex.EncodeToString(sum[:])[:ruleAdvertisementHashLen] + "-" + family
	prefix := rule + "-" + node
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
	rule, ok := adv.Labels[networkRuleLabel]
	if !ok {
		return false
	}
	for _, family := range []string{"v4", "v6"} {
		if adv.Name == ruleAdvertisementName(rule, nodeName, family) ||
			adv.Name == legacyRuleAdvertisementName(rule, nodeName, family) {
			return true
		}
	}
	return false
}

// sweepOrphanedAdvertisements deletes this node's BGPAdvertisements for rules
// that no longer exist. rules is every NetworkRule in namespace as this pass
// listed them.
//
// This node can create an advertisement from a cache that has not yet seen its
// rule's deletion timestamp, after NetworkRuleReconciler's teardown has already
// removed the finalizer. Teardown never sees that advertisement. Without this
// sweep it would stay advertised, with no node serving the rule, until
// Kubernetes garbage collection follows its owner reference. Here it is
// withdrawn on the pass where this node's cache drops the rule, the same pass
// that unloads the rule from the datapath.
//
// A rule missing from rules is looked up through APIReader first and kept if it
// still exists, so a cache that has not yet seen a new rule never withdraws a
// live route.
func (r *NetworkGatewayReconciler) sweepOrphanedAdvertisements(
	ctx context.Context, namespace string, rules []bgpv1alpha1.NetworkRule,
) error {
	known := make(map[string]bool, len(rules))
	for i := range rules {
		known[rules[i].Name] = true
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
		ruleName := adv.Labels[networkRuleLabel]
		if known[ruleName] {
			continue
		}
		err := r.APIReader.Get(ctx, types.NamespacedName{Namespace: namespace, Name: ruleName},
			&bgpv1alpha1.NetworkRule{})
		switch {
		case err == nil:
			continue
		case !apierrors.IsNotFound(err):
			errs = append(errs, fmt.Errorf("check NetworkRule %s for BGPAdvertisement %s: %w", ruleName, adv.Name, err))
			continue
		}
		if err := r.Delete(ctx, adv); err != nil && !apierrors.IsNotFound(err) {
			errs = append(errs, fmt.Errorf("withdraw BGPAdvertisement %s for deleted NetworkRule %s: %w",
				adv.Name, ruleName, err))
		}
	}
	return errors.Join(errs...)
}

// withdrawNodeAdvertisements deletes every BGPAdvertisement that gateway node
// nodeName created in namespace: each per-rule, per-address-family route it
// advertised. It lists by gatewayNodeLabel and deletes those that
// isNodeAdvertisement accepts, so it needs no NetworkRule object, live or
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
