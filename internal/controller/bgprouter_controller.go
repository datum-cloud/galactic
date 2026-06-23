// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"context"
	"fmt"

	bgpv1alpha1 "go.miloapis.com/cosmos/api/bgp/v1alpha1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"go.datum.net/galactic/internal/model"
	"go.datum.net/galactic/internal/reconcile"
	galacticruntime "go.datum.net/galactic/internal/runtime"
)

// annotationConfigHash is the annotation key used to persist the last-applied
// config hash across pod restarts, enabling no-op detection on reconcile.
const annotationConfigHash = "galactic.datum.net/config-hash"

// BGPRouterReconciler reconciles BGPRouter resources.
type BGPRouterReconciler struct {
	client.Client
	Scheme         *runtime.Scheme
	Reconciler     *reconcile.Reconciler
	RuntimeManager galacticruntime.RuntimeManager
	Hasher         func(model.DesiredRouter) (string, error)
	NodeName       string
	RouterRole     string
}

// Reconcile reconciles a single BGPRouter.
func (r *BGPRouterReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	router := &bgpv1alpha1.BGPRouter{}
	if err := r.Get(ctx, req.NamespacedName, router); err != nil {
		if errors.IsNotFound(err) {
			// Router deleted: stop its runtime.
			if stopErr := r.RuntimeManager.Stop(ctx, req.NamespacedName); stopErr != nil {
				logger.Error(stopErr, "stop runtime for deleted router", "router", req.NamespacedName)
			}
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("get BGPRouter %s: %w", req.NamespacedName, err)
	}

	// Handle deletion.
	if !router.DeletionTimestamp.IsZero() {
		if stopErr := r.RuntimeManager.Stop(ctx, req.NamespacedName); stopErr != nil {
			logger.Error(stopErr, "stop runtime for terminating router", "router", req.NamespacedName)
		}
		routerCopy := router.DeepCopy()
		setRouterPhase(routerCopy, bgpv1alpha1.BGPRouterPhaseFailed)
		setRouterCondition(routerCopy, metav1.Condition{
			Type:    ConditionReady,
			Status:  metav1.ConditionFalse,
			Reason:  "Terminating",
			Message: "BGPRouter is being deleted",
		})
		if updateErr := r.Status().Update(ctx, routerCopy); updateErr != nil {
			logger.Error(updateErr, "update status for terminating router")
		}
		return ctrl.Result{}, nil
	}

	// Build desired state.
	desired, err := r.Reconciler.BuildDesiredRouter(ctx, router)
	if err != nil {
		routerCopy := router.DeepCopy()
		setRouterPhase(routerCopy, bgpv1alpha1.BGPRouterPhaseFailed)
		setRouterCondition(routerCopy, metav1.Condition{
			Type:    ConditionReady,
			Status:  metav1.ConditionFalse,
			Reason:  "ReconcileError",
			Message: err.Error(),
		})
		if updateErr := r.Status().Update(ctx, routerCopy); updateErr != nil {
			logger.Error(updateErr, "update status after reconcile error")
		}
		return ctrl.Result{}, err
	}
	if desired == nil {
		// Not for this node/role — skip silently.
		return ctrl.Result{}, nil
	}

	// Hash the desired state to skip no-op reconciles.
	newHash, hashErr := r.Hasher(*desired)
	if hashErr != nil {
		return ctrl.Result{}, fmt.Errorf("hash desired router: %w", hashErr)
	}

	if router.Annotations[annotationConfigHash] == newHash {
		// State unchanged: update ObservedGeneration only.
		routerCopy := router.DeepCopy()
		routerCopy.Status.ObservedGeneration = router.Generation
		if updateErr := r.Status().Update(ctx, routerCopy); updateErr != nil {
			logger.Error(updateErr, "update observedGeneration (no-op reconcile)")
		}
		return ctrl.Result{}, nil
	}

	// Apply to runtime.
	if applyErr := r.RuntimeManager.Apply(ctx, req.NamespacedName, *desired); applyErr != nil {
		routerCopy := router.DeepCopy()
		setRouterPhase(routerCopy, bgpv1alpha1.BGPRouterPhaseFailed)
		setRouterCondition(routerCopy, metav1.Condition{
			Type:    ConditionConfigApplied,
			Status:  metav1.ConditionFalse,
			Reason:  "ApplyFailed",
			Message: applyErr.Error(),
		})
		if updateErr := r.Status().Update(ctx, routerCopy); updateErr != nil {
			logger.Error(updateErr, "update status after apply error")
		}
		return ctrl.Result{}, applyErr
	}

	// Get runtime status.
	runtimeStatus, statusErr := r.RuntimeManager.Status(ctx, req.NamespacedName)
	if statusErr != nil {
		logger.Error(statusErr, "get runtime status")
	}

	// Update BGPRouter status.
	routerCopy := router.DeepCopy()
	r.updateRouterStatus(routerCopy, runtimeStatus)
	if updateErr := r.Status().Update(ctx, routerCopy); updateErr != nil {
		logger.Error(updateErr, "update BGPRouter status")
	}

	// Persist the config hash as an annotation so no-op detection survives pod restarts.
	patchBase := router.DeepCopy()
	if patchBase.Annotations == nil {
		patchBase.Annotations = make(map[string]string)
	}
	patchBase.Annotations[annotationConfigHash] = newHash
	if patchErr := r.Patch(ctx, patchBase, client.MergeFrom(router)); patchErr != nil {
		logger.Error(patchErr, "patch config-hash annotation")
	}

	// Update per-peer BGPPeer statuses.
	r.updatePeerStatuses(ctx, router, runtimeStatus)

	// Update per-advertisement BGPAdvertisement statuses.
	r.updateAdvertisementStatuses(ctx, router, runtimeStatus)

	// Update per-policy BGPPolicy statuses.
	r.updatePolicyStatuses(ctx, router)

	return ctrl.Result{}, nil
}

// updateRouterStatus updates the BGPRouter status from runtime status.
func (r *BGPRouterReconciler) updateRouterStatus(router *bgpv1alpha1.BGPRouter, rs model.RuntimeStatus) {
	if rs.Healthy {
		setRouterPhase(router, bgpv1alpha1.BGPRouterPhaseReady)
		setRouterCondition(router, metav1.Condition{
			Type:    ConditionReady,
			Status:  metav1.ConditionTrue,
			Reason:  "RuntimeReady",
			Message: "BGP runtime is healthy",
		})
		setRouterCondition(router, metav1.Condition{
			Type:    ConditionConfigApplied,
			Status:  metav1.ConditionTrue,
			Reason:  "Applied",
			Message: "Configuration applied successfully",
		})
	} else {
		setRouterPhase(router, bgpv1alpha1.BGPRouterPhasePending)
		setRouterCondition(router, metav1.Condition{
			Type:    ConditionReady,
			Status:  metav1.ConditionFalse,
			Reason:  "RuntimeNotReady",
			Message: "BGP runtime is not healthy",
		})
	}

	established := int32(0)
	for _, ps := range rs.Peers {
		if ps.SessionState == model.BGPPeerStateEstablished {
			established++
		}
	}
	router.Status.Peers = bgpv1alpha1.BGPRouterPeerSummary{
		Total:       int32(len(rs.Peers)),
		Established: established,
	}
}

// updatePeerStatuses updates BGPPeer status only for peers that target this router.
// It uses the routerRef name index for direct references and evaluates routerSelector
// for selector-based bindings.
func (r *BGPRouterReconciler) updatePeerStatuses(ctx context.Context, router *bgpv1alpha1.BGPRouter, rs model.RuntimeStatus) {
	logger := log.FromContext(ctx)

	// Build a lookup map by peer address.
	stateByAddr := make(map[string]model.PeerStatus, len(rs.Peers))
	for _, ps := range rs.Peers {
		stateByAddr[ps.Address] = ps
	}

	// Find peers that target this router, either via direct reference or selector.
	var targetPeers []*bgpv1alpha1.BGPPeer

	// Peers with direct routerRef.name match.
	peerByRef := &bgpv1alpha1.BGPPeerList{}
	if err := r.List(ctx, peerByRef,
		client.InNamespace(router.Namespace),
		client.MatchingFields{BGPPeerByRouterName: router.Name},
	); err != nil {
		logger.Error(err, "list BGPPeers by routerRef for status update")
	} else {
		for i := range peerByRef.Items {
			targetPeers = append(targetPeers, &peerByRef.Items[i])
		}
	}

	// Peers with routerSelector: list all peers and evaluate the selector.
	peerList := &bgpv1alpha1.BGPPeerList{}
	if err := r.List(ctx, peerList, client.InNamespace(router.Namespace)); err != nil {
		logger.Error(err, "list BGPPeers for selector status update")
	} else {
		for i := range peerList.Items {
			peer := &peerList.Items[i]
			// Skip peers already matched by routerRef.
			if peer.Spec.RouterRef != nil && peer.Spec.RouterRef.Name == router.Name {
				continue
			}
			if peer.Spec.RouterSelector != nil {
				sel, err := metav1.LabelSelectorAsSelector(&metav1.LabelSelector{
					MatchLabels:      peer.Spec.RouterSelector.MatchLabels,
					MatchExpressions: peer.Spec.RouterSelector.MatchExpressions,
				})
				if err != nil {
					continue
				}
				if sel.Matches(labels.Set(router.Labels)) {
					targetPeers = append(targetPeers, peer)
				}
			}
		}
	}

	for _, peer := range targetPeers {
		ps, ok := stateByAddr[peer.Spec.Address]
		if !ok {
			continue
		}
		peerCopy := peer.DeepCopy()
		setPeerReadyCondition(peerCopy, ps.SessionState, "Idle")
		if ps.LastEstablishedTime != nil {
			peerCopy.Status.LastEstablishedTime = ps.LastEstablishedTime
		}
		if updateErr := r.Status().Update(ctx, peerCopy); updateErr != nil {
			logger.Error(updateErr, "update BGPPeer status", "peer", peer.Name)
		}
	}
}

// updateAdvertisementStatuses updates BGPAdvertisement status.
func (r *BGPRouterReconciler) updateAdvertisementStatuses(ctx context.Context, router *bgpv1alpha1.BGPRouter, rs model.RuntimeStatus) {
	logger := log.FromContext(ctx)

	advByName := make(map[string]model.AdvertisementStatus, len(rs.Advertisements))
	for _, as := range rs.Advertisements {
		advByName[as.Name] = as
	}

	advList := &bgpv1alpha1.BGPAdvertisementList{}
	if err := r.List(ctx, advList,
		client.InNamespace(router.Namespace),
		client.MatchingFields{".spec.routerRef.name": router.Name},
	); err != nil {
		logger.Error(err, "list BGPAdvertisements for status update")
		return
	}
	for i := range advList.Items {
		adv := &advList.Items[i]
		advCopy := adv.DeepCopy()
		advCopy.Status.ObservedGeneration = adv.Generation
		if as, ok := advByName[adv.Name]; ok {
			advCopy.Status.AdvertisedPrefixes = as.AdvertisedPrefixes
			setAdvertisementCondition(advCopy, metav1.Condition{
				Type:    ConditionAdvertised,
				Status:  metav1.ConditionTrue,
				Reason:  "Advertised",
				Message: "Prefixes are being advertised",
			})
		}
		setAdvertisementCondition(advCopy, metav1.Condition{
			Type:    ConditionReady,
			Status:  metav1.ConditionTrue,
			Reason:  "Accepted",
			Message: "Advertisement accepted",
		})
		if updateErr := r.Status().Update(ctx, advCopy); updateErr != nil {
			logger.Error(updateErr, "update BGPAdvertisement status", "advertisement", adv.Name)
		}
	}
}

// updatePolicyStatuses updates BGPPolicy status.
func (r *BGPRouterReconciler) updatePolicyStatuses(ctx context.Context, router *bgpv1alpha1.BGPRouter) {
	logger := log.FromContext(ctx)

	policyList := &bgpv1alpha1.BGPPolicyList{}
	if err := r.List(ctx, policyList,
		client.InNamespace(router.Namespace),
		client.MatchingFields{".spec.routerRef.name": router.Name},
	); err != nil {
		logger.Error(err, "list BGPRoutePolicies for status update")
		return
	}
	for i := range policyList.Items {
		policy := &policyList.Items[i]
		policyCopy := policy.DeepCopy()
		policyCopy.Status.ObservedGeneration = policy.Generation
		setPolicyCondition(policyCopy, metav1.Condition{
			Type:    ConditionPolicyApplied,
			Status:  metav1.ConditionTrue,
			Reason:  "Applied",
			Message: "Policy applied successfully",
		})
		setPolicyCondition(policyCopy, metav1.Condition{
			Type:    ConditionReady,
			Status:  metav1.ConditionTrue,
			Reason:  "Ready",
			Message: "Policy is ready",
		})
		if updateErr := r.Status().Update(ctx, policyCopy); updateErr != nil {
			logger.Error(updateErr, "update BGPPolicy status", "policy", policy.Name)
		}
	}
}

// SetupWithManager registers the BGPRouterReconciler with the manager.
func (r *BGPRouterReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&bgpv1alpha1.BGPRouter{}).
		Named("bgprouter").
		Complete(r)
}
