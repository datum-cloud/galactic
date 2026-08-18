// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"context"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	bgpv1alpha1 "go.datum.net/network/api/v1alpha1"
)

// NAT66DatapathHealth reports whether this node's NAT66 egress XDP
// datapath (internal/plumbing/ebpf/nat66prog, loaded and attached by
// cmd/galactic-nat66's setupNat66Datapath) is currently attached and
// serving traffic -- the interface NAT66ShardReconciler uses to decide
// whether to set its Ready condition True, mirroring GatewayEngine's
// interface-seam pattern in networkgateway_controller.go for
// test-fakeability.
type NAT66DatapathHealth interface {
	// Attached reports whether the datapath is loaded and attached.
	Attached() bool
}

const (
	// reasonNAT66DatapathAttached is the Ready condition reason once the
	// datapath is confirmed attached.
	reasonNAT66DatapathAttached = "DatapathAttached"

	// reasonNAT66DatapathNotAttached is the Ready condition reason while
	// the datapath is not yet (or no longer) attached.
	reasonNAT66DatapathNotAttached = "DatapathNotAttached"
)

// NAT66ShardReconciler reconciles the single NAT66Shard object for this
// node (spec.targetRef.name == NodeName), mirroring
// NetworkGatewayReconciler's node-scoped root-object pattern -- but much
// simpler: there is no rule/backend desired-state assembly here at all.
// This reconciler's only job is to publish Status.ShardAddress/
// Status.ShardSID, echoing back the operator-configured values this
// node's own cmd/galactic-nat66 process was started with (ShardAddress/
// ShardSID below -- plain strings, not re-derived from anything), and set
// a Ready condition once the datapath is confirmed attached.
type NAT66ShardReconciler struct {
	client.Client
	Scheme *runtime.Scheme

	NodeName string

	// ShardAddress/ShardSID are this node's own operator-configured NAT66
	// shard identity (config.NAT66Config.ShardPubAddr/ShardSID,
	// already the values the running datapath was configured with -- see
	// cmd/galactic-nat66's setupNat66Datapath). This reconciler publishes
	// them, it does not compute them -- same division of responsibility
	// as NetworkGatewayReconciler.SRv6Address/publishSelfAddress.
	ShardAddress string
	ShardSID     string

	// Datapath reports whether this node's NAT66 datapath is currently
	// attached -- see NAT66DatapathHealth's doc comment.
	Datapath NAT66DatapathHealth
}

// Reconcile reconciles a single NAT66Shard.
func (r *NAT66ShardReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	shard := &bgpv1alpha1.NAT66Shard{}
	if err := r.Get(ctx, req.NamespacedName, shard); err != nil {
		if apierrors.IsNotFound(err) {
			// No finalizer, no cross-node cleanup to perform: unlike
			// NetworkGateway (whose deletion must withdraw BGPAdvertisements
			// other nodes may still be depending on), a NAT66Shard carries no
			// other object this reconciler is responsible for tearing down.
			// There is simply nothing left to reconcile once the object is
			// gone.
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("get NAT66Shard %s: %w", req.NamespacedName, err)
	}

	// Node check: skip shards that don't target this node, mirroring
	// NetworkGatewayReconciler's identical targetRef.Name check.
	if shard.Spec.TargetRef.Name != r.NodeName {
		return ctrl.Result{}, nil
	}

	if !shard.DeletionTimestamp.IsZero() {
		// Nothing to tear down beyond the object itself -- see the NotFound
		// branch above for why this reconciler owns no other resource's
		// lifecycle.
		return ctrl.Result{}, nil
	}

	shardCopy := shard.DeepCopy()
	shardCopy.Status.ObservedGeneration = shard.Generation
	if r.ShardAddress != "" {
		shardCopy.Status.ShardAddress = r.ShardAddress
	}
	if r.ShardSID != "" {
		shardCopy.Status.ShardSID = r.ShardSID
	}
	setNAT66ShardCondition(shardCopy, r.readyCondition())

	if err := r.Status().Update(ctx, shardCopy); err != nil {
		logger.Error(err, "update NAT66Shard status", "nat66Shard", req.NamespacedName)
		return ctrl.Result{}, fmt.Errorf("update NAT66Shard %s status: %w", req.NamespacedName, err)
	}

	return ctrl.Result{}, nil
}

// readyCondition computes the Ready condition from the datapath's current
// attachment state. A nil Datapath (not expected in production --
// cmd/galactic-nat66 always wires a real one -- but guarded against for
// test/defensive-programming reasons the same way GatewayEngine's own
// callers never pass nil) is treated as not attached, not as a panic.
func (r *NAT66ShardReconciler) readyCondition() metav1.Condition {
	if r.Datapath != nil && r.Datapath.Attached() {
		return metav1.Condition{
			Type:    bgpv1alpha1.ConditionTypeReady,
			Status:  metav1.ConditionTrue,
			Reason:  reasonNAT66DatapathAttached,
			Message: "NAT66 egress datapath is attached and serving traffic",
		}
	}
	return metav1.Condition{
		Type:    bgpv1alpha1.ConditionTypeReady,
		Status:  metav1.ConditionFalse,
		Reason:  reasonNAT66DatapathNotAttached,
		Message: "NAT66 egress datapath is not yet attached",
	}
}

// SetupWithManager registers the NAT66ShardReconciler with the manager.
func (r *NAT66ShardReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&bgpv1alpha1.NAT66Shard{}).
		Named("nat66shard").
		Complete(r)
}
