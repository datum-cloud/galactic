// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"context"
	"fmt"
	"net/netip"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	ctrlreconcile "sigs.k8s.io/controller-runtime/pkg/reconcile"

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
// NetworkGatewayReconciler's node-scoped root-object pattern -- simpler in
// one respect (no rule/backend desired-state assembly) but, as of the
// shard-SID advertisement added below, no longer BGP-free: this
// reconciler's job is to publish Status.ShardAddress/Status.ShardSID,
// echoing back the operator-configured values this node's own
// cmd/galactic-nat66 process was started with (ShardAddress/ShardSID
// below -- plain strings, not re-derived from anything), set a Ready
// condition once the datapath is confirmed attached, and -- exactly as
// NAT66ShardStatus.ShardSID's own doc comment in datum-cloud/network
// already promises -- create/withdraw the /128 BGPAdvertisement that
// makes ShardSID actually reachable fabric-wide, the same RT-less,
// VRFID/Function-less "plain node reachability" shape
// NetworkGatewayReconciler.applyBGPAdvertisements uses for its own VIP
// advertisements. Without this, internal/plumbing/srv6.EgressDefaultRouteAdd
// (internal/cnibgp) would install a default route toward a SID no node
// ever learns a kernel route to.
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
			// No finalizer on NAT66Shard (same deliberate choice
			// NetworkGateway makes -- see that reconciler's own NotFound
			// branch), so by the time this Get observes NotFound the object
			// is already gone everywhere, on whichever node's process
			// happens to handle the delete event -- not necessarily the
			// shard's own node. Withdraw this shard's BGPAdvertisement keyed
			// on req.Name (shardAdvertisementName is deterministic, derived
			// from the name alone) rather than the now-unreadable deleted
			// object, mirroring withdrawNodeAdvertisements's identical
			// req.Name-keyed shape.
			if err := withdrawShardAdvertisement(ctx, r.Client, req.Namespace, req.Name); err != nil {
				logger.Error(err, "withdraw BGPAdvertisement for deleted NAT66Shard", "nat66Shard", req.NamespacedName)
				return ctrl.Result{}, err
			}
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
		// Not known to be reachable today -- no finalizer, so the NotFound
		// branch above is the one that actually runs on a real delete (see
		// its own comment) -- kept correct in case that changes later,
		// mirroring NetworkGatewayReconciler's identical stance on its own
		// equivalent branch.
		if err := withdrawShardAdvertisement(ctx, r.Client, shard.Namespace, shard.Name); err != nil {
			logger.Error(err, "withdraw BGPAdvertisement for terminating NAT66Shard", "nat66Shard", req.NamespacedName)
			return ctrl.Result{}, err
		}
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

	if err := r.applyShardAdvertisement(ctx, shardCopy); err != nil {
		logger.Error(err, "apply BGPAdvertisement for NAT66Shard", "nat66Shard", req.NamespacedName)
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// shardAdvertisementName derives the deterministic BGPAdvertisement name
// for a given NAT66Shard, so withdrawal (keyed on a deletion event's
// req.Name alone, per the NotFound branch above) never needs to read the
// shard object it's naming.
func shardAdvertisementName(shardName string) string {
	return shardName + "-sid"
}

// applyShardAdvertisement reconciles this shard's own /128 BGPAdvertisement
// for Status.ShardSID -- RT-less, VRFID/Function-less, the same "plain
// node reachability" shape NetworkGatewayReconciler.applyBGPAdvertisements
// uses for its own VIP advertisements, and exactly what
// NAT66ShardStatus.ShardSID's own doc comment in datum-cloud/network
// already promises. A no-op, not an error, when ShardSID is unset (an
// operator who hasn't configured this node's shard identity yet has
// nothing to advertise) or when no BGPRouter targets this node yet (the
// BGPRouter watch added in SetupWithManager retries once one appears,
// closing the same startup-race class NetworkGatewayReconciler hit before
// commit 782c231).
func (r *NAT66ShardReconciler) applyShardAdvertisement(ctx context.Context, shard *bgpv1alpha1.NAT66Shard) error {
	if shard.Status.ShardSID == "" {
		return nil
	}
	sidAddr, err := netip.ParseAddr(shard.Status.ShardSID)
	if err != nil {
		return fmt.Errorf("parse ShardSID %q: %w", shard.Status.ShardSID, err)
	}

	routerName, err := routerNameForNode(ctx, r.Client, shard.Namespace, r.NodeName)
	if err != nil {
		return fmt.Errorf("look up BGPRouter for node %s: %w", r.NodeName, err)
	}
	if routerName == "" {
		return nil
	}

	prefix := netip.PrefixFrom(sidAddr, sidAddr.BitLen()).String()
	name := shardAdvertisementName(shard.Name)
	key := types.NamespacedName{Namespace: shard.Namespace, Name: name}

	adv := &bgpv1alpha1.BGPAdvertisement{}
	err = r.Get(ctx, key, adv)
	switch {
	case apierrors.IsNotFound(err):
		adv = &bgpv1alpha1.BGPAdvertisement{
			ObjectMeta: metav1.ObjectMeta{Namespace: shard.Namespace, Name: name},
			Spec: bgpv1alpha1.BGPAdvertisementSpec{
				RouterRef:     bgpv1alpha1.RouterRef{Name: routerName},
				AddressFamily: bgpv1alpha1.AddressFamily{AFI: bgpv1alpha1.AFIL2VPN, SAFI: bgpv1alpha1.SAFIEVPN},
				Prefixes:      []bgpv1alpha1.Prefix{bgpv1alpha1.Prefix(prefix)},
			},
		}
		if err := r.Create(ctx, adv); err != nil {
			return fmt.Errorf("create BGPAdvertisement %s: %w", name, err)
		}
		return nil
	case err != nil:
		return fmt.Errorf("get BGPAdvertisement %s: %w", name, err)
	}

	advCopy := adv.DeepCopy()
	advCopy.Spec.RouterRef = bgpv1alpha1.RouterRef{Name: routerName}
	advCopy.Spec.AddressFamily = bgpv1alpha1.AddressFamily{AFI: bgpv1alpha1.AFIL2VPN, SAFI: bgpv1alpha1.SAFIEVPN}
	advCopy.Spec.Prefixes = []bgpv1alpha1.Prefix{bgpv1alpha1.Prefix(prefix)}
	if err := r.Update(ctx, advCopy); err != nil {
		return fmt.Errorf("update BGPAdvertisement %s: %w", name, err)
	}
	return nil
}

// withdrawShardAdvertisement deletes the BGPAdvertisement
// applyShardAdvertisement creates for shardName, if any. Not an error if
// it never existed (ShardSID was never set) or is already gone.
func withdrawShardAdvertisement(ctx context.Context, c client.Client, namespace, shardName string) error {
	adv := &bgpv1alpha1.BGPAdvertisement{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: shardAdvertisementName(shardName)},
	}
	if err := c.Delete(ctx, adv); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("delete BGPAdvertisement %s: %w", adv.Name, err)
	}
	return nil
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
//
// The BGPRouter watch below closes the same startup-race class
// NetworkGatewayReconciler hit before commit 782c231: without it, a
// NAT66Shard whose node's BGPRouter doesn't exist yet at first reconcile
// would fail applyShardAdvertisement's routerNameForNode lookup once and
// never get a second chance until some unrelated event happened to
// trigger a fresh reconcile.
func (r *NAT66ShardReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&bgpv1alpha1.NAT66Shard{}).
		Watches(&bgpv1alpha1.BGPRouter{}, handler.EnqueueRequestsFromMapFunc(
			func(ctx context.Context, obj client.Object) []ctrlreconcile.Request {
				return broadcastToShardRequests(ctx, r.Client, obj.GetNamespace())
			}),
		).
		Named("nat66shard").
		Complete(r)
}

// broadcastToShardRequests enqueues every NAT66Shard in namespace --
// mirrors broadcastToGatewayRequests (networkgateway_controller.go) for
// the same reason: a BGPRouter change might be the one this node's own
// NAT66Shard was waiting on, and there is normally at most one NAT66Shard
// per node anyway, so listing the whole namespace is cheap.
func broadcastToShardRequests(ctx context.Context, c client.Client, namespace string) []ctrlreconcile.Request {
	logger := log.FromContext(ctx)
	shardList := &bgpv1alpha1.NAT66ShardList{}
	if err := c.List(ctx, shardList, client.InNamespace(namespace)); err != nil {
		logger.Error(err, "list NAT66Shards for BGPRouter change", "namespace", namespace)
		return nil
	}
	reqs := make([]ctrlreconcile.Request, 0, len(shardList.Items))
	for _, s := range shardList.Items {
		reqs = append(reqs, ctrlreconcile.Request{
			NamespacedName: types.NamespacedName{Namespace: s.Namespace, Name: s.Name},
		})
	}
	return reqs
}
