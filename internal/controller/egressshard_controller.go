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

// EgressDatapathHealth reports whether this node's egress translation XDP datapath is
// attached and serving traffic. EgressShardReconciler uses it to decide whether
// to set its Ready condition, and it is an interface so tests can fake it.
type EgressDatapathHealth interface {
	// Attached reports whether the datapath is loaded and attached.
	Attached() bool
}

const (
	// reasonEgressDatapathAttached is the Ready condition reason once the
	// datapath is confirmed attached.
	reasonEgressDatapathAttached = "DatapathAttached"

	// reasonEgressDatapathNotAttached is the Ready condition reason while
	// the datapath is not yet (or no longer) attached.
	reasonEgressDatapathNotAttached = "DatapathNotAttached"
)

// EgressShardReconciler reconciles the single EgressShard object whose
// spec.targetRef.name is this node. It publishes the shard address and SID this
// node's datapath process was started with, echoing the operator-configured
// values rather than deriving them, sets Ready once the datapath is confirmed
// attached, and maintains one BGPAdvertisement carrying a /128 for each.
//
// That advertisement is what makes both addresses reachable across the fabric,
// in the same route-target-less, VRFID-less shape the gateway's VIP
// advertisements use. Without the SID's route, a tenant VRF default egress
// route points at a SID no node ever learns a kernel route to, so no forward
// traffic reaches this shard. Without the address's route, forward traffic
// arrives and is correctly translated, but the reply has no route back from
// anywhere else on the fabric, so a TCP connection never completes even while
// every forward-path counter looks healthy.
type EgressShardReconciler struct {
	client.Client
	Scheme *runtime.Scheme

	NodeName string

	// ShardSID and the ShardAddress fields are this node's operator-configured
	// shard identity, the same values the running datapath was configured with.
	// This reconciler publishes them; it does not compute them.
	//
	// ShardAddressIPv4 and NAT64Prefix are set together or not at all, and only
	// on a shard performing NAT64.
	ShardSID         string
	ShardAddressIPv6 string
	ShardAddressIPv4 string
	NAT64Prefix      string

	// Datapath reports whether this node's egress translation datapath is
	// currently attached -- see EgressDatapathHealth's doc comment.
	Datapath EgressDatapathHealth
}

// Reconcile reconciles a single EgressShard.
func (r *EgressShardReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	shard := &bgpv1alpha1.EgressShard{}
	if err := r.Get(ctx, req.NamespacedName, shard); err != nil {
		if apierrors.IsNotFound(err) {
			// EgressShard carries no finalizer, so by the time this Get sees
			// NotFound the object is gone everywhere, on whichever node's
			// process handled the event and not necessarily the shard's own.
			// Withdraw keyed on req.Name, which the advertisement name is
			// derived from, rather than on the unreadable deleted object.
			if err := withdrawShardAdvertisement(ctx, r.Client, req.Namespace, req.Name); err != nil {
				logger.Error(err, "withdraw BGPAdvertisement for deleted EgressShard", "egressShard", req.NamespacedName)
				return ctrl.Result{}, err
			}
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("get EgressShard %s: %w", req.NamespacedName, err)
	}

	// Node check: skip shards that don't target this node, mirroring
	// NetworkGatewayReconciler's identical targetRef.Name check.
	if shard.Spec.TargetRef.Name != r.NodeName {
		return ctrl.Result{}, nil
	}

	if !shard.DeletionTimestamp.IsZero() {
		// Not known to be reachable while there is no finalizer, the NotFound
		// branch above being the one a real delete takes, but kept correct in
		// case that changes.
		if err := withdrawShardAdvertisement(ctx, r.Client, shard.Namespace, shard.Name); err != nil {
			logger.Error(err, "withdraw BGPAdvertisement for terminating EgressShard", "egressShard", req.NamespacedName)
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	shardCopy := shard.DeepCopy()
	shardCopy.Status.ObservedGeneration = shard.Generation
	if r.ShardSID != "" {
		shardCopy.Status.ShardSID = r.ShardSID
	}
	if r.ShardAddressIPv6 != "" {
		shardCopy.Status.ShardAddressIPv6 = r.ShardAddressIPv6
	}
	if r.ShardAddressIPv4 != "" {
		shardCopy.Status.ShardAddressIPv4 = r.ShardAddressIPv4
	}
	if r.NAT64Prefix != "" {
		shardCopy.Status.NAT64Prefix = r.NAT64Prefix
	}
	setEgressShardCondition(shardCopy, r.readyCondition())

	if err := r.Status().Update(ctx, shardCopy); err != nil {
		logger.Error(err, "update EgressShard status", "egressShard", req.NamespacedName)
		return ctrl.Result{}, fmt.Errorf("update EgressShard %s status: %w", req.NamespacedName, err)
	}

	if err := r.applyShardAdvertisement(ctx, shardCopy); err != nil {
		logger.Error(err, "apply BGPAdvertisement for EgressShard", "egressShard", req.NamespacedName)
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// shardAdvertisementName derives the deterministic BGPAdvertisement name for a
// EgressShard, so withdrawal keyed on a deletion event's name alone never needs
// to read the object it is naming. The "-sid" suffix predates the advertisement
// also carrying the shard address, and is kept rather than churning every
// existing shard's name for a cosmetic rename.
func shardAdvertisementName(shardName string) string {
	return shardName + "-sid"
}

// shardAdvertisementPrefixes builds the /128 prefixes advertised for shard: the
// shard SID, which is the forward leg a tenant VRF's egress routes encapsulate
// toward, and the IPv6 shard address, which is the return leg a reply's
// destination is rewritten to and which needs a route back from wherever that
// reply's next hop is, not just from this node.
//
// Status.ShardAddressIPv4 is deliberately absent. A NAT64 reply arrives from the
// IPv4 internet rather than across this fabric, so advertising that address into
// the EVPN mesh would not make it reachable by the party that needs to reach it;
// the underlay or an upstream announcement has to attract it to this node. See
// EgressShard's own field documentation.
//
// Either prefix may be independently unset, by an operator who has not finished
// configuring this node's identity, in which case it is omitted rather than
// failing the whole advertisement. Callers treat an empty result as nothing to
// advertise yet, not an error.
func shardAdvertisementPrefixes(shard *bgpv1alpha1.EgressShard) ([]bgpv1alpha1.Prefix, error) {
	var prefixes []bgpv1alpha1.Prefix
	for _, raw := range []string{shard.Status.ShardSID, shard.Status.ShardAddressIPv6} {
		if raw == "" {
			continue
		}
		addr, err := netip.ParseAddr(raw)
		if err != nil {
			return nil, fmt.Errorf("parse %q: %w", raw, err)
		}
		prefixes = append(prefixes, bgpv1alpha1.Prefix(netip.PrefixFrom(addr, addr.BitLen()).String()))
	}
	return prefixes, nil
}

// applyShardAdvertisement reconciles this shard's single BGPAdvertisement
// covering both prefixes, in the route-target-less, VRFID-less plain
// reachability shape the gateway's VIP advertisements use.
//
// A no-op rather than an error when neither address is set yet, or when no
// BGPRouter targets this node yet: the BGPRouter watch retries once one
// appears.
func (r *EgressShardReconciler) applyShardAdvertisement(ctx context.Context, shard *bgpv1alpha1.EgressShard) error {
	prefixes, err := shardAdvertisementPrefixes(shard)
	if err != nil {
		return fmt.Errorf("build advertised prefixes: %w", err)
	}
	if len(prefixes) == 0 {
		return nil
	}

	routerName, err := routerNameForNode(ctx, r.Client, shard.Namespace, r.NodeName)
	if err != nil {
		return fmt.Errorf("look up BGPRouter for node %s: %w", r.NodeName, err)
	}
	if routerName == "" {
		return nil
	}

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
				Prefixes:      prefixes,
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
	advCopy.Spec.Prefixes = prefixes
	if err := r.Update(ctx, advCopy); err != nil {
		return fmt.Errorf("update BGPAdvertisement %s: %w", name, err)
	}
	return nil
}

// withdrawShardAdvertisement deletes the BGPAdvertisement
// applyShardAdvertisement creates for shardName, if any. One that never existed
// or is already gone is not an error.
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
// attachment state. A nil datapath, not expected in production, is treated as
// not attached rather than a panic.
func (r *EgressShardReconciler) readyCondition() metav1.Condition {
	if r.Datapath != nil && r.Datapath.Attached() {
		return metav1.Condition{
			Type:    bgpv1alpha1.ConditionTypeReady,
			Status:  metav1.ConditionTrue,
			Reason:  reasonEgressDatapathAttached,
			Message: "Egress translation datapath is attached and serving traffic",
		}
	}
	return metav1.Condition{
		Type:    bgpv1alpha1.ConditionTypeReady,
		Status:  metav1.ConditionFalse,
		Reason:  reasonEgressDatapathNotAttached,
		Message: "Egress translation datapath is not yet attached",
	}
}

// SetupWithManager registers the reconciler with the manager.
//
// The BGPRouter watch closes a startup race: without it, a EgressShard whose
// node's BGPRouter does not exist yet at first reconcile fails its router
// lookup once and gets no second chance until an unrelated event triggers a
// fresh reconcile.
func (r *EgressShardReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&bgpv1alpha1.EgressShard{}).
		Watches(&bgpv1alpha1.BGPRouter{}, handler.EnqueueRequestsFromMapFunc(
			func(ctx context.Context, obj client.Object) []ctrlreconcile.Request {
				return broadcastToShardRequests(ctx, r.Client, obj.GetNamespace())
			}),
		).
		Named("egressshard").
		Complete(r)
}

// broadcastToShardRequests enqueues every EgressShard in namespace. A BGPRouter
// change may be the one this node's shard was waiting on, and there is normally
// at most one shard per node, so listing the namespace is cheap.
func broadcastToShardRequests(ctx context.Context, c client.Client, namespace string) []ctrlreconcile.Request {
	logger := log.FromContext(ctx)
	shardList := &bgpv1alpha1.EgressShardList{}
	if err := c.List(ctx, shardList, client.InNamespace(namespace)); err != nil {
		logger.Error(err, "list EgressShards for BGPRouter change", "namespace", namespace)
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
