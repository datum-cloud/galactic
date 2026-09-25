// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	ctrlreconcile "sigs.k8s.io/controller-runtime/pkg/reconcile"

	"go.datum.net/galactic/internal/plumbing/ebpf/uformat"
	bgpv1alpha1 "go.datum.net/network/api/v1alpha1"
)

// EgressShardIdentity is the identity an egress translation datapath is
// programmed with: the shard SID tenant egress routes encapsulate toward, and
// the masquerade address of each family it serves. ShardAddressIPv4 and
// NAT64Prefix are valid together or not at all.
//
// It is this package's own type rather than the datapath's map row so the
// controller package, which every binary links, does not pull in the egress
// translation eBPF objects.
type EgressShardIdentity struct {
	ShardSID         netip.Addr
	ShardAddressIPv6 netip.Addr
	ShardAddressIPv4 netip.Addr
	NAT64Prefix      netip.Prefix
}

// EgressDatapath is this node's egress translation XDP datapath, as
// EgressShardReconciler drives it. It is an interface so tests can fake it.
type EgressDatapath interface {
	// Attached reports whether the datapath is loaded and attached.
	Attached() bool

	// Program replaces the identity the datapath translates with. It rejects
	// an identity the datapath cannot translate with, leaving the previous one
	// in place.
	Program(EgressShardIdentity) error

	// Clear removes the identity, so the datapath claims no packet.
	Clear() error

	// Programmed reports the identity the datapath currently translates with,
	// and false when it has none.
	Programmed() (EgressShardIdentity, bool)
}

const (
	// reasonEgressDatapathAttached is the Ready condition reason once the
	// datapath is confirmed attached.
	reasonEgressDatapathAttached = "DatapathAttached"

	// reasonEgressDatapathNotAttached is the Ready condition reason while
	// the datapath is not yet (or no longer) attached.
	reasonEgressDatapathNotAttached = "DatapathNotAttached"

	// reasonEgressShardConflict is the Programmed condition reason on every
	// EgressShard targeting a node that more than one targets. The datapath
	// holds one identity, so none of them is programmed until the conflict is
	// resolved.
	reasonEgressShardConflict = "ShardConflict"
)

// EgressShardReconciler programs this node's egress translation datapath from
// the spec of the single EgressShard whose spec.targetRef.name is this node,
// and publishes what the datapath is actually programmed with in its status.
// Ready reports that the datapath is attached; Programmed reports that it is
// translating with the identity the spec assigns.
//
// It also maintains one BGPAdvertisement per shard carrying the shard SID's
// locator and the IPv6 masquerade address, built from status rather than spec
// so the fabric only learns an identity this node actually translates with.
//
// That advertisement is what makes both reachable across the fabric, in the
// same route-target-less, VRFID-less shape the gateway's VIP advertisements
// use. Without the SID's route, a tenant VRF default egress route points at a
// SID no node ever learns a kernel route to, so no forward traffic reaches this
// shard. Without the address's route, forward traffic arrives and is correctly
// translated, but the reply has no route back from anywhere else on the fabric,
// so a TCP connection never completes even while every forward-path counter
// looks healthy.
type EgressShardReconciler struct {
	client.Client
	Scheme *runtime.Scheme

	NodeName string

	// Datapath is this node's egress translation datapath -- see
	// EgressDatapath's doc comment.
	Datapath EgressDatapath

	// syncMu serializes syncNode between the controller's reconciles and the
	// startup sync SetupWithManager registers, which run concurrently.
	syncMu sync.Mutex
}

// Reconcile reconciles a single EgressShard.
//
// The datapath holds one identity per node, so which shard it is programmed
// from is a property of every EgressShard targeting this node together, not of
// the one named in req. Every request therefore ends in syncNode, which
// re-derives the datapath's state from all of them. That is also what clears
// the datapath when this node's shard is deleted: by then the object is gone
// and could not say which node it targeted.
func (r *EgressShardReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	shard := &bgpv1alpha1.EgressShard{}
	err := r.Get(ctx, req.NamespacedName, shard)
	switch {
	case apierrors.IsNotFound(err):
		// EgressShard carries no finalizer, so by the time this Get sees
		// NotFound the object is gone everywhere, on whichever node's
		// process handled the event and not necessarily the shard's own.
		// Withdraw keyed on req.Name, which the advertisement name is
		// derived from, rather than on the unreadable deleted object.
		if err := withdrawShardAdvertisement(ctx, r.Client, req.Namespace, req.Name); err != nil {
			logger.Error(err, "withdraw BGPAdvertisement for deleted EgressShard", "egressShard", req.NamespacedName)
			return ctrl.Result{}, err
		}
	case err != nil:
		return ctrl.Result{}, fmt.Errorf("get EgressShard %s: %w", req.NamespacedName, err)
	case !shard.DeletionTimestamp.IsZero() && shard.Spec.TargetRef.Name == r.NodeName:
		// Not known to be reachable while there is no finalizer, the NotFound
		// branch above being the one a real delete takes, but kept correct in
		// case that changes.
		if err := withdrawShardAdvertisement(ctx, r.Client, shard.Namespace, shard.Name); err != nil {
			logger.Error(err, "withdraw BGPAdvertisement for terminating EgressShard", "egressShard", req.NamespacedName)
			return ctrl.Result{}, err
		}
	}

	if err := r.syncNode(ctx); err != nil {
		logger.Error(err, "sync egress translation datapath", "node", r.NodeName)
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

// syncNode drives the datapath from every live EgressShard targeting this node
// and publishes the result on each of them:
//
//   - none: the datapath is cleared. Nothing assigns this node an identity, so
//     it must not keep translating with one a deleted shard left behind.
//   - one: the datapath is programmed from its spec.
//   - more than one: the datapath is cleared and every one of them reports the
//     conflict. Picking one would make which shard translates depend on list
//     order, and the other would publish an identity nothing translates with.
func (r *EgressShardReconciler) syncNode(ctx context.Context) error {
	if r.Datapath == nil {
		return errors.New("no egress translation datapath configured")
	}
	r.syncMu.Lock()
	defer r.syncMu.Unlock()

	shardList := &bgpv1alpha1.EgressShardList{}
	if err := r.List(ctx, shardList); err != nil {
		return fmt.Errorf("list EgressShards: %w", err)
	}
	var mine []*bgpv1alpha1.EgressShard
	for i := range shardList.Items {
		s := &shardList.Items[i]
		if s.Spec.TargetRef.Name == r.NodeName && s.DeletionTimestamp.IsZero() {
			mine = append(mine, s)
		}
	}

	var programmed metav1.Condition
	switch len(mine) {
	case 0:
		if err := r.Datapath.Clear(); err != nil {
			return fmt.Errorf("clear egress translation datapath: %w", err)
		}
		return nil
	case 1:
		var err error
		if programmed, err = r.program(mine[0]); err != nil {
			// Publish why before returning the error for a retry.
			if pubErr := r.publish(ctx, mine[0], programmed); pubErr != nil {
				return errors.Join(err, pubErr)
			}
			return err
		}
	default:
		if err := r.Datapath.Clear(); err != nil {
			return fmt.Errorf("clear egress translation datapath: %w", err)
		}
		programmed = metav1.Condition{
			Type:    bgpv1alpha1.ConditionTypeProgrammed,
			Status:  metav1.ConditionFalse,
			Reason:  reasonEgressShardConflict,
			Message: fmt.Sprintf("%d EgressShards target node %s; exactly one may", len(mine), r.NodeName),
		}
	}

	var errs []error
	for _, s := range mine {
		errs = append(errs, r.publish(ctx, s, programmed))
	}
	return errors.Join(errs...)
}

// program writes shard's spec into the datapath and returns the resulting
// Programmed condition. A spec that assigns no usable identity yet clears the
// datapath rather than leaving a previous one in place, which is not an error:
// the assignment arrives later as a spec update.
func (r *EgressShardReconciler) program(shard *bgpv1alpha1.EgressShard) (metav1.Condition, error) {
	cond := metav1.Condition{Type: bgpv1alpha1.ConditionTypeProgrammed, Status: metav1.ConditionFalse}

	identity, missing, err := identityFromSpec(shard.Spec)
	if err != nil {
		cond.Reason = bgpv1alpha1.ProgrammedReasonProgrammingFailed
		cond.Message = err.Error()
		return cond, nil
	}
	if missing != "" {
		if err := r.Datapath.Clear(); err != nil {
			return cond, fmt.Errorf("clear egress translation datapath: %w", err)
		}
		cond.Reason = bgpv1alpha1.ProgrammedReasonAddressUnassigned
		cond.Message = missing
		return cond, nil
	}
	if err := r.Datapath.Program(identity); err != nil {
		cond.Reason = bgpv1alpha1.ProgrammedReasonProgrammingFailed
		cond.Message = err.Error()
		return cond, fmt.Errorf("program egress translation datapath from EgressShard %s/%s: %w",
			shard.Namespace, shard.Name, err)
	}

	cond.Status = metav1.ConditionTrue
	cond.Reason = bgpv1alpha1.ProgrammedReasonAddressesProgrammed
	cond.Message = "Egress translation datapath is translating with the assigned identity"
	return cond, nil
}

// identityFromSpec parses spec's identity fields. missing is non-empty, with
// the error nil, when the spec does not yet assign enough to translate with: a
// SID and at least one family. err is a value that does not parse, which the
// CRD's own validation should already have rejected.
func identityFromSpec(spec bgpv1alpha1.EgressShardSpec) (identity EgressShardIdentity, missing string, err error) {
	parseAddr := func(field, raw string) (netip.Addr, error) {
		if raw == "" {
			return netip.Addr{}, nil
		}
		addr, err := netip.ParseAddr(raw)
		if err != nil {
			return netip.Addr{}, fmt.Errorf("spec.%s: %w", field, err)
		}
		return addr, nil
	}

	if identity.ShardSID, err = parseAddr("shardSID", spec.ShardSID); err != nil {
		return identity, "", err
	}
	if identity.ShardAddressIPv6, err = parseAddr("shardAddressIPv6", spec.ShardAddressIPv6); err != nil {
		return identity, "", err
	}
	if identity.ShardAddressIPv4, err = parseAddr("shardAddressIPv4", spec.ShardAddressIPv4); err != nil {
		return identity, "", err
	}
	if spec.NAT64Prefix != "" {
		if identity.NAT64Prefix, err = netip.ParsePrefix(spec.NAT64Prefix); err != nil {
			return identity, "", fmt.Errorf("spec.nat64Prefix: %w", err)
		}
	}

	switch {
	case !identity.ShardSID.IsValid():
		return identity, "No shard SID is assigned", nil
	case !identity.ShardAddressIPv6.IsValid() && !identity.ShardAddressIPv4.IsValid():
		return identity, "No masquerade address is assigned for either family", nil
	}
	return identity, "", nil
}

// publish writes shard's status from what the datapath is programmed with --
// not from its spec, so a shard that has not converged shows it -- together
// with the Ready and Programmed conditions, then reconciles its advertisement
// to match.
func (r *EgressShardReconciler) publish(ctx context.Context, shard *bgpv1alpha1.EgressShard,
	programmed metav1.Condition,
) error {
	shardCopy := shard.DeepCopy()
	shardCopy.Status.ObservedGeneration = shard.Generation
	shardCopy.Status.ShardSID = ""
	shardCopy.Status.ShardAddressIPv6 = ""
	shardCopy.Status.ShardAddressIPv4 = ""
	shardCopy.Status.NAT64Prefix = ""
	// A conflicting shard publishes no identity even while the datapath holds
	// one, which it cannot here: syncNode clears it first. Checking the
	// condition rather than relying on that keeps the two from drifting.
	if programmed.Reason != reasonEgressShardConflict {
		if identity, ok := r.Datapath.Programmed(); ok {
			shardCopy.Status.ShardSID = addrString(identity.ShardSID)
			shardCopy.Status.ShardAddressIPv6 = addrString(identity.ShardAddressIPv6)
			shardCopy.Status.ShardAddressIPv4 = addrString(identity.ShardAddressIPv4)
			if identity.NAT64Prefix.IsValid() {
				shardCopy.Status.NAT64Prefix = identity.NAT64Prefix.String()
			}
		}
	}
	setEgressShardCondition(shardCopy, r.readyCondition())
	setEgressShardCondition(shardCopy, programmed)

	if err := r.Status().Update(ctx, shardCopy); err != nil {
		return fmt.Errorf("update EgressShard %s/%s status: %w", shard.Namespace, shard.Name, err)
	}
	if err := r.applyShardAdvertisement(ctx, shardCopy); err != nil {
		return fmt.Errorf("apply BGPAdvertisement for EgressShard %s/%s: %w", shard.Namespace, shard.Name, err)
	}
	return nil
}

// addrString is addr's string form, or empty for the zero Addr rather than
// netip's "invalid IP".
func addrString(addr netip.Addr) string {
	if !addr.IsValid() {
		return ""
	}
	return addr.String()
}

// shardAdvertisementName derives the deterministic BGPAdvertisement name for a
// EgressShard, so withdrawal keyed on a deletion event's name alone never needs
// to read the object it is naming. The "-sid" suffix predates the advertisement
// also carrying the shard address, and is kept rather than churning every
// existing shard's name for a cosmetic rename.
func shardAdvertisementName(shardName string) string {
	return shardName + "-sid"
}

// shardAdvertisementPrefixes builds the prefixes advertised for shard: the
// shard SID, which is the forward leg a tenant VRF's egress routes encapsulate
// toward, and the IPv6 shard address, which is the return leg a reply's
// destination is rewritten to and which needs a route back from wherever that
// reply's next hop is, not just from this node.
//
// The SID is advertised as its covering /64 -- Block and Node-ID, the shard's
// whole uSID identity -- not as a /128. A tenant VRF's egress route encapsulates
// toward this SID with that tenant's own 12-bit Argument written into it, so the
// destination differs per tenant and a /128 covers exactly one of them. The
// datapath already treats the top 64 bits as the shard's identity: see
// locator_matches in internal/plumbing/ebpf/natprog/nat.c, which deliberately
// does not compare the Argument, and locator_table's key in prog/usid.c. This
// makes the control plane agree with that.
//
// Whatever Argument the operator baked into the configured SID is therefore not
// advertised and carries no meaning; installEgressRoutes overwrites it per
// tenant. Reserving the Block and Node-ID for this shard alone is what the /64
// requires, which was already true -- locator_matches' doc comment spells out
// what reusing a co-located BGPRouter's Node-ID silently breaks.
//
// The shard address stays a /128. It is an ordinary masquerade source address,
// not a uSID, and nothing varies below it.
//
// Status.ShardAddressIPv4 is deliberately absent. A NAT64 reply arrives from the
// IPv4 internet rather than across this fabric, so advertising that address into
// the EVPN mesh would not make it reachable by the party that needs to reach it;
// the underlay or an upstream announcement has to attract it to this node. See
// EgressShard's own field documentation.
//
// Either prefix may be independently unset -- a NAT64-only shard has no IPv6
// address, and a shard its node is not translating for has neither -- in which
// case it is omitted rather than failing the whole advertisement. Callers treat
// an empty result as nothing to advertise, not an error.
func shardAdvertisementPrefixes(shard *bgpv1alpha1.EgressShard) ([]bgpv1alpha1.Prefix, error) {
	var prefixes []bgpv1alpha1.Prefix

	if raw := shard.Status.ShardSID; raw != "" {
		addr, err := netip.ParseAddr(raw)
		if err != nil {
			return nil, fmt.Errorf("parse %q: %w", raw, err)
		}
		if addr.BitLen() < uformat.LocatorBits {
			return nil, fmt.Errorf("parse %q: a shard SID must be an IPv6 address", raw)
		}
		prefixes = append(prefixes,
			bgpv1alpha1.Prefix(netip.PrefixFrom(addr, uformat.LocatorBits).Masked().String()))
	}

	if raw := shard.Status.ShardAddressIPv6; raw != "" {
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
// With neither prefix set, which is a shard its node is not translating for,
// any advertisement left from an earlier identity is withdrawn. With no
// BGPRouter targeting this node yet it is a no-op rather than an error: the
// BGPRouter watch retries once one appears.
func (r *EgressShardReconciler) applyShardAdvertisement(ctx context.Context, shard *bgpv1alpha1.EgressShard) error {
	prefixes, err := shardAdvertisementPrefixes(shard)
	if err != nil {
		return fmt.Errorf("build advertised prefixes: %w", err)
	}
	if len(prefixes) == 0 {
		return withdrawShardAdvertisement(ctx, r.Client, shard.Namespace, shard.Name)
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
//
// The startup runnable closes another. The datapath's maps are pinned, so a
// restarted process inherits whatever identity its predecessor programmed. If
// this node's shard was deleted while no process was running and no other
// EgressShard exists, no event ever arrives to clear it, and the node would go
// on translating for a shard that no longer exists.
func (r *EgressShardReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if err := mgr.Add(manager.RunnableFunc(func(ctx context.Context) error {
		if !mgr.GetCache().WaitForCacheSync(ctx) {
			return nil
		}
		if err := r.syncNode(ctx); err != nil {
			// Not fatal: the next EgressShard event syncs again.
			log.FromContext(ctx).Error(err, "initial egress translation datapath sync", "node", r.NodeName)
		}
		return nil
	})); err != nil {
		return fmt.Errorf("add initial EgressShard sync: %w", err)
	}

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
