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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	ctrlreconcile "sigs.k8s.io/controller-runtime/pkg/reconcile"

	"go.datum.net/galactic/internal/plumbing/ebpf/uformat"
	bgpv1alpha1 "go.datum.net/network/api/v1alpha1"
)

// EgressDatapath is this node's egress translation XDP datapath as the
// reconciler sees it: whether it is attached, and what masquerade identity it
// is programmed with. An interface so tests can fake it.
type EgressDatapath interface {
	// Attached reports whether the datapath is loaded and attached.
	Attached() bool

	// Program writes addressIPv6 into the datapath's shard config row and
	// reports the identity the datapath holds afterwards.
	//
	// An invalid addressIPv6 means the spec assigns this shard no IPv6
	// address. That programs nothing and is not an error: the XDP program
	// fails open on a row it has never been given, claiming no packet at all,
	// which is the state a shard sits in between attaching and being assigned
	// an address.
	Program(addressIPv6 netip.Addr) (EgressShardIdentity, error)
}

// EgressShardIdentity is the masquerade identity a datapath reports it is
// programmed with, as opposed to the one its spec asks for. Every field is the
// string form the status fields of the same name carry, and an empty one means
// the datapath translates nothing for that family.
//
// The shard SID is absent: it is still process configuration rather than
// something a controller assigns, so the reconciler publishes it from its own
// field. See EgressShardStatus.ShardSID.
type EgressShardIdentity struct {
	ShardAddressIPv6 string
	ShardAddressIPv4 string
	NAT64Prefix      string
}

// errNoDatapath is the programming failure a nil Datapath produces. It is
// reported as a condition and never returned from Reconcile: no retry can
// conjure a datapath into a process that failed to load one.
var errNoDatapath = errors.New("no egress translation datapath is available on this node")

const (
	// reasonEgressDatapathAttached is the Ready condition reason once the
	// datapath is confirmed attached.
	reasonEgressDatapathAttached = "DatapathAttached"

	// reasonEgressDatapathNotAttached is the Ready condition reason while
	// the datapath is not yet (or no longer) attached.
	reasonEgressDatapathNotAttached = "DatapathNotAttached"
)

// EgressShardReconciler reconciles the single EgressShard object whose
// spec.targetRef.name is this node. It programs the masquerade address the
// spec assigns into this node's datapath, publishes what that datapath is
// actually translating with, sets Ready once the datapath is confirmed
// attached and Programmed once it holds an assigned address, and maintains one
// BGPAdvertisement carrying a route for each.
//
// The address arrives in spec because the controller that owns the cell claims
// it, which keeps the addressing-service credential off every translating
// node. The SID does not: nothing allocates one yet, so it stays process
// configuration and is echoed into status the way both addresses used to be.
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

	// ShardSID is this node's operator-configured uSID. It stays process
	// configuration because nothing allocates one yet, unlike the masquerade
	// addresses, which a controller assigns in spec. This reconciler
	// publishes it; it does not compute it.
	ShardSID string

	// Datapath is this node's egress translation datapath: what the assigned
	// address is programmed into, and what reports back what it holds.
	Datapath EgressDatapath

	// SetProgrammedHealth reports whether this shard is translating with an
	// assigned address, for the gRPC health service a readiness probe reads.
	// Distinct from attachment, which the process reports as soon as the XDP
	// program is on the wire: a shard attached with no address assigned is a
	// live datapath that claims no packet, and a probe that cannot tell the
	// two apart calls it healthy. Optional; nil in tests.
	SetProgrammedHealth func(programmed bool)
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

	// The datapath is programmed before status is written, so status reports
	// what this node is translating with rather than what it was asked for.
	identity, progErr := r.programDatapath(shard)
	if progErr != nil {
		logger.Error(progErr, "program egress translation datapath", "egressShard", req.NamespacedName)
	}
	if r.SetProgrammedHealth != nil {
		r.SetProgrammedHealth(progErr == nil && identity.serves())
	}

	shardCopy := shard.DeepCopy()
	shardCopy.Status.ObservedGeneration = shard.Generation
	if r.ShardSID != "" {
		shardCopy.Status.ShardSID = r.ShardSID
	}
	// Each published only when the datapath reports one, never cleared to an
	// empty string. The shard config row is a blind overwrite that nothing
	// ever deletes, so an address this datapath once programmed is an address
	// it is still translating with, whatever the spec says now.
	if identity.ShardAddressIPv6 != "" {
		shardCopy.Status.ShardAddressIPv6 = identity.ShardAddressIPv6
	}
	if identity.ShardAddressIPv4 != "" {
		shardCopy.Status.ShardAddressIPv4 = identity.ShardAddressIPv4
	}
	if identity.NAT64Prefix != "" {
		shardCopy.Status.NAT64Prefix = identity.NAT64Prefix
	}
	setEgressShardCondition(shardCopy, r.readyCondition())
	setEgressShardCondition(shardCopy, programmedCondition(identity, progErr))

	if err := r.Status().Update(ctx, shardCopy); err != nil {
		logger.Error(err, "update EgressShard status", "egressShard", req.NamespacedName)
		return ctrl.Result{}, fmt.Errorf("update EgressShard %s status: %w", req.NamespacedName, err)
	}

	if err := r.applyShardAdvertisement(ctx, shardCopy); err != nil {
		logger.Error(err, "apply BGPAdvertisement for EgressShard", "egressShard", req.NamespacedName)
		return ctrl.Result{}, err
	}

	// Returned after status, so a failed map write is visible on the object
	// before the retry. errNoDatapath is excluded: it is the one programming
	// failure no retry can fix.
	if progErr != nil && !errors.Is(progErr, errNoDatapath) {
		return ctrl.Result{}, progErr
	}

	return ctrl.Result{}, nil
}

// programDatapath writes the address this shard's spec assigns into the
// datapath and returns what the datapath holds afterwards.
//
// An unassigned address is passed through as an invalid netip.Addr rather than
// skipped, so the datapath decides what an unassigned family means for the row
// it holds. An unparseable one is a programming failure: CEL rejects it on the
// way in, so reaching here means something wrote around the API server.
func (r *EgressShardReconciler) programDatapath(shard *bgpv1alpha1.EgressShard) (EgressShardIdentity, error) {
	if r.Datapath == nil {
		return EgressShardIdentity{}, errNoDatapath
	}

	var address netip.Addr
	if raw := shard.Spec.ShardAddressIPv6; raw != "" {
		parsed, err := netip.ParseAddr(raw)
		if err != nil {
			return EgressShardIdentity{}, fmt.Errorf("parse spec.shardAddressIPv6 %q: %w", raw, err)
		}
		address = parsed
	}

	identity, err := r.Datapath.Program(address)
	if err != nil {
		return identity, fmt.Errorf("program egress translation datapath: %w", err)
	}
	return identity, nil
}

// serves reports whether this identity translates for any address family.
func (i EgressShardIdentity) serves() bool {
	return i.ShardAddressIPv6 != "" || i.ShardAddressIPv4 != ""
}

// programmedCondition computes the Programmed condition from what the datapath
// reports it holds. It is deliberately separate from Ready, which reports only
// that the XDP program is attached: an attached shard whose spec assigns it no
// address is on the wire, counting nothing and claiming nothing, and a single
// condition covering both states cannot say so.
func programmedCondition(identity EgressShardIdentity, err error) metav1.Condition {
	switch {
	case err != nil:
		return metav1.Condition{
			Type:    bgpv1alpha1.ConditionTypeProgrammed,
			Status:  metav1.ConditionFalse,
			Reason:  bgpv1alpha1.ProgrammedReasonProgrammingFailed,
			Message: err.Error(),
		}
	case !identity.serves():
		return metav1.Condition{
			Type:   bgpv1alpha1.ConditionTypeProgrammed,
			Status: metav1.ConditionFalse,
			Reason: bgpv1alpha1.ProgrammedReasonAddressUnassigned,
			Message: "No egress address is assigned to this shard, so its datapath claims no packet " +
				"(assign spec.shardAddressIPv6)",
		}
	default:
		return metav1.Condition{
			Type:    bgpv1alpha1.ConditionTypeProgrammed,
			Status:  metav1.ConditionTrue,
			Reason:  bgpv1alpha1.ProgrammedReasonAddressesProgrammed,
			Message: "Egress translation datapath is programmed with every assigned address",
		}
	}
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
// Either prefix may be independently unset, by an operator who has not finished
// configuring this node's identity, in which case it is omitted rather than
// failing the whole advertisement. Callers treat an empty result as nothing to
// advertise yet, not an error.
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
// attachment state alone. Whether that attached datapath translates anything
// is the Programmed condition's job. A nil datapath, not expected in
// production, is treated as not attached rather than a panic.
func (r *EgressShardReconciler) readyCondition() metav1.Condition {
	if r.Datapath != nil && r.Datapath.Attached() {
		return metav1.Condition{
			Type:    bgpv1alpha1.ConditionTypeReady,
			Status:  metav1.ConditionTrue,
			Reason:  reasonEgressDatapathAttached,
			Message: "Egress translation datapath is attached",
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
