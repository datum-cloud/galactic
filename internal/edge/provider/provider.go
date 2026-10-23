// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package provider is the provider side of the Galactic Edge forwarding
// claim: an internal/edge/claim Store over an EdgeInstance's Lease, and the
// compare-and-swap writes a provider pod makes to claim and release an
// EdgeRoute.
//
// Nothing here grants forwarding. galactic-controller accepts a route claim
// only after the previous holder is fenced, and galactic-edge opens a
// prefix's gate only for the accepted holder while that holder's lease, as
// this store records it, is renewed. A provider that skips these helpers or
// forges their values can stall only its own routes.
package provider

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"math"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	coordinationv1 "k8s.io/api/coordination/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
	"go.datum.net/galactic/internal/edge/claim"
)

// InstanceName is the derived name of a pod's EdgeInstance.
func InstanceName(podUID string) string { return "ei-" + digest(podUID) }

// RouteName is the derived name of the EdgeRoute for prefix in the VPC with
// vpcUID.
func RouteName(vpcUID string, prefix netip.Prefix) string {
	return "er-" + digest(vpcUID+"/"+prefix.Masked().String())
}

func digest(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:16])
}

// InstanceStore is a claim.Store over the leases of EdgeInstances in one
// namespace, keyed by instance name. Each lease is a coordination.k8s.io/v1
// Lease with its instance's name, owned by the instance and laid out as
// api/v1alpha1's EdgeLease constants describe; its incarnation is the
// Lease's UID. Every read is from the API server, and every write after the
// first is a merge patch with the Lease's UID and resourceVersion as
// preconditions, so a write based on an older read, or on a Lease since
// deleted and recreated, fails with claim.ErrConflict.
//
// The EdgeInstance itself must exist: Create writes the first lease of an
// existing instance and never creates the instance.
type InstanceStore struct {
	// Client must read from the API server, not a cache.
	Client    client.Client
	Namespace string
	// Duration, when set, is written as the Lease's leaseDurationSeconds
	// for tools that display it. Nothing reads it back.
	Duration time.Duration
	// Now stamps the Lease's renewTime for tools that display it; nothing
	// reads it back. Nil uses the wall clock.
	Now func() time.Time
}

// Get implements claim.Store.
func (s InstanceStore) Get(ctx context.Context, key string) (claim.Record, error) {
	var l coordinationv1.Lease
	if err := s.Client.Get(ctx, types.NamespacedName{Namespace: s.Namespace, Name: key}, &l); err != nil {
		if apierrors.IsNotFound(err) {
			return claim.Record{}, claim.ErrNotFound
		}
		return claim.Record{}, err
	}
	return record(&l)
}

// Create implements claim.Store: it writes r as the first lease of an
// existing instance. The lease's incarnation is the UID the API server gives
// the Lease, not r.Incarnation.
func (s InstanceStore) Create(ctx context.Context, r claim.Record) (claim.Record, error) {
	var inst galacticv1alpha1.EdgeInstance
	if err := s.Client.Get(ctx, types.NamespacedName{Namespace: s.Namespace, Name: r.Key}, &inst); err != nil {
		if apierrors.IsNotFound(err) {
			return claim.Record{}, fmt.Errorf("%w: EdgeInstance %s/%s must exist before its lease", claim.ErrNotFound,
				s.Namespace, r.Key)
		}
		return claim.Record{}, err
	}
	epoch, err := leaseEpoch(r.Epoch)
	if err != nil {
		return claim.Record{}, err
	}
	l := &coordinationv1.Lease{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: s.Namespace, Name: r.Key,
			Labels:      map[string]string{galacticv1alpha1.EdgeLeaseProviderLabel: inst.Spec.ProviderRef.Name},
			Annotations: map[string]string{galacticv1alpha1.EdgeLeasePodUIDAnnotation: inst.Spec.PodUID},
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: galacticv1alpha1.GroupVersion.String(), Kind: "EdgeInstance",
				Name: inst.Name, UID: inst.UID, Controller: ptr.To(true),
			}},
		},
		Spec: s.spec(r, epoch),
	}
	maps.Copy(l.Annotations, protocolAnnotations(r))
	switch err := s.Client.Create(ctx, l); {
	case apierrors.IsAlreadyExists(err):
		return claim.Record{}, claim.ErrConflict
	case err != nil:
		return claim.Record{}, err
	}
	return record(l)
}

// Update implements claim.Store.
func (s InstanceStore) Update(ctx context.Context, r claim.Record) (claim.Record, error) {
	uid, rv, ok := strings.Cut(r.Version, "/")
	if !ok {
		return claim.Record{}, fmt.Errorf("%w: malformed version %q", claim.ErrConflict, r.Version)
	}
	epoch, err := leaseEpoch(r.Epoch)
	if err != nil {
		return claim.Record{}, err
	}
	// The patch names every field it owns, a null holderIdentity included,
	// so none keeps a stale value.
	spec := s.spec(r, epoch)
	specPatch := map[string]any{"holderIdentity": spec.HolderIdentity, "leaseTransitions": spec.LeaseTransitions,
		"renewTime": spec.RenewTime}
	if spec.LeaseDurationSeconds != nil {
		specPatch["leaseDurationSeconds"] = spec.LeaseDurationSeconds
	}
	patch, err := json.Marshal(map[string]any{
		"metadata": map[string]any{"uid": uid, "resourceVersion": rv, "annotations": protocolAnnotations(r)},
		"spec":     specPatch,
	})
	if err != nil {
		return claim.Record{}, err
	}
	l := &coordinationv1.Lease{ObjectMeta: metav1.ObjectMeta{Namespace: s.Namespace, Name: r.Key}}
	err = s.Client.Patch(ctx, l, client.RawPatch(types.MergePatchType, patch))
	switch {
	case apierrors.IsConflict(err):
		return claim.Record{}, claim.ErrConflict
	case apierrors.IsInvalid(err):
		// An admission policy refused the write, as it does once the Lease
		// no longer names this provider or pod: retrying cannot succeed. A
		// write from a stale version, a fenced or recreated lease's
		// included, is a conflict instead.
		return claim.Record{}, fmt.Errorf("%w: lease %s/%s write refused: %w", claim.ErrLost, s.Namespace, r.Key, err)
	case apierrors.IsNotFound(err):
		return claim.Record{}, claim.ErrNotFound
	case err != nil:
		return claim.Record{}, err
	}
	return record(l)
}

// spec is the Lease spec for r. holderIdentity is null while nobody holds
// the lease.
func (s InstanceStore) spec(r claim.Record, epoch int32) coordinationv1.LeaseSpec {
	now := time.Now
	if s.Now != nil {
		now = s.Now
	}
	spec := coordinationv1.LeaseSpec{LeaseTransitions: ptr.To(epoch), RenewTime: ptr.To(metav1.NewMicroTime(now()))}
	if r.Holder != "" {
		spec.HolderIdentity = ptr.To(r.Holder)
	}
	if s.Duration > 0 {
		spec.LeaseDurationSeconds = ptr.To(int32(math.Ceil(s.Duration.Seconds())))
	}
	return spec
}

func leaseEpoch(e uint64) (int32, error) {
	if e > math.MaxInt32 {
		return 0, fmt.Errorf("claim: epoch %d does not fit a Lease's leaseTransitions", e)
	}
	return int32(e), nil
}

func protocolAnnotations(r claim.Record) map[string]string {
	return map[string]string{
		galacticv1alpha1.EdgeLeaseRenewStartAnnotation: strconv.FormatInt(int64(r.RenewStart), 10),
		galacticv1alpha1.EdgeLeaseSequenceAnnotation:   strconv.FormatUint(r.Sequence, 10),
		galacticv1alpha1.EdgeLeaseReleasedAnnotation:   strconv.FormatBool(r.Released),
	}
}

func record(l *coordinationv1.Lease) (claim.Record, error) {
	a := l.Annotations
	start, err := strconv.ParseInt(a[galacticv1alpha1.EdgeLeaseRenewStartAnnotation], 10, 64)
	if err != nil || start < 0 {
		return claim.Record{}, fmt.Errorf("lease %s/%s: malformed %s", l.Namespace, l.Name,
			galacticv1alpha1.EdgeLeaseRenewStartAnnotation)
	}
	seq, err := strconv.ParseUint(a[galacticv1alpha1.EdgeLeaseSequenceAnnotation], 10, 64)
	if err != nil {
		return claim.Record{}, fmt.Errorf("lease %s/%s: malformed %s", l.Namespace, l.Name,
			galacticv1alpha1.EdgeLeaseSequenceAnnotation)
	}
	released, err := strconv.ParseBool(a[galacticv1alpha1.EdgeLeaseReleasedAnnotation])
	if err != nil {
		return claim.Record{}, fmt.Errorf("lease %s/%s: malformed %s", l.Namespace, l.Name,
			galacticv1alpha1.EdgeLeaseReleasedAnnotation)
	}
	return claim.Record{
		Key: l.Name, Holder: ptr.Deref(l.Spec.HolderIdentity, ""), Incarnation: string(l.UID),
		Epoch: uint64(max(ptr.Deref(l.Spec.LeaseTransitions, 0), 0)), Sequence: seq,
		RenewStart: time.Duration(start), Released: released,
		Version: string(l.UID) + "/" + l.ResourceVersion,
	}, nil
}

// ReadLease reads inst's lease from reader. It reports false, and no error,
// when inst has no lease or its Lease is not bound to inst: owned by inst,
// labeled with inst's provider and annotated with inst's pod, with every
// protocol annotation well formed. Callers that decide forwarding pass a
// reader that reads from the API server.
func ReadLease(ctx context.Context, reader client.Reader, inst *galacticv1alpha1.EdgeInstance,
) (claim.Record, bool, error) {
	var l coordinationv1.Lease
	switch err := reader.Get(ctx, client.ObjectKeyFromObject(inst), &l); {
	case apierrors.IsNotFound(err):
		return claim.Record{}, false, nil
	case err != nil:
		return claim.Record{}, false, err
	}
	owned := slices.ContainsFunc(l.OwnerReferences, func(o metav1.OwnerReference) bool { return o.UID == inst.UID })
	if !owned || l.Labels[galacticv1alpha1.EdgeLeaseProviderLabel] != inst.Spec.ProviderRef.Name ||
		l.Annotations[galacticv1alpha1.EdgeLeasePodUIDAnnotation] != inst.Spec.PodUID {
		return claim.Record{}, false, nil
	}
	r, err := record(&l)
	if err != nil {
		return claim.Record{}, false, nil
	}
	return r, true, nil
}

// Fence takes the lease r away from its holder: it moves the Lease named
// r.Key in namespace to the next epoch with no holder, by merge patch with
// r.Version's UID and resourceVersion as preconditions. galactic-controller
// fences the previous holder's lease before accepting another attachment's
// claim, at the version it saw unchanged for the takeover interval: a
// renewal that lands afterwards conflicts and its holder learns the lease is
// lost, and one that landed first makes Fence return claim.ErrConflict, so
// the holder is still renewing.
func Fence(ctx context.Context, c client.Client, namespace string, r claim.Record) error {
	uid, rv, ok := strings.Cut(r.Version, "/")
	if !ok {
		return fmt.Errorf("%w: malformed version %q", claim.ErrConflict, r.Version)
	}
	epoch, err := leaseEpoch(r.Epoch + 1)
	if err != nil {
		return err
	}
	patch, err := json.Marshal(map[string]any{
		"metadata": map[string]any{"uid": uid, "resourceVersion": rv, "annotations": map[string]string{
			galacticv1alpha1.EdgeLeaseReleasedAnnotation: strconv.FormatBool(false),
		}},
		"spec": map[string]any{"holderIdentity": nil, "leaseTransitions": epoch},
	})
	if err != nil {
		return err
	}
	l := &coordinationv1.Lease{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: r.Key}}
	switch err := c.Patch(ctx, l, client.RawPatch(types.MergePatchType, patch)); {
	case apierrors.IsConflict(err), apierrors.IsNotFound(err):
		return fmt.Errorf("%w: fence lease %s/%s: %w", claim.ErrConflict, namespace, r.Key, err)
	case err != nil:
		return fmt.Errorf("fence lease %s/%s: %w", namespace, r.Key, err)
	}
	return nil
}

// NewInstance returns the EdgeInstance of the pod with podUID and podName on
// node, for the provider, created in boot bootID.
func NewInstance(namespace, provider, podName, podUID, node, bootID string) *galacticv1alpha1.EdgeInstance {
	return &galacticv1alpha1.EdgeInstance{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: InstanceName(podUID)},
		Spec: galacticv1alpha1.EdgeInstanceSpec{
			ProviderRef: galacticv1alpha1.EdgeProviderReference{Name: provider},
			PodName:     podName, PodUID: podUID, NodeName: node, BootID: bootID,
		},
	}
}

// NewRoute returns a route for prefix in the VPC with vpcUID, with a new
// incarnation and no claim.
func NewRoute(namespace, provider, vpcUID string, prefix netip.Prefix) *galacticv1alpha1.EdgeRoute {
	prefix = prefix.Masked()
	return &galacticv1alpha1.EdgeRoute{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: RouteName(vpcUID, prefix)},
		Spec: galacticv1alpha1.EdgeRouteSpec{
			ProviderRef: galacticv1alpha1.EdgeProviderReference{Name: provider},
			VPCUID:      vpcUID, Prefix: prefix.String(), Incarnation: rand.Text(),
		},
	}
}

// ErrNotHolder is returned by Release when the route's claim is not the
// caller's.
var ErrNotHolder = errors.New("provider: the route is claimed by another holder")

// ended reports whether the route's claim at epoch can never forward again:
// galactic-controller revoked it, or its node recorded its gate closed, as it
// does once the gate's deadline passes. Only a new claim epoch replaces it.
func ended(route *galacticv1alpha1.EdgeRoute, epoch int64) bool {
	if route.Status.ClosedEpoch >= epoch {
		return true
	}
	acc := route.Status.Accepted
	return acc != nil && acc.Epoch == epoch &&
		meta.IsStatusConditionFalse(route.Status.Conditions, galacticv1alpha1.EdgeRouteAccepted)
}

// Claim makes the attachment of the pod with podUID, under lease l of its
// instance, the route's claimed holder, by compare-and-swap on the route as
// it was read. A claim that already names this holder unreleased is left
// alone; any other holder, or a released claim, takes the next claim epoch.
// The route must have been read from the API server. A concurrent change
// fails with an apierrors Conflict, and the caller reads again.
//
// The claim grants nothing until galactic-controller accepts it.
func Claim(ctx context.Context, c client.Client, route *galacticv1alpha1.EdgeRoute, attachment, podUID string,
	l claim.Lease) error {
	cur := route.Spec.Claim
	next := galacticv1alpha1.EdgeRouteClaim{
		Attachment: attachment, HolderPodUID: podUID, HolderInstance: l.Key, InstanceEpoch: int64(l.Epoch), Epoch: 1,
	}
	if cur != nil {
		same := *cur
		same.Released = false
		next.Epoch = cur.Epoch
		if same == next && !cur.Released && !ended(route, cur.Epoch) {
			return nil
		}
		next.Epoch = cur.Epoch + 1
	}
	route.Spec.Claim = &next
	return c.Update(ctx, route)
}

// Release marks the route's claim released, by compare-and-swap on the route
// as it was read. The caller must already have stopped forwarding the
// prefix. It returns ErrNotHolder when the claim names another holder or
// another epoch of l.
func Release(ctx context.Context, c client.Client, route *galacticv1alpha1.EdgeRoute, l claim.Lease) error {
	cur := route.Spec.Claim
	if cur == nil || cur.HolderInstance != l.Key || cur.InstanceEpoch != int64(l.Epoch) {
		return ErrNotHolder
	}
	if cur.Released {
		return nil
	}
	cur.Released = true
	return c.Update(ctx, route)
}
