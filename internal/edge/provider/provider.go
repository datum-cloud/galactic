// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package provider is the provider side of the Galactic Edge forwarding
// claim: an internal/edge/claim Store over an EdgeInstance's lease, and the
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
	"net/netip"
	"strings"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
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
// namespace, keyed by instance name. Every read is from the API server, and
// every write is a status update with the object's UID and resourceVersion
// as preconditions, so a write based on an older read, or on an object
// since deleted and recreated, fails with claim.ErrConflict.
//
// The EdgeInstance object itself must exist: Create writes the first lease
// of an existing instance and never creates the object.
type InstanceStore struct {
	// Client must read from the API server, not a cache.
	Client    client.Client
	Namespace string
}

// Get implements claim.Store. An instance with no lease yet is
// claim.ErrNotFound, like a missing one.
func (s InstanceStore) Get(ctx context.Context, key string) (claim.Record, error) {
	var inst galacticv1alpha1.EdgeInstance
	if err := s.Client.Get(ctx, types.NamespacedName{Namespace: s.Namespace, Name: key}, &inst); err != nil {
		if apierrors.IsNotFound(err) {
			return claim.Record{}, claim.ErrNotFound
		}
		return claim.Record{}, err
	}
	if inst.Status.Lease == nil {
		return claim.Record{}, claim.ErrNotFound
	}
	return record(&inst), nil
}

// Create implements claim.Store: it writes r as the first lease of an
// existing instance.
func (s InstanceStore) Create(ctx context.Context, r claim.Record) (claim.Record, error) {
	var inst galacticv1alpha1.EdgeInstance
	if err := s.Client.Get(ctx, types.NamespacedName{Namespace: s.Namespace, Name: r.Key}, &inst); err != nil {
		if apierrors.IsNotFound(err) {
			return claim.Record{}, fmt.Errorf("%w: EdgeInstance %s/%s must exist before its lease", claim.ErrNotFound,
				s.Namespace, r.Key)
		}
		return claim.Record{}, err
	}
	if inst.Status.Lease != nil {
		return claim.Record{}, claim.ErrConflict
	}
	return s.write(ctx, &inst, r)
}

// Update implements claim.Store.
func (s InstanceStore) Update(ctx context.Context, r claim.Record) (claim.Record, error) {
	uid, rv, ok := strings.Cut(r.Version, "/")
	if !ok {
		return claim.Record{}, fmt.Errorf("%w: malformed version %q", claim.ErrConflict, r.Version)
	}
	inst := &galacticv1alpha1.EdgeInstance{ObjectMeta: metav1.ObjectMeta{
		Namespace: s.Namespace, Name: r.Key, UID: types.UID(uid), ResourceVersion: rv,
	}}
	return s.write(ctx, inst, r)
}

// write stores r as inst's lease. The patch carries inst's UID and
// resourceVersion: the server refuses it with a conflict when the
// resourceVersion moved, and as invalid when the object was recreated with
// another UID.
func (s InstanceStore) write(ctx context.Context, inst *galacticv1alpha1.EdgeInstance, r claim.Record,
) (claim.Record, error) {
	inst.Status.Lease = &galacticv1alpha1.EdgeLease{
		Holder: r.Holder, Incarnation: r.Incarnation, Epoch: int64(r.Epoch), Sequence: int64(r.Sequence),
		RenewStart: int64(r.RenewStart), Released: r.Released,
	}
	patch, err := json.Marshal(map[string]any{
		"metadata": map[string]any{"uid": inst.UID, "resourceVersion": inst.ResourceVersion},
		"status":   map[string]any{"lease": inst.Status.Lease},
	})
	if err != nil {
		return claim.Record{}, err
	}
	err = s.Client.Status().Patch(ctx, inst, client.RawPatch(types.MergePatchType, patch))
	switch {
	case apierrors.IsConflict(err), apierrors.IsInvalid(err):
		return claim.Record{}, claim.ErrConflict
	case apierrors.IsNotFound(err):
		return claim.Record{}, claim.ErrNotFound
	case err != nil:
		return claim.Record{}, err
	}
	if inst.Status.Lease == nil {
		return claim.Record{}, fmt.Errorf("%w: lease missing after write", claim.ErrConflict)
	}
	return record(inst), nil
}

func record(inst *galacticv1alpha1.EdgeInstance) claim.Record {
	l := inst.Status.Lease
	return claim.Record{
		Key: inst.Name, Holder: l.Holder, Incarnation: l.Incarnation, Epoch: uint64(l.Epoch),
		Sequence: uint64(l.Sequence), RenewStart: time.Duration(l.RenewStart), Released: l.Released,
		Version: string(inst.UID) + "/" + inst.ResourceVersion,
	}
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
