// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package rollout

import (
	"context"
	"errors"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	networkv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
)

// reactivate marks a release target a re-activation.
func reactivate(t *networkv1alpha1.FabricReleaseTarget) { t.Reactivate = true }

// committedOn writes a deployment committed on rev at epoch, with recovery.
func (f *fakeFleet) committedOn(name string, rev *networkv1alpha1.FabricRouterRevision, epoch int64,
	recovery *networkv1alpha1.FabricRecovery) {
	f.t.Helper()
	ctx := context.Background()
	d := f.deployment(name)
	d.Spec.ActivationEpoch = epoch
	d.Spec.ActiveRevisionRef = &networkv1alpha1.LocalObjectRef{Name: rev.Name}
	d.Spec.ActivationDependencyDigest = rev.Spec.ActivationDependencyDigest
	d.Spec.AuthorizationRef = &networkv1alpha1.FabricObjectIdentity{Name: "earlier", UID: "earlier-uid"}
	d.Spec.Activation = &networkv1alpha1.FabricActivationSettings{}
	d.Spec.Recovery = recovery
	if err := f.c.Update(ctx, d); err != nil {
		f.t.Fatal(err)
	}
	hb := metav1.Now()
	d.Status = networkv1alpha1.FabricRouterDeploymentStatus{
		HeartbeatTime: &hb, AppliedEpoch: epoch, AppliedRevision: rev.Name,
		AppliedDigest: rev.Spec.ActivationDependencyDigest,
		Epochs: []networkv1alpha1.FabricEpochStatus{{Epoch: epoch, Revision: rev.Name,
			Stage: networkv1alpha1.FabricStageCommitted}},
	}
	if err := f.c.Status().Update(ctx, d); err != nil {
		f.t.Fatal(err)
	}
}

func recoveryTo(rev *networkv1alpha1.FabricRouterRevision) *networkv1alpha1.FabricRecovery {
	return &networkv1alpha1.FabricRecovery{TargetRevisionRef: &networkv1alpha1.LocalObjectRef{Name: rev.Name},
		TargetDependencyDigest: rev.Spec.ActivationDependencyDigest}
}

// TestReleaseReactivatesLostNode: a release re-activating the revision a
// deployment reports committed promotes it as a new epoch, under that
// release, keeping the recovery target the deployment had; the same
// release without the flag promotes nothing.
func TestReleaseReactivatesLostNode(t *testing.T) {
	other := routerRevision("edge-bbbbbbbbbb", digestB, "")
	f := newFakeFleet(t, map[string]string{"a1": "a"}, other)
	f.committedOn("a1", other, 2, recoveryTo(f.rev))

	f.releaseOf("again", 1, other, nil, "a1")
	if a := f.reconcile("again"); a.Status.Phase != networkv1alpha1.FabricReleasePhaseCompleted {
		t.Fatalf("without re-activation: %s, want Completed at once", a.Status.Phase)
	}
	if e := f.deployment("a1").Spec.ActivationEpoch; e != 2 {
		t.Fatalf("a release without re-activation promoted a1 to epoch %d", e)
	}

	f.releaseOf("reactivate", 2, other, reactivate, "a1")
	a := f.reconcile("reactivate")
	if a.Status.Phase != networkv1alpha1.FabricReleasePhaseStarted {
		t.Fatalf("re-activation %s, want Started", a.Status.Phase)
	}
	d := f.deployment("a1")
	if d.Spec.ActivationEpoch != 3 || d.Spec.ActiveRevisionRef.Name != other.Name ||
		d.Spec.AuthorizationRef.Name != "reactivate" || d.Spec.AuthorizationRef.UID != "reactivate-uid" {
		t.Fatalf("a1 at epoch %d on %s under %+v, want epoch 3 on %s under reactivate", d.Spec.ActivationEpoch,
			d.Spec.ActiveRevisionRef.Name, d.Spec.AuthorizationRef, other.Name)
	}
	if r := d.Spec.Recovery; r == nil || r.TargetRevisionRef == nil || r.TargetRevisionRef.Name != f.rev.Name ||
		r.TargetDependencyDigest != digestA {
		t.Errorf("recovery %+v, want the earlier target %s", d.Spec.Recovery, f.rev.Name)
	}
	f.report("a1", networkv1alpha1.FabricStageCommitted, true)
	if a := f.reconcile("reactivate"); a.Status.Phase != networkv1alpha1.FabricReleasePhaseCompleted {
		t.Fatalf("re-activation committed: %s, want Completed", a.Status.Phase)
	}
	if e := f.deployment("a1").Spec.ActivationEpoch; e != 3 {
		t.Errorf("a completed re-activation promoted again, to epoch %d", e)
	}
}

// TestReactivationHonoursLimits: re-activations count against a failure
// domain's limit like any promotion.
func TestReactivationHonoursLimits(t *testing.T) {
	f := newFakeFleet(t, map[string]string{"a1": "a", "a2": "a"})
	f.committedOn("a1", f.rev, 1, nil)
	f.committedOn("a2", f.rev, 1, nil)
	f.releaseOf(relName, 1, f.rev, reactivate, "a1", "a2")
	f.reconcile(relName)
	if got := f.deployment("a1").Spec.ActivationEpoch + f.deployment("a2").Spec.ActivationEpoch; got != 3 {
		t.Fatalf("epochs sum to %d; want one of two routers in zone a re-activated", got)
	}
}

// TestReactivationRefused: a re-activation passes every check an ordinary
// promotion does.
func TestReactivationRefused(t *testing.T) {
	cred := routerRevision("edge-cccccccccc", digestC, secretName)
	for _, tc := range []struct {
		name     string
		rev      func(f *fakeFleet) *networkv1alpha1.FabricRouterRevision
		recovery *networkv1alpha1.FabricRecovery
		secret   *corev1.Secret
		want     string
	}{
		{name: "retired", recovery: &networkv1alpha1.FabricRecovery{Retired: true}, want: "retired"},
		{name: "revoked prefix", recovery: &networkv1alpha1.FabricRecovery{RevokedPrefixes: []string{"192.0.0.0/16"}},
			want: "revoked on deployment"},
		{name: "revoked credential", rev: func(*fakeFleet) *networkv1alpha1.FabricRouterRevision { return cred },
			recovery: &networkv1alpha1.FabricRecovery{RevokedCredentials: []networkv1alpha1.FabricObjectIdentity{{
				Name: secretName, UID: secretUID}}},
			secret: credentialSecret(secretUID), want: "credential " + secretName},
		{name: "unresolvable credential", rev: func(*fakeFleet) *networkv1alpha1.FabricRouterRevision { return cred },
			want: "cannot be resolved"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			extra := []client.Object{cred}
			if tc.secret != nil {
				extra = append(extra, tc.secret)
			}
			f := newFakeFleet(t, map[string]string{"a1": "a"}, extra...)
			rev := f.rev
			if tc.rev != nil {
				rev = tc.rev(f)
			}
			f.committedOn("a1", rev, 1, tc.recovery)
			f.releaseOf(relName, 1, rev, reactivate, "a1")
			cancelledFor(t, f.reconcile(relName), networkv1alpha1.FabricReleasePhaseCancelled, tc.want)
			if e := f.deployment("a1").Spec.ActivationEpoch; e != 1 {
				t.Errorf("a refused re-activation promoted a1 to epoch %d", e)
			}
		})
	}
}

// TestReactivationDropsRevokedRecovery: the recovery target a
// re-activation keeps is dropped when a failure could not restore it: it
// originates a revoked prefix, or uses a revoked or unresolvable
// credential, or is gone.
func TestReactivationDropsRevokedRecovery(t *testing.T) {
	cred := routerRevision("edge-cccccccccc", digestC, secretName)
	running := routerRevision("edge-bbbbbbbbbb", digestB, "")
	revoked := []networkv1alpha1.FabricObjectIdentity{{Name: secretName, UID: secretUID}}
	for _, tc := range []struct {
		name     string
		target   *networkv1alpha1.FabricRouterRevision
		edit     func(r *networkv1alpha1.FabricRecovery)
		secret   *corev1.Secret
		keep     bool
		withRevs bool
	}{
		{name: "eligible", keep: true, withRevs: true},
		{name: "revoked prefix", edit: func(r *networkv1alpha1.FabricRecovery) {
			r.RevokedPrefixes = []string{prefixA}
		}, withRevs: true},
		{name: "eligible credential", target: cred, secret: credentialSecret("other-uid"), keep: true,
			edit: func(r *networkv1alpha1.FabricRecovery) { r.RevokedCredentials = revoked }, withRevs: true},
		{name: "revoked credential", target: cred, secret: credentialSecret(secretUID),
			edit: func(r *networkv1alpha1.FabricRecovery) { r.RevokedCredentials = revoked }, withRevs: true},
		{name: "unresolvable credential", target: cred, withRevs: true},
		{name: "gone"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			extra := []client.Object{running}
			if tc.secret != nil {
				extra = append(extra, tc.secret)
			}
			target := tc.target
			if target == nil {
				target = routerRevision("edge-dddddddddd", strings.Repeat("d", 64), "")
				target.Spec.Configuration.Advertisements = []networkv1alpha1.FabricNamedAdvertisement{{
					Spec: networkv1alpha1.BGPAdvertisementSpec{Prefixes: []networkv1alpha1.Prefix{prefixA}},
				}}
			}
			if tc.withRevs {
				extra = append(extra, target)
			}
			f := newFakeFleet(t, map[string]string{"a1": "a"}, extra...)
			rec := recoveryTo(target)
			if tc.edit != nil {
				tc.edit(rec)
			}
			f.committedOn("a1", running, 2, rec)
			f.releaseOf(relName, 1, running, reactivate, "a1")
			f.reconcile(relName)
			d := f.deployment("a1")
			if d.Spec.ActivationEpoch != 3 {
				t.Fatalf("a1 at epoch %d, want re-activated at 3", d.Spec.ActivationEpoch)
			}
			kept := d.Spec.Recovery.TargetRevisionRef != nil
			if kept != tc.keep {
				t.Errorf("recovery target kept %t, want %t: %+v", kept, tc.keep, d.Spec.Recovery)
			}
			if !kept && d.Spec.Recovery.TargetDependencyDigest != "" {
				t.Errorf("a dropped recovery target left its digest %s", d.Spec.Recovery.TargetDependencyDigest)
			}
		})
	}
}

// TestReactivationDropsUnreadableRecovery: a recovery target whose
// credential the controller may not read is unrestorable, so the
// re-activation records none rather than retrying.
func TestReactivationDropsUnreadableRecovery(t *testing.T) {
	cred := routerRevision("edge-cccccccccc", digestC, secretName)
	running := routerRevision("edge-bbbbbbbbbb", digestB, "")
	funcs := &interceptor.Funcs{Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey,
		obj client.Object, opts ...client.GetOption) error {
		if md, ok := obj.(*metav1.PartialObjectMetadata); ok && md.Kind == "Secret" {
			return apierrors.NewForbidden(corev1.Resource("secrets"), key.Name, errors.New("denied"))
		}
		return c.Get(ctx, key, obj, opts...)
	}}
	f := newFakeFleetWith(t, map[string]string{"a1": "a"}, funcs, cred, running, credentialSecret(secretUID))
	f.committedOn("a1", running, 2, recoveryTo(cred))
	f.releaseOf(relName, 1, running, reactivate, "a1")
	f.reconcile(relName)
	d := f.deployment("a1")
	if d.Spec.ActivationEpoch != 3 || d.Spec.Recovery.TargetRevisionRef != nil {
		t.Errorf("a1 at epoch %d with recovery %+v; want re-activated with no recovery target",
			d.Spec.ActivationEpoch, d.Spec.Recovery)
	}
}
