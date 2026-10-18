// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package rollout

import (
	"context"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	networkv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
)

const (
	digestC    = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	secretName = "bgp-auth"
	secretUID  = "secret-uid"
)

// routerRevision is a revision of the test router; with credential it
// authenticates a peer with that Secret.
func routerRevision(name, digest, credential string) *networkv1alpha1.FabricRouterRevision {
	rev := revisionWith(name, digest, nil)
	rev.Labels = map[string]string{routerLabel: testRouter}
	if credential != "" {
		rev.Spec.Configuration.Peers = []networkv1alpha1.FabricNamedPeer{{Name: "upstream",
			Spec: networkv1alpha1.BGPPeerSpec{Address: "203.0.113.9",
				AuthSecretRef: &networkv1alpha1.LocalSecretRef{Name: credential}}}}
	}
	return rev
}

func credentialSecret(uid string) *corev1.Secret {
	return &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: testNS, Name: secretName, UID: types.UID(uid)}}
}

// releaseOf creates a release promoting each deployment to rev, each
// target edited by edit when it is set.
func (f *fakeFleet) releaseOf(name string, seq int64, rev *networkv1alpha1.FabricRouterRevision,
	edit func(*networkv1alpha1.FabricReleaseTarget), deployments ...string) {
	f.t.Helper()
	a := &networkv1alpha1.FabricReleaseAuthorization{
		ObjectMeta: metav1.ObjectMeta{Namespace: testNS, Name: name, UID: types.UID(name + "-uid")},
		Spec: networkv1alpha1.FabricReleaseAuthorizationSpec{
			Type: networkv1alpha1.FabricReleaseTypeRelease, RoutingDomain: testDomain, FleetReleaseID: name,
			FleetSequence: seq,
		},
	}
	for _, d := range deployments {
		t := networkv1alpha1.FabricReleaseTarget{
			Deployment: d, DeploymentUID: d + "-uid", Revision: rev.Name,
			ActivationDependencyDigest: rev.Spec.ActivationDependencyDigest,
		}
		if edit != nil {
			edit(&t)
		}
		a.Spec.Deployments = append(a.Spec.Deployments, t)
	}
	if err := f.c.Create(context.Background(), a); err != nil {
		f.t.Fatal(err)
	}
}

// cancelledFor checks the release was cancelled as an invalid target, with
// a message naming want.
func cancelledFor(t *testing.T, a *networkv1alpha1.FabricReleaseAuthorization, phase networkv1alpha1.FabricReleasePhase,
	want string) {
	t.Helper()
	c := meta.FindStatusCondition(a.Status.Conditions, ConditionProgressing)
	if a.Status.Phase != phase || c == nil || c.Reason != reasonInvalidTarget || !strings.Contains(c.Message, want) {
		t.Fatalf("phase %s, condition %+v, want %s naming %q", a.Status.Phase, c, phase, want)
	}
}

// TestReleaseRefusesRevokedCredential: a revision whose credential is
// revoked on the deployment, by Secret UID, or cannot be resolved is
// never promoted; a Secret recreated under the same name is a new
// credential.
func TestReleaseRefusesRevokedCredential(t *testing.T) {
	cred := routerRevision("edge-cccccccccc", digestC, secretName)
	revoked := &networkv1alpha1.FabricRecovery{RevokedCredentials: []networkv1alpha1.FabricObjectIdentity{{
		Name: secretName, UID: secretUID}}}
	for _, tc := range []struct {
		name     string
		secret   *corev1.Secret
		recovery *networkv1alpha1.FabricRecovery
		want     string
	}{
		{name: "resolved", secret: credentialSecret(secretUID)},
		{name: "revoked", secret: credentialSecret(secretUID), recovery: revoked,
			want: "uses credential " + secretName + " (Secret UID " + secretUID + "), which is revoked"},
		{name: "recreated", secret: credentialSecret("new-uid"), recovery: revoked},
		{name: "unresolvable", recovery: revoked, want: "uses credential " + secretName + ", which cannot be resolved"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			extra := []client.Object{cred}
			if tc.secret != nil {
				extra = append(extra, tc.secret)
			}
			f := newFakeFleet(t, map[string]string{"a1": "a"}, extra...)
			if tc.recovery != nil {
				d := f.deployment("a1")
				d.Spec.Recovery = tc.recovery
				if err := f.c.Update(context.Background(), d); err != nil {
					t.Fatal(err)
				}
			}
			f.releaseOf(relName, 1, cred, nil, "a1")
			a := f.reconcile(relName)
			if tc.want != "" {
				cancelledFor(t, a, networkv1alpha1.FabricReleasePhaseCancelled, tc.want)
				if e := f.deployment("a1").Spec.ActivationEpoch; e != 0 {
					t.Errorf("promoted to epoch %d", e)
				}
				return
			}
			if e := f.deployment("a1").Spec.ActivationEpoch; e != 1 {
				t.Errorf("a1 at epoch %d, phase %s; want promoted", e, a.Status.Phase)
			}
		})
	}
}

// TestReleaseFailsOnCredentialRevokedAfterStart: a credential revoked
// after the release started stops the promotion that would use it, and
// fails the release naming it.
func TestReleaseFailsOnCredentialRevokedAfterStart(t *testing.T) {
	cred := routerRevision("edge-cccccccccc", digestC, secretName)
	f := newFakeFleet(t, map[string]string{"a1": "a", "a2": "a"}, cred, credentialSecret(secretUID))
	f.releaseOf(relName, 1, cred, nil, "a1", "a2")
	f.reconcile(relName)
	first, second := "a1", "a2"
	if f.deployment("a1").Spec.ActivationEpoch == 0 {
		first, second = "a2", "a1"
	}
	d := f.deployment(second)
	d.Spec.Recovery = &networkv1alpha1.FabricRecovery{RevokedCredentials: []networkv1alpha1.FabricObjectIdentity{{
		Name: secretName, UID: secretUID}}}
	if err := f.c.Update(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	f.report(first, networkv1alpha1.FabricStageCommitted, true)
	// Once: a later pass reports the failed release's recovery instead.
	key := types.NamespacedName{Namespace: testNS, Name: relName}
	if _, err := f.r.Reconcile(context.Background(), ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatal(err)
	}
	a := &networkv1alpha1.FabricReleaseAuthorization{}
	if err := f.c.Get(context.Background(), key, a); err != nil {
		t.Fatal(err)
	}
	cancelledFor(t, a, networkv1alpha1.FabricReleasePhaseFailed, "credential "+secretName)
	if e := f.deployment(second).Spec.ActivationEpoch; e != 0 {
		t.Errorf("%s promoted to epoch %d with a revoked credential", second, e)
	}
}
