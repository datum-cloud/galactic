// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package rollout

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	networkv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
)

// fakeFleet is a namespace of deployments on Nodes in zones, one router
// revision, and a release reconciler over a fake client.
type fakeFleet struct {
	t   *testing.T
	c   client.Client
	r   *ReleaseReconciler
	rev *networkv1alpha1.FabricRouterRevision
}

func newFakeFleet(t *testing.T, zones map[string]string, extra ...client.Object) *fakeFleet {
	t.Helper()
	return newFakeFleetWith(t, zones, nil, extra...)
}

// newFakeFleetWith is newFakeFleet with intercepted client calls.
func newFakeFleetWith(t *testing.T, zones map[string]string, funcs *interceptor.Funcs,
	extra ...client.Object) *fakeFleet {
	t.Helper()
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = networkv1alpha1.AddToScheme(scheme)
	rev := revisionWith("edge-aaaaaaaaaa", digestA, nil)
	rev.Labels = map[string]string{routerLabel: testRouter}
	rev.Spec.Configuration.Advertisements = []networkv1alpha1.FabricNamedAdvertisement{{
		Spec: networkv1alpha1.BGPAdvertisementSpec{Prefixes: []networkv1alpha1.Prefix{prefixA}},
	}}
	objs := make([]client.Object, 0, 2*len(zones)+1+len(extra))
	objs = append(objs, rev)
	for name, zone := range zones {
		objs = append(objs,
			&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: map[string]string{defaultFailureDomainLabel: zone}}},
			&networkv1alpha1.FabricRouterDeployment{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNS, Name: name, UID: types.UID(name + "-uid")},
				Spec: networkv1alpha1.FabricRouterDeploymentSpec{
					RouterRef: networkv1alpha1.FabricObjectIdentity{Name: testRouter, UID: "router-uid"},
					Target:    networkv1alpha1.FabricNodeIdentity{NodeName: name, NodeUID: name + "-node"},
					Source:    networkv1alpha1.FabricConfigSourceCRD,
				},
			})
	}
	objs = append(objs, extra...)
	b := fake.NewClientBuilder()
	if funcs != nil {
		b = b.WithInterceptorFuncs(*funcs)
	}
	c := b.WithScheme(scheme).WithObjects(objs...).
		WithStatusSubresource(&networkv1alpha1.FabricReleaseAuthorization{},
			&networkv1alpha1.FabricRouterDeployment{}).Build()
	return &fakeFleet{t: t, c: c, r: &ReleaseReconciler{Client: c}, rev: rev}
}

func (f *fakeFleet) release(name string, typ networkv1alpha1.FabricReleaseType, seq int64, deployments ...string) {
	f.t.Helper()
	a := &networkv1alpha1.FabricReleaseAuthorization{
		ObjectMeta: metav1.ObjectMeta{Namespace: testNS, Name: name, UID: types.UID(name + "-uid")},
		Spec: networkv1alpha1.FabricReleaseAuthorizationSpec{
			Type: typ, RoutingDomain: testDomain, FleetReleaseID: name, FleetSequence: seq,
		},
	}
	if typ == networkv1alpha1.FabricReleaseTypeEmergencyWithdrawal {
		a.Spec.WithdrawnPrefixes = []string{prefixB}
	}
	for _, d := range deployments {
		a.Spec.Deployments = append(a.Spec.Deployments, networkv1alpha1.FabricReleaseTarget{
			Deployment: d, DeploymentUID: d + "-uid", Revision: f.rev.Name, ActivationDependencyDigest: digestA,
		})
	}
	if err := f.c.Create(context.Background(), a); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fakeFleet) reconcile(name string) *networkv1alpha1.FabricReleaseAuthorization {
	f.t.Helper()
	key := types.NamespacedName{Namespace: testNS, Name: name}
	for range 3 {
		if _, err := f.r.Reconcile(context.Background(), ctrl.Request{NamespacedName: key}); err != nil {
			f.t.Fatal(err)
		}
	}
	a := &networkv1alpha1.FabricReleaseAuthorization{}
	if err := f.c.Get(context.Background(), key, a); err != nil {
		f.t.Fatal(err)
	}
	return a
}

func (f *fakeFleet) deployment(name string) *networkv1alpha1.FabricRouterDeployment {
	f.t.Helper()
	d := &networkv1alpha1.FabricRouterDeployment{}
	if err := f.c.Get(context.Background(), types.NamespacedName{Namespace: testNS, Name: name}, d); err != nil {
		f.t.Fatal(err)
	}
	return d
}

// report writes an agent report for the deployment's active epoch.
func (f *fakeFleet) report(name string, stage networkv1alpha1.FabricActivationStage, committed bool) {
	f.t.Helper()
	d := f.deployment(name)
	hb := metav1.Now()
	d.Status.HeartbeatTime = &hb
	d.Status.Epochs = append([]networkv1alpha1.FabricEpochStatus{{
		Epoch: d.Spec.ActivationEpoch, Revision: d.Spec.ActiveRevisionRef.Name, Stage: stage,
	}}, d.Status.Epochs...)
	if committed {
		d.Status.AppliedEpoch = d.Spec.ActivationEpoch
		d.Status.AppliedRevision = d.Spec.ActiveRevisionRef.Name
		d.Status.AppliedDigest = d.Spec.ActivationDependencyDigest
	}
	if err := f.c.Status().Update(context.Background(), d); err != nil {
		f.t.Fatal(err)
	}
}

// TestReleasesShareDomainLimits: an emergency withdrawal running beside a
// release counts the release's in-flight routers against the limit, and
// never promotes a deployment still activating the release's epoch.
func TestReleasesShareDomainLimits(t *testing.T) {
	f := newFakeFleet(t, map[string]string{"a1": "a", "a2": "a"})
	f.release("rel", networkv1alpha1.FabricReleaseTypeRelease, 1, "a1")
	// Started, or Unknown until a1's agent reports.
	if a := f.reconcile("rel"); a.Status.StartedAt == nil {
		t.Fatalf("rel phase %s", a.Status.Phase)
	}
	if f.deployment("a1").Spec.ActivationEpoch != 1 {
		t.Fatal("rel did not promote a1")
	}
	f.report("a1", networkv1alpha1.FabricStageAccepted, false)

	f.release("ew", networkv1alpha1.FabricReleaseTypeEmergencyWithdrawal, 2, "a1", "a2")
	if a := f.reconcile("ew"); a.Status.Phase != networkv1alpha1.FabricReleasePhaseStarted {
		t.Fatalf("ew phase %s; an emergency withdrawal may start beside a release", a.Status.Phase)
	}
	if e := f.deployment("a1").Spec.ActivationEpoch; e != 1 {
		t.Errorf("ew promoted a1 over rel's epoch in flight (epoch %d)", e)
	}
	if e := f.deployment("a2").Spec.ActivationEpoch; e != 0 {
		t.Errorf("ew promoted a2 past zone a's limit with a1 in flight (epoch %d)", e)
	}

	// a1 commits under rel; rel completes, and ew may proceed.
	f.report("a1", networkv1alpha1.FabricStageCommitted, true)
	if a := f.reconcile("rel"); a.Status.Phase != networkv1alpha1.FabricReleasePhaseCompleted {
		t.Fatalf("rel phase %s", a.Status.Phase)
	}
	f.reconcile("ew")
	if f.deployment("a2").Spec.ActivationEpoch != 1 {
		t.Fatal("ew did not promote a2 once zone a was free")
	}
	// a1 already runs ew's revision, committed: only a2 has to commit.
	f.report("a2", networkv1alpha1.FabricStageCommitted, true)
	if a := f.reconcile("ew"); a.Status.Phase != networkv1alpha1.FabricReleasePhaseCompleted {
		t.Errorf("ew phase %s", a.Status.Phase)
	}
}

// TestReleaseRefusesRevokedOrigination: a revision originating a prefix an
// emergency withdrawal revoked on the deployment is never promoted.
func TestReleaseRefusesRevokedOrigination(t *testing.T) {
	f := newFakeFleet(t, map[string]string{"a1": "a"})
	d := f.deployment("a1")
	d.Spec.Recovery = &networkv1alpha1.FabricRecovery{RevokedPrefixes: []string{"192.0.0.0/16"}}
	if err := f.c.Update(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	f.release("rel", networkv1alpha1.FabricReleaseTypeRelease, 1, "a1")
	a := f.reconcile("rel")
	c := meta.FindStatusCondition(a.Status.Conditions, ConditionProgressing)
	if a.Status.Phase != networkv1alpha1.FabricReleasePhaseCancelled || c == nil || c.Reason != reasonInvalidTarget {
		t.Fatalf("phase %s, condition %+v", a.Status.Phase, c)
	}
	if f.deployment("a1").Spec.ActivationEpoch != 0 {
		t.Error("a revoked origination was promoted")
	}
}

// TestFailedReleaseOperatorConfirmation: a failed router with no recovery
// target never reports a recovery; an operator's annotation releases the
// routing domain.
func TestFailedReleaseOperatorConfirmation(t *testing.T) {
	f := newFakeFleet(t, map[string]string{"a1": "a"})
	f.release("rel", networkv1alpha1.FabricReleaseTypeRelease, 1, "a1")
	f.reconcile("rel")
	f.report("a1", networkv1alpha1.FabricStageApplyFailed, false)
	if a := f.reconcile("rel"); a.Status.Phase != networkv1alpha1.FabricReleasePhaseFailed || a.Status.RecoveryVerified {
		t.Fatalf("phase %s verified %v", a.Status.Phase, a.Status.RecoveryVerified)
	}
	if a := f.reconcile("rel"); a.Status.RecoveryVerified || !a.Status.Outstanding() {
		t.Fatal("a release whose router cannot recover stopped blocking by itself")
	}
	a := &networkv1alpha1.FabricReleaseAuthorization{}
	if err := f.c.Get(context.Background(), types.NamespacedName{Namespace: testNS, Name: relName}, a); err != nil {
		t.Fatal(err)
	}
	a.Annotations = map[string]string{RecoveryVerifiedAnnotation: "oncall"}
	if err := f.c.Update(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	if a := f.reconcile("rel"); !a.Status.RecoveryVerified || a.Status.Outstanding() || len(a.Finalizers) != 0 {
		t.Errorf("after confirmation: verified %v outstanding %v finalizers %v",
			a.Status.RecoveryVerified, a.Status.Outstanding(), a.Finalizers)
	}
}

// TestReleasePromotesOverRefusedEpoch: a router promoted by a release that
// failed before its agent accepted the promotion is refused by the agent,
// and a later release promotes it rather than waiting on it forever.
func TestReleasePromotesOverRefusedEpoch(t *testing.T) {
	f := newFakeFleet(t, map[string]string{"a1": "a", "a2": "a"}, widePolicy()...)
	f.release(relName, networkv1alpha1.FabricReleaseTypeRelease, 1, "a1", "a2")
	f.reconcile(relName)
	f.report("a1", networkv1alpha1.FabricStageApplyFailed, false)
	if a := f.reconcile(relName); a.Status.Phase != networkv1alpha1.FabricReleasePhaseFailed {
		t.Fatalf("rel phase %s", a.Status.Phase)
	}
	d := f.deployment("a2")
	if d.Spec.ActivationEpoch != 1 {
		t.Fatal("rel did not promote a2")
	}
	hb := metav1.Now()
	d.Status.HeartbeatTime = &hb
	d.Status.Conditions = []metav1.Condition{{
		Type: networkv1alpha1.FabricConditionAccepted, Status: metav1.ConditionFalse,
		Reason: networkv1alpha1.FabricReasonPromotionRefused, ObservedGeneration: d.Generation,
		LastTransitionTime: hb,
	}}
	if err := f.c.Status().Update(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	a := &networkv1alpha1.FabricReleaseAuthorization{}
	if err := f.c.Get(context.Background(), types.NamespacedName{Namespace: testNS, Name: relName}, a); err != nil {
		t.Fatal(err)
	}
	a.Annotations = map[string]string{RecoveryVerifiedAnnotation: "oncall"}
	if err := f.c.Update(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	f.reconcile(relName)
	f.release("rel2", networkv1alpha1.FabricReleaseTypeRelease, 2, "a2")
	f.reconcile("rel2")
	if d := f.deployment("a2"); d.Spec.ActivationEpoch != 2 || d.Spec.AuthorizationRef.Name != "rel2" {
		t.Errorf("a2 at epoch %d under %s; rel2 waited on a refused promotion", d.Spec.ActivationEpoch,
			d.Spec.AuthorizationRef.Name)
	}
}

func TestHeartbeatTimeoutFloor(t *testing.T) {
	p := effectivePolicy(&networkv1alpha1.FabricRolloutPolicy{Spec: networkv1alpha1.FabricRolloutPolicySpec{
		HeartbeatTimeoutSeconds: 5,
	}})
	if p.HeartbeatTimeoutSeconds != minHeartbeatTimeout {
		t.Errorf("heartbeat timeout %d, want the %ds floor", p.HeartbeatTimeoutSeconds, minHeartbeatTimeout)
	}
}

// TestStateOfRollback: a revision the deployment committed before, and
// since replaced, is promoted again: a rollback is a real promotion.
func TestStateOfRollback(t *testing.T) {
	r1 := revisionWith("r-aaaaaaaaaa", digestA, nil)
	r2 := revisionWith("r-bbbbbbbbbb", digestB, nil)
	auth := &networkv1alpha1.FabricReleaseAuthorization{ObjectMeta: metav1.ObjectMeta{Name: relName, UID: relUID}}
	d := committedDeployment(3, r2)
	d.Status.Epochs = []networkv1alpha1.FabricEpochStatus{
		{Epoch: 3, Revision: r2.Name, Stage: networkv1alpha1.FabricStageCommitted},
		{Epoch: 2, Revision: r1.Name, Stage: networkv1alpha1.FabricStageCommitted},
	}
	target := networkv1alpha1.FabricReleaseTarget{Revision: r1.Name, ActivationDependencyDigest: digestA}
	if got := stateOf(d, auth, target, time.Minute, time.Now()); got != targetWaiting {
		t.Errorf("rolling back to a revision committed before: state %d, want waiting", got)
	}
	sameName := networkv1alpha1.FabricReleaseTarget{Revision: r2.Name, ActivationDependencyDigest: digestA}
	if got := stateOf(d, auth, sameName, time.Minute, time.Now()); got != targetWaiting {
		t.Errorf("the running revision under another digest: state %d, want waiting", got)
	}
}

// widePolicy lets two routers of one failure domain activate at once.
func widePolicy() []client.Object {
	return []client.Object{
		&networkv1alpha1.FabricRolloutPolicy{
			ObjectMeta: metav1.ObjectMeta{Namespace: testNS, Name: "wide"},
			Spec:       networkv1alpha1.FabricRolloutPolicySpec{MaxUnavailable: 2},
		},
		&networkv1alpha1.BGPRouter{
			ObjectMeta: metav1.ObjectMeta{Namespace: testNS, Name: testRouter},
			Spec: networkv1alpha1.BGPRouterSpec{
				FRR: &networkv1alpha1.BGPRouterFRR{RolloutPolicyRef: &networkv1alpha1.LocalObjectRef{Name: "wide"}},
			},
		},
	}
}

// TestReleaseRechecksBeforePromoting: a deployment read as idle that
// another release promoted since is not promoted over.
func TestReleaseRechecksBeforePromoting(t *testing.T) {
	gets := 0
	funcs := &interceptor.Funcs{Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object,
		opts ...client.GetOption) error {
		if err := c.Get(ctx, key, obj, opts...); err != nil {
			return err
		}
		if d, ok := obj.(*networkv1alpha1.FabricRouterDeployment); ok && key.Name == "a1" {
			gets++
			if gets == 1 {
				// The first read predates the other release's promotion.
				d.Spec.ActivationEpoch, d.Spec.ActiveRevisionRef, d.Spec.AuthorizationRef = 0, nil, nil
				d.Spec.ActivationDependencyDigest, d.Spec.Activation, d.Status = "", nil,
					networkv1alpha1.FabricRouterDeploymentStatus{}
			}
		}
		return nil
	}}
	f := newFakeFleetWith(t, map[string]string{"a1": "a"}, funcs, widePolicy()...)
	d := f.deployment("a1")
	gets = 0
	d.Spec.ActivationEpoch = 1
	d.Spec.ActiveRevisionRef = &networkv1alpha1.LocalObjectRef{Name: "other-revision"}
	d.Spec.ActivationDependencyDigest = digestB
	d.Spec.AuthorizationRef = &networkv1alpha1.FabricObjectIdentity{Name: "other", UID: "other-uid"}
	if err := f.c.Update(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	f.release("rel", networkv1alpha1.FabricReleaseTypeRelease, 1, "a1")
	key := types.NamespacedName{Namespace: testNS, Name: relName}
	for range 2 {
		gets = 0
		if _, err := f.r.Reconcile(context.Background(), ctrl.Request{NamespacedName: key}); err != nil {
			t.Fatal(err)
		}
	}
	gets = 2
	if got := f.deployment("a1"); got.Spec.AuthorizationRef.Name != "other" || got.Spec.ActivationEpoch != 1 {
		t.Errorf("a1 at epoch %d under %s; promoted over another release's epoch", got.Spec.ActivationEpoch,
			got.Spec.AuthorizationRef.Name)
	}
}

// A promotion its agent refused for good, under a release that ended
// before the agent accepted it, never activates and holds no slot.
func TestBusyUntilRefused(t *testing.T) {
	r1 := revisionWith("r-aaaaaaaaaa", digestA, nil)
	d := committedDeployment(2, r1)
	d.Status.AppliedEpoch = 1
	d.Generation = 3
	refusal := metav1.Condition{
		Type: networkv1alpha1.FabricConditionAccepted, Status: metav1.ConditionFalse,
		Reason: networkv1alpha1.FabricReasonPromotionRefused, ObservedGeneration: 2,
	}
	d.Status.Conditions = []metav1.Condition{refusal}
	if !busy(d) {
		t.Error("a refusal reported for an earlier generation released a promoted router")
	}
	d.Status.Conditions[0].ObservedGeneration = 3
	if busy(d) {
		t.Error("a router whose agent refused its promotion still counts as busy")
	}
	d.Status.Conditions[0].Reason = "NotAuthorized"
	if !busy(d) {
		t.Error("a refusal that may yet clear released a promoted router")
	}
	d.Status.Conditions[0].Reason = networkv1alpha1.FabricReasonPromotionRefused
	d.Status.Epochs = []networkv1alpha1.FabricEpochStatus{{Epoch: 2, Stage: networkv1alpha1.FabricStageAccepted}}
	if !busy(d) {
		t.Error("a router activating its epoch counts as free")
	}
}

// A router whose activation failed with nothing to recover to, handed back
// to its ConfigMap, activates nothing and holds no slot, though its agent
// no longer reports Degraded off CRD.
func TestBusyUntilHandedBack(t *testing.T) {
	r1 := revisionWith("r-aaaaaaaaaa", digestA, nil)
	d := committedDeployment(2, r1)
	d.Status.AppliedEpoch = 1
	d.Status.Epochs = []networkv1alpha1.FabricEpochStatus{{Epoch: 2, Stage: networkv1alpha1.FabricStageApplyFailed}}
	d.Spec.Source = networkv1alpha1.FabricConfigSourceConfigMap
	d.Status.EffectiveSource = networkv1alpha1.FabricConfigSourceCRD
	if !busy(d) {
		t.Error("a router still on CRD, its handoff pending, counts as free")
	}
	d.Status.EffectiveSource = networkv1alpha1.FabricConfigSourceConfigMap
	if busy(d) {
		t.Error("a router handed back to its ConfigMap still counts as busy")
	}
}

func TestBusyWhileRecovering(t *testing.T) {
	r1 := revisionWith("r-aaaaaaaaaa", digestA, nil)
	d := committedDeployment(2, r1)
	d.Status.AppliedEpoch = 1
	d.Generation = 3
	d.Status.Epochs = []networkv1alpha1.FabricEpochStatus{{Epoch: 2, Stage: networkv1alpha1.FabricStageApplyFailed}}
	if !busy(d) {
		t.Error("a router recovering from a failed apply counts as free")
	}
	d.Status.Conditions = []metav1.Condition{{
		Type: networkv1alpha1.FabricConditionDegraded, Status: metav1.ConditionTrue,
		Reason: networkv1alpha1.FabricReasonNoEligibleRecovery, ObservedGeneration: 2,
	}}
	if !busy(d) {
		t.Error("a Degraded condition from an earlier generation released a recovering router")
	}
	d.Status.Conditions[0].ObservedGeneration = 3
	if busy(d) {
		t.Error("a router with nothing to recover to still counts as busy")
	}
	d.Status.Epochs[0].Stage = networkv1alpha1.FabricStageRecovered
	d.Status.Conditions = nil
	if busy(d) {
		t.Error("a recovered router counts as busy")
	}
}

func TestReleaseRefusesRetired(t *testing.T) {
	f := newFakeFleet(t, map[string]string{"a1": "a"})
	d := f.deployment("a1")
	d.Spec.Recovery = &networkv1alpha1.FabricRecovery{Retired: true}
	if err := f.c.Update(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	f.release("rel", networkv1alpha1.FabricReleaseTypeRelease, 1, "a1")
	a := f.reconcile("rel")
	c := meta.FindStatusCondition(a.Status.Conditions, ConditionProgressing)
	if a.Status.Phase != networkv1alpha1.FabricReleasePhaseCancelled || c == nil || c.Reason != reasonInvalidTarget {
		t.Fatalf("phase %s condition %+v", a.Status.Phase, c)
	}
}

// TestDeletingReleaseStopsPromoting: a started release being deleted keeps
// its finalizer and tracks what it promoted, but promotes nothing more.
func TestDeletingReleaseStopsPromoting(t *testing.T) {
	f := newFakeFleet(t, map[string]string{"a1": "a", "a2": "a"})
	f.release("rel", networkv1alpha1.FabricReleaseTypeRelease, 1, "a1", "a2")
	f.reconcile("rel")
	first := "a1"
	if f.deployment("a1").Spec.ActivationEpoch == 0 {
		first = "a2"
	}
	f.report(first, networkv1alpha1.FabricStageCommitted, true)
	a := &networkv1alpha1.FabricReleaseAuthorization{}
	if err := f.c.Get(context.Background(), types.NamespacedName{Namespace: testNS, Name: relName}, a); err != nil {
		t.Fatal(err)
	}
	if err := f.c.Delete(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	a = f.reconcile("rel")
	if f.deployment("a1").Spec.ActivationEpoch+f.deployment("a2").Spec.ActivationEpoch != 1 {
		t.Error("a release being deleted promoted another router")
	}
	if len(a.Finalizers) == 0 {
		t.Error("a started release lost its finalizer while being deleted")
	}
}

// TestReleaseLeavesSupersededTargets: a target a later release moved on
// is left alone and counts toward completion.
func TestReleaseLeavesSupersededTargets(t *testing.T) {
	f := newFakeFleet(t, map[string]string{"a1": "a", "a2": "a"})
	f.release("rel", networkv1alpha1.FabricReleaseTypeRelease, 1, "a1", "a2")
	f.reconcile("rel")
	first, second := "a1", "a2"
	if f.deployment("a1").Spec.ActivationEpoch == 0 {
		first, second = "a2", "a1"
	}
	f.report(first, networkv1alpha1.FabricStageCommitted, true)

	// A later emergency withdrawal takes the other router first.
	f.release("ew", networkv1alpha1.FabricReleaseTypeEmergencyWithdrawal, 2, second)
	ew := &networkv1alpha1.FabricReleaseAuthorization{}
	key := types.NamespacedName{Namespace: testNS, Name: "ew"}
	if err := f.c.Get(context.Background(), key, ew); err != nil {
		t.Fatal(err)
	}
	ew.Spec.Deployments[0].Revision, ew.Spec.Deployments[0].ActivationDependencyDigest = f.rev.Name, digestA
	f.reconcile("ew")
	if f.deployment(second).Spec.AuthorizationRef == nil || f.deployment(second).Spec.AuthorizationRef.Name != "ew" {
		t.Fatalf("ew did not promote %s", second)
	}
	f.report(second, networkv1alpha1.FabricStageAccepted, false)
	epoch := f.deployment(second).Spec.ActivationEpoch

	a := f.reconcile("rel")
	if got := f.deployment(second); got.Spec.ActivationEpoch != epoch || got.Spec.AuthorizationRef.Name != "ew" {
		t.Errorf("rel rewound %s from ew's epoch %d to %d", second, epoch, got.Spec.ActivationEpoch)
	}
	if a.Status.Phase != networkv1alpha1.FabricReleasePhaseCompleted {
		t.Errorf("rel phase %s with one router committed and one superseded", a.Status.Phase)
	}
}

// TestReleaseNeverPromotesOverAnotherEpoch: even with room under the
// domain limit, a deployment still activating another release's epoch is
// not promoted.
func TestReleaseNeverPromotesOverAnotherEpoch(t *testing.T) {
	f := newFakeFleet(t, map[string]string{"a1": "a"}, widePolicy()...)
	f.release(relName, networkv1alpha1.FabricReleaseTypeRelease, 1, "a1")
	f.reconcile(relName)
	f.report("a1", networkv1alpha1.FabricStageAccepted, false)
	f.release("ew", networkv1alpha1.FabricReleaseTypeEmergencyWithdrawal, 2, "a1")
	f.reconcile("ew")
	d := f.deployment("a1")
	if d.Spec.ActivationEpoch != 1 || d.Spec.AuthorizationRef.Name != relName {
		t.Errorf("a1 at epoch %d under %s; ew promoted over rel's epoch in flight",
			d.Spec.ActivationEpoch, d.Spec.AuthorizationRef.Name)
	}
}
