// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package rollout

import (
	"context"
	"slices"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	networkv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
)

const (
	digestA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	digestB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	prefixA = "192.0.2.0/24"
	prefixB = "198.51.100.0/24"
	relName = "rel"
	relUID  = "rel-uid"
)

func revisionWith(name, digest string, peers map[string]string,
	routes ...string) *networkv1alpha1.FabricRouterRevision {
	rev := &networkv1alpha1.FabricRouterRevision{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: testNS}}
	rev.Spec.ActivationDependencyDigest = digest
	for n, a := range peers {
		rev.Spec.Configuration.Peers = append(rev.Spec.Configuration.Peers,
			networkv1alpha1.FabricNamedPeer{Name: n, Spec: networkv1alpha1.BGPPeerSpec{Address: a}})
	}
	for _, r := range routes {
		rev.Spec.Configuration.StaticRoutes = append(rev.Spec.Configuration.StaticRoutes,
			networkv1alpha1.FabricNamedStaticRoute{Spec: networkv1alpha1.BGPStaticRouteSpec{Destination: r}})
	}
	return rev
}

func TestActivationSettings(t *testing.T) {
	rev := revisionWith("r", digestA, map[string]string{
		"upstream-1": "203.0.113.1", "upstream-2": "2001:db8::0:1", "maint": "203.0.113.2",
		"optional": "203.0.113.3", "unnumbered": "eth0",
	}, "192.0.2.1/24", prefixA, "2001:db8:100::/48")
	policy := effectivePolicy(&networkv1alpha1.FabricRolloutPolicy{Spec: networkv1alpha1.FabricRolloutPolicySpec{
		StabilizationSeconds: 30,
		OptionalPeers:        []networkv1alpha1.LocalObjectRef{{Name: "optional"}},
		MaintenancePeers:     []networkv1alpha1.LocalObjectRef{{Name: "maint"}},
	}})
	got := activationSettings(policy, rev)
	if !slices.Equal(got.RequiredPeers, []string{"2001:db8::1", "203.0.113.1"}) {
		t.Errorf("required peers %v", got.RequiredPeers)
	}
	if !slices.Equal(got.RequiredStaticRoutes, []string{prefixA, "2001:db8:100::/48"}) {
		t.Errorf("required static routes %v", got.RequiredStaticRoutes)
	}
	if got.StabilizationSeconds != 30 || got.ApplyTimeoutSeconds != defaultApplyTimeout ||
		got.OfflineBootSeconds != defaultOfflineBoot {
		t.Errorf("timers %+v", got)
	}
}

func committedDeployment(epoch int64,
	active *networkv1alpha1.FabricRouterRevision) *networkv1alpha1.FabricRouterDeployment {
	d := &networkv1alpha1.FabricRouterDeployment{ObjectMeta: metav1.ObjectMeta{Name: "d", Namespace: testNS,
		UID: "d-uid"}}
	d.Spec.ActivationEpoch = epoch
	d.Spec.ActiveRevisionRef = &networkv1alpha1.LocalObjectRef{Name: active.Name}
	d.Spec.ActivationDependencyDigest = active.Spec.ActivationDependencyDigest
	d.Status.AppliedEpoch, d.Status.AppliedRevision = epoch, active.Name
	d.Status.AppliedDigest = active.Spec.ActivationDependencyDigest
	return d
}

func TestPromote(t *testing.T) {
	r1, r2 := revisionWith("r-aaaaaaaaaa", digestA, nil), revisionWith("r-bbbbbbbbbb", digestB, nil)
	auth := &networkv1alpha1.FabricReleaseAuthorization{ObjectMeta: metav1.ObjectMeta{Name: relName, UID: relUID}}

	d := committedDeployment(3, r1)
	d.Spec.Recovery = &networkv1alpha1.FabricRecovery{RevokedPrefixes: []string{prefixB}}
	spec := promote(d, r2, auth, networkv1alpha1.FabricReleaseTarget{}, &networkv1alpha1.FabricActivationSettings{})
	if spec.ActivationEpoch != 4 || spec.ActiveRevisionRef.Name != r2.Name || spec.ActivationDependencyDigest != digestB ||
		spec.AuthorizationRef.UID != relUID {
		t.Fatalf("promoted = %+v", spec)
	}
	if spec.Recovery.TargetRevisionRef.Name != r1.Name || spec.Recovery.TargetDependencyDigest != digestA ||
		!slices.Equal(spec.Recovery.RevokedPrefixes, []string{prefixB}) {
		t.Errorf("recovery = %+v", spec.Recovery)
	}
	if d.Spec.ActivationEpoch != 3 {
		t.Error("promote changed the deployment it read")
	}

	// Not committed: the earlier recovery target stands.
	uncommitted := committedDeployment(3, r1)
	uncommitted.Status.AppliedEpoch = 2
	uncommitted.Spec.Recovery = &networkv1alpha1.FabricRecovery{
		TargetRevisionRef: &networkv1alpha1.LocalObjectRef{Name: "r-older"}, TargetDependencyDigest: digestB,
	}
	if got := promote(uncommitted, r2, auth, networkv1alpha1.FabricReleaseTarget{},
		nil).Recovery.TargetRevisionRef.Name; got != "r-older" {
		t.Errorf("recovery target %s for an uncommitted epoch", got)
	}

	// An emergency withdrawal revokes what it withdraws.
	ew := auth.DeepCopy()
	ew.Spec.Type = networkv1alpha1.FabricReleaseTypeEmergencyWithdrawal
	ew.Spec.WithdrawnPrefixes = []string{prefixA, prefixB}
	got := promote(d, r2, ew, networkv1alpha1.FabricReleaseTarget{}, nil).Recovery.RevokedPrefixes
	if !slices.Equal(got, []string{prefixB, prefixA}) {
		t.Errorf("revoked after withdrawal %v", got)
	}
	if r := promote(d, r2, auth, networkv1alpha1.FabricReleaseTarget{Retire: true}, nil).Recovery; !r.Retired {
		t.Error("a retiring promotion did not retire the router")
	}
}

func TestStateOf(t *testing.T) {
	r1 := revisionWith("r-aaaaaaaaaa", digestA, nil)
	auth := &networkv1alpha1.FabricReleaseAuthorization{ObjectMeta: metav1.ObjectMeta{Name: relName, UID: relUID}}
	target := networkv1alpha1.FabricReleaseTarget{Revision: r1.Name}
	now := time.Now()
	promoted := func(stage networkv1alpha1.FabricActivationStage, heartbeat time.Duration,
		applied bool) *networkv1alpha1.FabricRouterDeployment {
		d := committedDeployment(2, r1)
		if !applied {
			d.Status.AppliedEpoch = 1
		}
		d.Spec.AuthorizationRef = &networkv1alpha1.FabricObjectIdentity{Name: relName, UID: relUID}
		hb := metav1.NewTime(now.Add(-heartbeat))
		d.Status.HeartbeatTime = &hb
		if stage != "" {
			d.Status.Epochs = []networkv1alpha1.FabricEpochStatus{{Epoch: 2, Stage: stage}}
		}
		return d
	}
	for _, tc := range []struct {
		name string
		d    *networkv1alpha1.FabricRouterDeployment
		want targetState
	}{
		{"not promoted", committedDeployment(1, r1), targetWaiting},
		{"accepted", promoted(networkv1alpha1.FabricStageAccepted, time.Second, false), targetActivating},
		{"committed", promoted(networkv1alpha1.FabricStageCommitted, time.Second, true), targetCommitted},
		{"committed stage, applied lagging", promoted(networkv1alpha1.FabricStageCommitted, time.Second, false),
			targetActivating},
		{"recovered", promoted(networkv1alpha1.FabricStageRecovered, time.Second, false), targetFailed},
		{"failed", promoted(networkv1alpha1.FabricStageApplyFailed, time.Second, false), targetFailed},
		{"silent", promoted(networkv1alpha1.FabricStageAccepted, time.Hour, false), targetSilent},
		{"no report yet", promoted("", time.Hour, false), targetSilent},
	} {
		if got := stateOf(tc.d, auth, target, time.Minute, now); got != tc.want {
			t.Errorf("%s: state %d, want %d", tc.name, got, tc.want)
		}
	}
}

// TestReleaseConcurrency: within one failure domain at most maxUnavailable
// routers activate at once; other domains proceed in parallel.
func TestReleaseConcurrency(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = networkv1alpha1.AddToScheme(scheme)
	rev := revisionWith("edge-aaaaaaaaaa", digestA, nil)
	auth := &networkv1alpha1.FabricReleaseAuthorization{
		ObjectMeta: metav1.ObjectMeta{Namespace: testNS, Name: relName, UID: relUID,
			Finalizers: []string{ReleaseFinalizer}},
		Spec: networkv1alpha1.FabricReleaseAuthorizationSpec{
			Type: networkv1alpha1.FabricReleaseTypeRelease, RoutingDomain: testDomain, FleetReleaseID: relName, FleetSequence: 1,
		},
		Status: networkv1alpha1.FabricReleaseAuthorizationStatus{Phase: networkv1alpha1.FabricReleasePhaseStarted,
			StartedAt: &metav1.Time{Time: time.Now()}},
	}
	zones := map[string]string{"a1": "a", "a2": "a", "a3": "a", "b1": "b", "b2": "b"}
	objs := make([]client.Object, 0, 2*len(zones)+2)
	for name, zone := range zones {
		objs = append(objs, &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name,
			Labels: map[string]string{defaultFailureDomainLabel: zone}}})
		d := &networkv1alpha1.FabricRouterDeployment{
			ObjectMeta: metav1.ObjectMeta{Namespace: testNS, Name: name, UID: types.UID(name + "-uid")},
			Spec: networkv1alpha1.FabricRouterDeploymentSpec{
				RouterRef: networkv1alpha1.FabricObjectIdentity{Name: testRouter, UID: "router-uid"},
				Target:    networkv1alpha1.FabricNodeIdentity{NodeName: name, NodeUID: name + "-node"},
				Source:    networkv1alpha1.FabricConfigSourceCRD,
			},
		}
		objs = append(objs, d)
		auth.Spec.Deployments = append(auth.Spec.Deployments, networkv1alpha1.FabricReleaseTarget{
			Deployment: name, DeploymentUID: name + "-uid", Revision: rev.Name, ActivationDependencyDigest: digestA,
		})
	}
	rev.Labels = map[string]string{routerLabel: testRouter}
	objs = append(objs, rev, auth)
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).
		WithStatusSubresource(&networkv1alpha1.FabricReleaseAuthorization{},
			&networkv1alpha1.FabricRouterDeployment{}).Build()
	r := &ReleaseReconciler{Client: c}
	ctx := context.Background()

	promoted := func() map[string]int {
		out := map[string]int{}
		for name, zone := range zones {
			d := &networkv1alpha1.FabricRouterDeployment{}
			if err := c.Get(ctx, client.ObjectKey{Namespace: testNS, Name: name}, d); err != nil {
				t.Fatal(err)
			}
			if d.Spec.ActivationEpoch > 0 {
				out[zone]++
			}
		}
		return out
	}
	reconcile := func() {
		t.Helper()
		if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(auth)}); err != nil {
			t.Fatal(err)
		}
	}
	commit := func(name string) {
		t.Helper()
		d := &networkv1alpha1.FabricRouterDeployment{}
		if err := c.Get(ctx, client.ObjectKey{Namespace: testNS, Name: name}, d); err != nil {
			t.Fatal(err)
		}
		hb := metav1.Now()
		d.Status = networkv1alpha1.FabricRouterDeploymentStatus{
			HeartbeatTime: &hb, AppliedEpoch: 1, AppliedRevision: rev.Name, AppliedDigest: digestA,
			Epochs: []networkv1alpha1.FabricEpochStatus{{Epoch: 1, Revision: rev.Name,
				Stage: networkv1alpha1.FabricStageCommitted}},
		}
		if err := c.Status().Update(ctx, d); err != nil {
			t.Fatal(err)
		}
	}
	// Heartbeats keep in-flight routers from looking silent.
	beat := func() {
		for name := range zones {
			d := &networkv1alpha1.FabricRouterDeployment{}
			_ = c.Get(ctx, client.ObjectKey{Namespace: testNS, Name: name}, d)
			if d.Spec.ActivationEpoch > 0 && d.Status.HeartbeatTime == nil {
				hb := metav1.Now()
				d.Status.HeartbeatTime = &hb
				_ = c.Status().Update(ctx, d)
			}
		}
	}

	reconcile()
	if got := promoted(); got["a"] != 1 || got["b"] != 1 {
		t.Fatalf("first wave promoted %v, want one per zone", got)
	}
	beat()
	reconcile()
	if got := promoted(); got["a"] != 1 || got["b"] != 1 {
		t.Fatalf("promoted %v while each zone had one in flight", got)
	}
	for range 3 {
		for name := range zones {
			d := &networkv1alpha1.FabricRouterDeployment{}
			_ = c.Get(ctx, client.ObjectKey{Namespace: testNS, Name: name}, d)
			if d.Spec.ActivationEpoch > 0 {
				commit(name)
			}
		}
		reconcile()
		beat()
	}
	if got := promoted(); got["a"] != 3 || got["b"] != 2 {
		t.Fatalf("promoted %v after every wave committed", got)
	}
	for name := range zones {
		commit(name)
	}
	reconcile()
	final := &networkv1alpha1.FabricReleaseAuthorization{}
	if err := c.Get(ctx, client.ObjectKeyFromObject(auth), final); err != nil {
		t.Fatal(err)
	}
	if final.Status.Phase != networkv1alpha1.FabricReleasePhaseCompleted {
		t.Errorf("phase %s, want Completed", final.Status.Phase)
	}
}

// TestPromoteReactivation: re-activating the committed revision is a new
// epoch with no recovery target, not even the one the deployment had,
// which a rollback may have abandoned, and carries every revocation over.
func TestPromoteReactivation(t *testing.T) {
	r1, r2 := revisionWith("r-aaaaaaaaaa", digestA, nil), revisionWith("r-bbbbbbbbbb", digestB, nil)
	auth := &networkv1alpha1.FabricReleaseAuthorization{ObjectMeta: metav1.ObjectMeta{Name: relName, UID: relUID}}
	d := committedDeployment(4, r2)
	d.Spec.Recovery = &networkv1alpha1.FabricRecovery{
		TargetRevisionRef: &networkv1alpha1.LocalObjectRef{Name: r1.Name}, TargetDependencyDigest: digestA,
		RevokedPrefixes:    []string{prefixB},
		RevokedCredentials: []networkv1alpha1.FabricObjectIdentity{{Name: "old", UID: "old-uid"}},
	}
	target := networkv1alpha1.FabricReleaseTarget{Revision: r2.Name, ActivationDependencyDigest: digestB,
		Reactivate: true}
	spec := promote(d, r2, auth, target, &networkv1alpha1.FabricActivationSettings{})
	if spec.ActivationEpoch != 5 || spec.ActiveRevisionRef.Name != r2.Name || spec.AuthorizationRef.UID != relUID {
		t.Fatalf("re-activated = %+v", spec)
	}
	r := spec.Recovery
	if r.TargetRevisionRef != nil || r.TargetDependencyDigest != "" {
		t.Errorf("recovery target %+v, want none", r)
	}
	if !slices.Equal(r.RevokedPrefixes, []string{prefixB}) || len(r.RevokedCredentials) != 1 {
		t.Errorf("revocations %+v", r)
	}

	// Never the earlier target, even read before the status caught up.
	lagging := committedDeployment(4, r2)
	lagging.Status.AppliedEpoch = 3
	lagging.Spec.Recovery = &networkv1alpha1.FabricRecovery{
		TargetRevisionRef: &networkv1alpha1.LocalObjectRef{Name: r1.Name}, TargetDependencyDigest: digestA,
	}
	if r := promote(lagging, r2, auth, target, nil).Recovery; r.TargetRevisionRef != nil {
		t.Errorf("recovery target %s for a re-activation", r.TargetRevisionRef.Name)
	}

	// The same promotion without re-activation recovers to what runs:
	// here the revision itself, so none either; to another, that one.
	target.Reactivate = false
	if r := promote(d, r2, auth, target, nil).Recovery; r.TargetRevisionRef != nil {
		t.Errorf("recovery target %s, the revision being promoted", r.TargetRevisionRef.Name)
	}
	if r := promote(d, r1, auth, target, nil).Recovery; r.TargetRevisionRef == nil ||
		r.TargetRevisionRef.Name != r2.Name {
		t.Errorf("recovery %+v for an ordinary promotion, want %s", r, r2.Name)
	}
}

// TestStateOfReactivation: a target the deployment runs, committed, is
// done at once unless it re-activates; then it waits for its promotion,
// or behind an epoch still activating.
func TestStateOfReactivation(t *testing.T) {
	r1 := revisionWith("r-aaaaaaaaaa", digestA, nil)
	auth := &networkv1alpha1.FabricReleaseAuthorization{ObjectMeta: metav1.ObjectMeta{Name: relName, UID: relUID}}
	d := committedDeployment(2, r1)
	d.Spec.AuthorizationRef = &networkv1alpha1.FabricObjectIdentity{Name: "earlier", UID: "earlier-uid"}
	target := networkv1alpha1.FabricReleaseTarget{Revision: r1.Name, ActivationDependencyDigest: digestA}
	if got := stateOf(d, auth, target, time.Minute, time.Now()); got != targetCommitted {
		t.Errorf("the running revision: state %d, want committed", got)
	}
	target.Reactivate = true
	if got := stateOf(d, auth, target, time.Minute, time.Now()); got != targetWaiting {
		t.Errorf("re-activating the running revision: state %d, want waiting", got)
	}
	d.Status.AppliedEpoch = 1
	if got := stateOf(d, auth, target, time.Minute, time.Now()); got != targetBlocked {
		t.Errorf("re-activating behind an epoch in flight: state %d, want blocked", got)
	}
	// Promoted under the release, its outcome is read as any other's.
	d = committedDeployment(3, r1)
	d.Spec.AuthorizationRef = &networkv1alpha1.FabricObjectIdentity{Name: relName, UID: relUID}
	d.Status.Epochs = []networkv1alpha1.FabricEpochStatus{{Epoch: 3, Stage: networkv1alpha1.FabricStageCommitted}}
	if got := stateOf(d, auth, target, time.Minute, time.Now()); got != targetCommitted {
		t.Errorf("re-activated and committed: state %d, want committed", got)
	}
}
