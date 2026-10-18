// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package metrics

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	networkv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
)

const (
	testNS     = "galactic-system"
	fabricKind = "fabric-frr"
	testRouter = "edge-a"
)

func newReader(t *testing.T, objs ...client.Object) client.Reader {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := networkv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build()
}

func ref(name string) *networkv1alpha1.LocalObjectRef {
	return &networkv1alpha1.LocalObjectRef{Name: name}
}

func cond(t, s, reason string) metav1.Condition {
	return metav1.Condition{Type: t, Status: metav1.ConditionStatus(s), Reason: reason}
}

func fleet() []client.Object {
	heartbeat := metav1.NewTime(time.Unix(1700000000, 0))
	until := metav1.NewTime(time.Unix(1700086400, 0))
	class := func(name, controller string) *networkv1alpha1.BGPRouterClass {
		return &networkv1alpha1.BGPRouterClass{ObjectMeta: metav1.ObjectMeta{Name: name},
			Spec: networkv1alpha1.BGPRouterClassSpec{ControllerName: controller}}
	}
	router := func(name, class, node string, conds ...metav1.Condition) *networkv1alpha1.BGPRouter {
		r := &networkv1alpha1.BGPRouter{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: testNS}}
		if class != "" {
			r.Spec.RouterClassName = &class
		}
		r.Spec.TargetRef.Name = node
		r.Status.Conditions = conds
		return r
	}
	release := func(name string, phase networkv1alpha1.FabricReleasePhase, verified bool) client.Object {
		return &networkv1alpha1.FabricReleaseAuthorization{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: testNS},
			Spec: networkv1alpha1.FabricReleaseAuthorizationSpec{
				Type: networkv1alpha1.FabricReleaseTypeRelease, RoutingDomain: "fabric",
			},
			Status: networkv1alpha1.FabricReleaseAuthorizationStatus{Phase: phase, RecoveryVerified: verified},
		}
	}
	return []client.Object{
		class(fabricKind, networkv1alpha1.FabricRouterControllerName),
		class("evpn", "galactic.datumapis.com/galactic-router"),
		router(testRouter, fabricKind, "node-a", cond("Accepted", "True", "Compiled")),
		router("edge-b", fabricKind, "node-b", cond("Accepted", "False", "UnresolvedRef")),
		// Not compiled yet: no Accepted condition, no series.
		router("edge-c", fabricKind, "node-c"),
		// Another implementation's router, and an unclassed one.
		router("tenant", "evpn", "node-a", cond("Accepted", "False", "Whatever")),
		router("plain", "", "node-a", cond("Accepted", "True", "Ready")),

		// On CRD, promoted, with a candidate waiting.
		&networkv1alpha1.FabricRouterDeployment{
			ObjectMeta: metav1.ObjectMeta{Name: testRouter, Namespace: testNS},
			Spec: networkv1alpha1.FabricRouterDeploymentSpec{
				Target: networkv1alpha1.FabricNodeIdentity{NodeName: "node-a"},
				Source: networkv1alpha1.FabricConfigSourceCRD, ActivationEpoch: 3,
				ActiveRevisionRef: ref("edge-a-1111111111"), CandidateRevisionRef: ref("edge-a-2222222222"),
			},
			Status: networkv1alpha1.FabricRouterDeploymentStatus{
				EffectiveSource: networkv1alpha1.FabricConfigSourceCRD, AppliedEpoch: 2,
				Epochs: []networkv1alpha1.FabricEpochStatus{
					{Epoch: 3, Stage: networkv1alpha1.FabricStageDegraded},
					{Epoch: 2, Stage: networkv1alpha1.FabricStageCommitted},
				},
				HeartbeatTime: &heartbeat, BootAuthorizedUntil: &until,
				Staged: &networkv1alpha1.FabricStagedRevision{
					Class: networkv1alpha1.FabricChangeSessionReset, LinesAdded: 4, LinesRemoved: 1,
				},
				Conditions: []metav1.Condition{
					cond("Accepted", "False", "FailedEpoch"),
					cond("Degraded", "True", "NoEligibleRecovery"),
					cond("Staged", "True", "Staged"),
					// Not a condition the agent writes: left out.
					cond("Other", "True", "Whatever"),
				},
			},
		},
		// Never reported, on its ConfigMap, candidate equal to active.
		&networkv1alpha1.FabricRouterDeployment{
			ObjectMeta: metav1.ObjectMeta{Name: "edge-b", Namespace: testNS},
			Spec: networkv1alpha1.FabricRouterDeploymentSpec{
				Target: networkv1alpha1.FabricNodeIdentity{NodeName: "node-b"},
				Source: networkv1alpha1.FabricConfigSourceConfigMap,
			},
		},

		release("r1", networkv1alpha1.FabricReleasePhaseCompleted, false),
		release("r2", networkv1alpha1.FabricReleasePhaseFailed, false),
		release("r3", networkv1alpha1.FabricReleasePhaseFailed, true),
		release("r4", "", false),
	}
}

// TestCollector reads a fleet with a promoted, degraded deployment, one
// that never reported, released and failed releases, and routers of
// several classes; testdata/fleet.prom is what it exports.
func TestCollector(t *testing.T) {
	c := &Collector{Reader: newReader(t, fleet()...), Rollout: true}
	c.leading.Store(true)
	want, err := os.Open(filepath.Join("testdata", "fleet.prom"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = want.Close() }()
	if err := testutil.CollectAndCompare(c, want); err != nil {
		t.Fatal(err)
	}
}

// TestCollectorWithoutRollout exports only compile results: without the
// rollout manager there are no deployments or releases to read.
func TestCollectorWithoutRollout(t *testing.T) {
	c := &Collector{Reader: newReader(t, fleet()...)}
	c.leading.Store(true)
	if n := testutil.CollectAndCount(c); n != 2 {
		t.Fatalf("got %d series, want the 2 router_accepted series", n)
	}
	if n := testutil.CollectAndCount(c, prefix+"router_accepted"); n != 2 {
		t.Fatalf("got %d router_accepted series, want 2", n)
	}
}

// TestCollectorStandby exports nothing until the manager starts it as the
// leader, and nothing again once leadership ends.
func TestCollectorStandby(t *testing.T) {
	c := &Collector{Reader: newReader(t, fleet()...), Rollout: true}
	if !c.NeedLeaderElection() {
		t.Fatal("the collector must run only on the leader")
	}
	if n := testutil.CollectAndCount(c); n != 0 {
		t.Fatalf("standby exported %d series, want none", n)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error)
	go func() { done <- c.Start(ctx) }()
	deadline := time.Now().Add(5 * time.Second)
	for !c.leading.Load() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if n := testutil.CollectAndCount(c); n == 0 {
		t.Fatal("leader exported nothing")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if n := testutil.CollectAndCount(c); n != 0 {
		t.Fatalf("former leader exported %d series, want none", n)
	}
}

// TestCollectorNoFabricClass reads no routers when no class names the
// fabric router controller.
func TestCollectorNoFabricClass(t *testing.T) {
	class := "evpn"
	r := &networkv1alpha1.BGPRouter{ObjectMeta: metav1.ObjectMeta{Name: "tenant", Namespace: testNS}}
	r.Spec.RouterClassName = &class
	r.Status.Conditions = []metav1.Condition{cond("Accepted", "False", "Whatever")}
	c := &Collector{Reader: newReader(t, r), Rollout: true}
	c.leading.Store(true)
	if n := testutil.CollectAndCount(c); n != 0 {
		t.Fatalf("got %d series from a cluster that does not route fabric through the API, want none", n)
	}
}
