// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package rollout

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	ctrlconfig "sigs.k8s.io/controller-runtime/pkg/config"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/yaml"

	networkv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	"go.datum.net/galactic/internal/fabric/routing/controller"
	"go.datum.net/galactic/internal/fabric/routing/frrimport"
)

const (
	testNS    = "galactic-system"
	testNode  = "edge-a"
	testClass = "fabric-frr"

	testDomain = "fabric"
	testRouter = "edge"
)

// startRollout runs the revision, deployment and release controllers
// against a real API server holding the stack's CRDs, so every write the
// rollout manager makes passes the CRDs' admission rules.
func startRollout(t *testing.T) client.Client {
	t.Helper()
	return startRolloutAs(t, false)
}

// startRolloutAs is startRollout; with shippedRBAC the controllers run as
// the fabric-router-controller ServiceAccount, bound only to the RBAC in
// config/fabric-router-controller, so a rule the code needs and the
// manifest lacks fails the test.
func startRolloutAs(t *testing.T, shippedRBAC bool) client.Client {
	t.Helper()
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("set KUBEBUILDER_ASSETS for the rollout envtest")
	}
	paths, err := filepath.Glob(filepath.Join("..", "..", "..", "..", "config", "crd", "galactic.datumapis.com_*.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var crds []*apiextensionsv1.CustomResourceDefinition
	for _, p := range paths {
		base := filepath.Base(p)
		if !strings.Contains(base, "_bgp") && !strings.Contains(base, "_frr") && !strings.Contains(base, "_fabric") {
			continue
		}
		data, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		crd := &apiextensionsv1.CustomResourceDefinition{}
		if err := yaml.Unmarshal(data, crd); err != nil {
			t.Fatal(err)
		}
		crds = append(crds, crd)
	}
	env := &envtest.Environment{CRDs: crds}
	cfg, err := env.Start()
	if err != nil {
		t.Fatal(err)
	}
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = networkv1alpha1.AddToScheme(scheme)
	mgrCfg := cfg
	if shippedRBAC {
		mgrCfg = asControllerServiceAccount(t, cfg)
	}
	skip := true
	mgr, err := ctrl.NewManager(mgrCfg, ctrl.Options{
		Scheme: scheme, Metrics: metricsserver.Options{BindAddress: "0"},
		// Each test starts its own manager in this process.
		Controller: ctrlconfig.Controller{SkipNameValidation: &skip},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := (&controller.Reconciler{Client: mgr.GetClient()}).SetupWithManager(mgr); err != nil {
		t.Fatal(err)
	}
	if err := (&DeploymentReconciler{Client: mgr.GetClient()}).SetupWithManager(mgr); err != nil {
		t.Fatal(err)
	}
	if err := (&ReleaseReconciler{Client: mgr.GetClient()}).SetupWithManager(mgr); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := mgr.Start(ctx); err != nil {
			t.Errorf("manager: %v", err)
		}
	}()
	t.Cleanup(func() {
		cancel()
		<-done
		if err := env.Stop(); err != nil {
			t.Errorf("stop API: %v", err)
		}
	})
	c, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// seed creates the synthetic edge router and everything it references,
// and returns the name of one of its peers.
func seed(t *testing.T, c client.Client) string {
	t.Helper()
	text, err := os.ReadFile(filepath.Join("..", "testdata", "edge-a.conf"))
	if err != nil {
		t.Fatal(err)
	}
	o, err := frrimport.Import(strings.NewReader(string(text)), frrimport.Options{
		Namespace: testNS, NodeName: testNode, RouterClassName: testClass,
	})
	if err != nil {
		t.Fatal(err)
	}
	objs := make([]client.Object, 0, 5+len(o.Profiles)+len(o.Policies)+len(o.PrefixLists)+len(o.CommunitySets)+
		len(o.Peers)+len(o.Advertisements)+len(o.StaticRoutes))
	objs = append(objs,
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: testNS}},
		&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: testNode,
			Labels: map[string]string{defaultFailureDomainLabel: "zone-a"}}},
		&networkv1alpha1.FRRRouterParameters{ObjectMeta: metav1.ObjectMeta{Name: testClass}, Spec: o.Parameters},
		&networkv1alpha1.BGPRouterClass{ObjectMeta: metav1.ObjectMeta{Name: testClass},
			Spec: networkv1alpha1.BGPRouterClassSpec{
				ControllerName: networkv1alpha1.FabricRouterControllerName,
				ParametersRef: &networkv1alpha1.BGPRouterClassParametersRef{
					Group: networkv1alpha1.GroupVersion.Group, Kind: networkv1alpha1.FRRRouterParametersKind, Name: testClass,
				},
			}},
	)
	for _, x := range o.Profiles {
		objs = append(objs, x)
	}
	for _, x := range o.Policies {
		objs = append(objs, x)
	}
	for _, x := range o.PrefixLists {
		objs = append(objs, x)
	}
	for _, x := range o.CommunitySets {
		objs = append(objs, x)
	}
	for _, x := range o.Peers {
		objs = append(objs, x)
	}
	for _, x := range o.Advertisements {
		objs = append(objs, x)
	}
	for _, x := range o.StaticRoutes {
		objs = append(objs, x)
	}
	objs = append(objs, o.Router)
	for _, x := range objs {
		if err := c.Create(context.Background(), x); err != nil && !apierrors.IsAlreadyExists(err) {
			t.Fatalf("create %T %s: %v", x, x.GetName(), err)
		}
	}
	return o.Peers[0].Name
}

// asControllerServiceAccount applies config/fabric-router-controller's
// ServiceAccount and RBAC and returns cfg impersonating that account.
func asControllerServiceAccount(t *testing.T, cfg *rest.Config) *rest.Config {
	t.Helper()
	admin, err := client.New(cfg, client.Options{})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := admin.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: testNS}}); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join("..", "..", "..", "..", "config", "fabric-router-controller")
	for _, file := range []string{"serviceaccount.yaml", "rbac.yaml"} {
		data, err := os.ReadFile(filepath.Join(dir, file))
		if err != nil {
			t.Fatal(err)
		}
		for _, doc := range strings.Split(string(data), "\n---\n") {
			obj := &unstructured.Unstructured{}
			if err := yaml.Unmarshal([]byte(doc), &obj.Object); err != nil {
				t.Fatal(err)
			}
			if len(obj.Object) == 0 {
				continue
			}
			if err := admin.Create(ctx, obj); err != nil {
				t.Fatalf("apply %s %s: %v", obj.GetKind(), obj.GetName(), err)
			}
		}
	}
	impersonated := rest.CopyConfig(cfg)
	impersonated.Impersonate = rest.ImpersonationConfig{
		UserName: "system:serviceaccount:" + testNS + ":fabric-router-controller",
		Groups:   []string{"system:serviceaccounts", "system:serviceaccounts:" + testNS, "system:authenticated"},
	}
	return impersonated
}

func eventually(t *testing.T, c client.Client, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s; rollout state:%s", what, rolloutState(c))
}

// rolloutState renders what the controllers last wrote and what the node
// agent last reported, so a timed-out wait names the state that stalled
// instead of only the wait.
func rolloutState(c client.Client) string {
	ctx := context.Background()
	var b strings.Builder
	d := &networkv1alpha1.FabricRouterDeployment{}
	if err := c.Get(ctx, client.ObjectKey{Namespace: testNS, Name: testNode}, d); err != nil {
		return fmt.Sprintf("\n  deployment %s: %v", testNode, err)
	}
	heartbeat := "<none>"
	if d.Status.HeartbeatTime != nil {
		heartbeat = d.Status.HeartbeatTime.UTC().Format(time.RFC3339Nano)
	}
	fmt.Fprintf(&b, "\n  deployment %s: source=%s epoch=%d activeRevision=%v authorization=%v",
		testNode, d.Spec.Source, d.Spec.ActivationEpoch, d.Spec.ActiveRevisionRef, d.Spec.AuthorizationRef)
	fmt.Fprintf(&b, " heartbeat=%s epochs=%v applied={epoch=%d revision=%q digest=%q}",
		heartbeat, d.Status.Epochs, d.Status.AppliedEpoch, d.Status.AppliedRevision, d.Status.AppliedDigest)
	releases := &networkv1alpha1.FabricReleaseAuthorizationList{}
	if err := c.List(ctx, releases, client.InNamespace(testNS)); err != nil {
		fmt.Fprintf(&b, "\n  releases: %v", err)
		return b.String()
	}
	for _, a := range releases.Items {
		fmt.Fprintf(&b, "\n  release %s: phase=%q outstanding=%t conditions=%v",
			a.Name, a.Status.Phase, a.Status.Outstanding(), a.Status.Conditions)
	}
	return b.String()
}

// TestRolloutState keeps the timeout diagnostic honest: it must name the
// deployment epoch and every release phase, which is what tells a stalled
// wait apart from one the controllers never advanced.
func TestRolloutState(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = networkv1alpha1.AddToScheme(scheme)
	dep := &networkv1alpha1.FabricRouterDeployment{ObjectMeta: metav1.ObjectMeta{Namespace: testNS, Name: testNode}}
	dep.Spec.ActivationEpoch = 2
	dep.Status.AppliedEpoch = 1
	release := &networkv1alpha1.FabricReleaseAuthorization{ObjectMeta: metav1.ObjectMeta{Namespace: testNS, Name: "r1"}}
	release.Status.Phase = networkv1alpha1.FabricReleasePhaseStarted
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(dep, release).Build()
	got := rolloutState(c)
	for _, want := range []string{
		"deployment edge-a", "epoch=2", "applied={epoch=1", "release r1", "phase=\"Started\"",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("rolloutState() missing %q in %q", want, got)
		}
	}
}

func getDeployment(t *testing.T, c client.Client) *networkv1alpha1.FabricRouterDeployment {
	t.Helper()
	d := &networkv1alpha1.FabricRouterDeployment{}
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: testNS, Name: testNode}, d); err != nil {
		t.Fatal(err)
	}
	return d
}

func getRelease(t *testing.T, c client.Client, name string) *networkv1alpha1.FabricReleaseAuthorization {
	t.Helper()
	a := &networkv1alpha1.FabricReleaseAuthorization{}
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: testNS, Name: name}, a); err != nil {
		t.Fatal(err)
	}
	return a
}

func latestRevision(t *testing.T, c client.Client) *networkv1alpha1.FabricRouterRevision {
	t.Helper()
	r := &networkv1alpha1.BGPRouter{}
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: testNS, Name: testNode}, r); err != nil {
		t.Fatal(err)
	}
	rev := &networkv1alpha1.FabricRouterRevision{}
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: testNS, Name: r.Status.Fabric.LatestRevision},
		rev); err != nil {
		t.Fatal(err)
	}
	return rev
}

func newRelease(name string, seq int64, dep *networkv1alpha1.FabricRouterDeployment,
	rev *networkv1alpha1.FabricRouterRevision) *networkv1alpha1.FabricReleaseAuthorization {
	return &networkv1alpha1.FabricReleaseAuthorization{
		ObjectMeta: metav1.ObjectMeta{Namespace: testNS, Name: name},
		Spec: networkv1alpha1.FabricReleaseAuthorizationSpec{
			Type: networkv1alpha1.FabricReleaseTypeRelease, RoutingDomain: testDomain, FleetReleaseID: name, FleetSequence: seq,
			Deployments: []networkv1alpha1.FabricReleaseTarget{{
				Deployment: dep.Name, DeploymentUID: string(dep.UID),
				Revision: rev.Name, ActivationDependencyDigest: rev.Spec.ActivationDependencyDigest,
			}},
		},
	}
}

func phase(c client.Client, name string) networkv1alpha1.FabricReleasePhase {
	a := &networkv1alpha1.FabricReleaseAuthorization{}
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: testNS, Name: name}, a); err != nil {
		return "missing"
	}
	return a.Status.Phase
}

// report writes what a node agent reports for the deployment's active
// epoch reaching stage, running applied.
func report(t *testing.T, c client.Client, stage networkv1alpha1.FabricActivationStage,
	applied *networkv1alpha1.FabricRouterRevision) {
	t.Helper()
	d := getDeployment(t, c)
	now := metav1.Now()
	d.Status.HeartbeatTime = &now
	d.Status.Epochs = []networkv1alpha1.FabricEpochStatus{{
		Epoch: d.Spec.ActivationEpoch, Revision: d.Spec.ActiveRevisionRef.Name, Stage: stage,
	}}
	if applied != nil {
		d.Status.AppliedEpoch = d.Spec.ActivationEpoch
		d.Status.AppliedRevision = applied.Name
		d.Status.AppliedDigest = applied.Spec.ActivationDependencyDigest
	}
	if err := c.Status().Update(context.Background(), d); err != nil {
		t.Fatal(err)
	}
}

// TestRolloutEndToEnd drives one router through a refused release, a
// committed one, a failed one and its recovery, playing the node agent.
func TestRolloutEndToEnd(t *testing.T) {
	rolloutEndToEnd(t, startRollout(t))
}

// TestRolloutWithShippedRBAC runs the same lifecycle with the controllers
// limited to the RBAC the manifests ship.
func TestRolloutWithShippedRBAC(t *testing.T) {
	rolloutEndToEnd(t, startRolloutAs(t, true))
}

func rolloutEndToEnd(t *testing.T, c client.Client) {
	peer := seed(t, c)
	ctx := context.Background()

	eventually(t, c, "the deployment with the first revision as candidate", func() bool {
		d := &networkv1alpha1.FabricRouterDeployment{}
		err := c.Get(ctx, client.ObjectKey{Namespace: testNS, Name: testNode}, d)
		return err == nil && d.Spec.CandidateRevisionRef != nil
	})
	dep := getDeployment(t, c)
	rev1 := latestRevision(t, c)
	if dep.Spec.Source != networkv1alpha1.FabricConfigSourceConfigMap || dep.Spec.ActivationEpoch != 0 ||
		dep.Spec.CandidateRevisionRef.Name != rev1.Name || dep.Spec.Target.NodeName != testNode {
		t.Fatalf("new deployment = %+v", dep.Spec)
	}

	// A release for a deployment still on its ConfigMap never starts.
	if err := c.Create(ctx, newRelease("r0", 1, dep, rev1)); err != nil {
		t.Fatal(err)
	}
	eventually(t, c, "r0 cancelled", func() bool { return phase(c, "r0") == networkv1alpha1.FabricReleasePhaseCancelled })
	if c := meta.FindStatusCondition(getRelease(t, c, "r0").Status.Conditions, ConditionProgressing); c == nil ||
		c.Reason != reasonInvalidTarget {
		t.Errorf("r0 condition = %+v", c)
	}

	// The operator moves the node to CRD; release r1 promotes rev1.
	dep = getDeployment(t, c)
	dep.Spec.Source = networkv1alpha1.FabricConfigSourceCRD
	if err := c.Update(ctx, dep); err != nil {
		t.Fatal(err)
	}
	if err := c.Create(ctx, newRelease("r1", 2, dep, rev1)); err != nil {
		t.Fatal(err)
	}
	eventually(t, c, "the epoch 1 promotion", func() bool { return getDeployment(t, c).Spec.ActivationEpoch == 1 })
	dep = getDeployment(t, c)
	r1 := getRelease(t, c, "r1")
	if dep.Spec.ActiveRevisionRef.Name != rev1.Name || dep.Spec.AuthorizationRef.UID != string(r1.UID) ||
		dep.Spec.Activation == nil || len(dep.Spec.Activation.RequiredPeers) == 0 {
		t.Fatalf("promoted spec = %+v", dep.Spec)
	}
	if !strings.Contains(strings.Join(r1.Finalizers, ","), ReleaseFinalizer) {
		t.Error("a started release has no finalizer")
	}
	report(t, c, networkv1alpha1.FabricStageCommitted, rev1)
	eventually(t, c, "r1 completed", func() bool { return phase(c, "r1") == networkv1alpha1.FabricReleasePhaseCompleted })
	eventually(t, c, "r1's finalizer removed", func() bool { return len(getRelease(t, c, "r1").Finalizers) == 0 })

	// A new revision: change a peer's description.
	p := &networkv1alpha1.BGPPeer{}
	if err := c.Get(ctx, client.ObjectKey{Namespace: testNS, Name: peer}, p); err != nil {
		t.Fatal(err)
	}
	p.Spec.Description = "CHANGED"
	if err := c.Update(ctx, p); err != nil {
		t.Fatal(err)
	}
	eventually(t, c, "a second revision", func() bool { return latestRevision(t, c).Name != rev1.Name })
	rev2 := latestRevision(t, c)
	eventually(t, c, "the candidate follows", func() bool {
		return getDeployment(t, c).Spec.CandidateRevisionRef.Name == rev2.Name
	})

	// A release older than one already started is superseded.
	if err := c.Create(ctx, newRelease("r-old", 1, dep, rev2)); err != nil {
		t.Fatal(err)
	}
	eventually(t, c, "r-old cancelled", func() bool {
		return phase(c,
			"r-old") == networkv1alpha1.FabricReleasePhaseCancelled
	})

	// r2 promotes rev2 with rev1 as its recovery target, and fails.
	if err := c.Create(ctx, newRelease("r2", 3, dep, rev2)); err != nil {
		t.Fatal(err)
	}
	eventually(t, c, "the epoch 2 promotion", func() bool { return getDeployment(t, c).Spec.ActivationEpoch == 2 })
	dep = getDeployment(t, c)
	if r := dep.Spec.Recovery; r == nil || r.TargetRevisionRef == nil || r.TargetRevisionRef.Name != rev1.Name ||
		r.TargetDependencyDigest != rev1.Spec.ActivationDependencyDigest {
		t.Fatalf("recovery = %+v", dep.Spec.Recovery)
	}

	// While r2 is outstanding, r3 waits.
	if err := c.Create(ctx, newRelease("r3", 4, dep, rev1)); err != nil {
		t.Fatal(err)
	}
	eventually(t, c, "r3 pending", func() bool { return phase(c, "r3") == networkv1alpha1.FabricReleasePhasePending })

	report(t, c, networkv1alpha1.FabricStageRecovered, rev1)
	eventually(t, c, "r2 failed and recovery verified", func() bool {
		a := getRelease(t, c, "r2")
		return a.Status.Phase == networkv1alpha1.FabricReleasePhaseFailed && a.Status.RecoveryVerified
	})
	// r2 no longer blocks: r3 starts and promotes rev1 again at epoch 3.
	eventually(t, c, "r3 promoting", func() bool { return getDeployment(t, c).Spec.ActivationEpoch == 3 })
	if r := getDeployment(t, c).Spec.Recovery; r == nil || r.TargetRevisionRef != nil {
		t.Errorf("a recovery to the revision being promoted: %+v", r)
	}

	// Every revision a deployment names survives pruning.
	for _, name := range []string{rev1.Name, rev2.Name} {
		if err := c.Get(ctx, client.ObjectKey{Namespace: testNS, Name: name},
			&networkv1alpha1.FabricRouterRevision{}); err != nil {
			t.Errorf("revision %s: %v", name, err)
		}
	}
}

// TestRolloutUnknownWhenSilent: a promoted router whose agent stops
// reporting moves its release to Unknown, and back when it reports.
func TestRolloutUnknownWhenSilent(t *testing.T) {
	c := startRollout(t)
	seed(t, c)
	ctx := context.Background()
	eventually(t, c, "the deployment", func() bool {
		return c.Get(ctx, client.ObjectKey{Namespace: testNS, Name: testNode},
			&networkv1alpha1.FabricRouterDeployment{}) == nil
	})
	dep := getDeployment(t, c)
	dep.Spec.Source = networkv1alpha1.FabricConfigSourceCRD
	if err := c.Update(ctx, dep); err != nil {
		t.Fatal(err)
	}
	rev := latestRevision(t, c)
	if err := c.Create(ctx, newRelease("silent", 1, dep, rev)); err != nil {
		t.Fatal(err)
	}
	eventually(t, c, "the promotion", func() bool { return getDeployment(t, c).Spec.ActivationEpoch == 1 })
	// No heartbeat at all: silent.
	eventually(t, c, "unknown", func() bool { return phase(c, "silent") == networkv1alpha1.FabricReleasePhaseUnknown })
	report(t, c, networkv1alpha1.FabricStageAccepted, nil)
	eventually(t, c, "started again", func() bool {
		return phase(c,
			"silent") == networkv1alpha1.FabricReleasePhaseStarted
	})
}

// TestRolloutReactivation re-activates the committed revision through the
// API server, as the shipped RBAC allows: the promotion to the same
// revision at a new epoch, with no recovery target, passes the
// deployment's admission rules, and the release completes once the node
// commits it. A release without re-activation completes at once, and a
// re-activation of a revision the router has since left is refused.
func TestRolloutReactivation(t *testing.T) {
	c := startRolloutAs(t, true)
	peer := seed(t, c)
	ctx := context.Background()
	eventually(t, c, "the deployment", func() bool {
		return c.Get(ctx, client.ObjectKey{Namespace: testNS, Name: testNode},
			&networkv1alpha1.FabricRouterDeployment{}) == nil
	})
	dep := getDeployment(t, c)
	dep.Spec.Source = networkv1alpha1.FabricConfigSourceCRD
	if err := c.Update(ctx, dep); err != nil {
		t.Fatal(err)
	}
	rev1 := latestRevision(t, c)
	if err := c.Create(ctx, newRelease("r1", 1, dep, rev1)); err != nil {
		t.Fatal(err)
	}
	eventually(t, c, "epoch 1", func() bool { return getDeployment(t, c).Spec.ActivationEpoch == 1 })
	report(t, c, networkv1alpha1.FabricStageCommitted, rev1)
	eventually(t, c, "r1 completed", func() bool { return phase(c, "r1") == networkv1alpha1.FabricReleasePhaseCompleted })

	p := &networkv1alpha1.BGPPeer{}
	if err := c.Get(ctx, client.ObjectKey{Namespace: testNS, Name: peer}, p); err != nil {
		t.Fatal(err)
	}
	p.Spec.Description = "CHANGED"
	if err := c.Update(ctx, p); err != nil {
		t.Fatal(err)
	}
	eventually(t, c, "a second revision", func() bool { return latestRevision(t, c).Name != rev1.Name })
	rev2 := latestRevision(t, c)
	if err := c.Create(ctx, newRelease("r2", 2, dep, rev2)); err != nil {
		t.Fatal(err)
	}
	eventually(t, c, "epoch 2", func() bool { return getDeployment(t, c).Spec.ActivationEpoch == 2 })
	report(t, c, networkv1alpha1.FabricStageCommitted, rev2)
	eventually(t, c, "r2 completed", func() bool { return phase(c, "r2") == networkv1alpha1.FabricReleasePhaseCompleted })

	// Written for rev1 before r2 moved the router on: refused, not a rollback.
	stale := newRelease("stale", 3, dep, rev1)
	stale.Spec.Deployments[0].Reactivate = true
	if err := c.Create(ctx, stale); err != nil {
		t.Fatal(err)
	}
	eventually(t, c, "stale cancelled", func() bool {
		return phase(c, "stale") == networkv1alpha1.FabricReleasePhaseCancelled
	})
	if cond := meta.FindStatusCondition(getRelease(t, c, "stale").Status.Conditions, ConditionProgressing); cond == nil ||
		cond.Reason != reasonInvalidTarget || !strings.Contains(cond.Message, "does not run revision "+rev1.Name) {
		t.Errorf("stale condition %+v", cond)
	}
	if d := getDeployment(t, c); d.Spec.ActivationEpoch != 2 || d.Spec.ActiveRevisionRef.Name != rev2.Name {
		t.Fatalf("a stale re-activation moved the router to epoch %d on %s", d.Spec.ActivationEpoch,
			d.Spec.ActiveRevisionRef.Name)
	}

	if err := c.Create(ctx, newRelease("again", 4, dep, rev2)); err != nil {
		t.Fatal(err)
	}
	eventually(t, c, "again completed", func() bool {
		return phase(c, "again") == networkv1alpha1.FabricReleasePhaseCompleted
	})
	if e := getDeployment(t, c).Spec.ActivationEpoch; e != 2 {
		t.Fatalf("a release without re-activation promoted to epoch %d", e)
	}

	re := newRelease("reactivate", 5, dep, rev2)
	re.Spec.Deployments[0].Reactivate = true
	if err := c.Create(ctx, re); err != nil {
		t.Fatal(err)
	}
	eventually(t, c, "the re-activation at epoch 3", func() bool { return getDeployment(t, c).Spec.ActivationEpoch == 3 })
	dep = getDeployment(t, c)
	if dep.Spec.ActiveRevisionRef.Name != rev2.Name || dep.Spec.AuthorizationRef.UID != string(getRelease(t, c,
		"reactivate").UID) {
		t.Fatalf("re-activated spec = %+v", dep.Spec)
	}
	if r := dep.Spec.Recovery; r != nil && r.TargetRevisionRef != nil {
		t.Errorf("recovery = %+v, want no target, not the earlier %s", dep.Spec.Recovery, rev1.Name)
	}
	report(t, c, networkv1alpha1.FabricStageCommitted, rev2)
	eventually(t, c, "reactivate completed", func() bool {
		return phase(c, "reactivate") == networkv1alpha1.FabricReleasePhaseCompleted
	})
}

// TestRolloutRefusesUnreadableCredential: with the shipped RBAC the
// controller cannot read Secrets outside its namespace, so a release there
// of a revision using a credential fails its target visibly, naming the
// deployment and the namespace, rather than retrying and blocking its
// routing domain.
func TestRolloutRefusesUnreadableCredential(t *testing.T) {
	c := startRolloutAs(t, true)
	seed(t, c)
	ctx := context.Background()
	eventually(t, c, "a revision", func() bool {
		r := &networkv1alpha1.BGPRouter{}
		return c.Get(ctx, client.ObjectKey{Namespace: testNS, Name: testNode}, r) == nil &&
			r.Status.Fabric != nil && r.Status.Fabric.LatestRevision != ""
	})
	const other = "elsewhere"
	src := latestRevision(t, c)
	if err := c.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: other}}); err != nil {
		t.Fatal(err)
	}
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: other, Name: secretName}}
	if err := c.Create(ctx, secret); err != nil {
		t.Fatal(err)
	}
	rev := &networkv1alpha1.FabricRouterRevision{
		ObjectMeta: metav1.ObjectMeta{Namespace: other, Name: src.Name, Labels: src.Labels},
		Spec:       *src.Spec.DeepCopy(),
	}
	rev.Spec.Configuration.Peers[0].Spec.AuthSecretRef = &networkv1alpha1.LocalSecretRef{Name: secretName}
	if err := c.Create(ctx, rev); err != nil {
		t.Fatal(err)
	}
	dep := &networkv1alpha1.FabricRouterDeployment{
		ObjectMeta: metav1.ObjectMeta{Namespace: other, Name: testNode},
		Spec: networkv1alpha1.FabricRouterDeploymentSpec{
			RouterRef: networkv1alpha1.FabricObjectIdentity{Name: testNode, UID: "elsewhere-router-uid"},
			Target:    networkv1alpha1.FabricNodeIdentity{NodeName: testNode, NodeUID: "elsewhere-node-uid"},
			Source:    networkv1alpha1.FabricConfigSourceCRD,
		},
	}
	if err := c.Create(ctx, dep); err != nil {
		t.Fatal(err)
	}
	rel := newRelease("unreadable", 1, dep, rev)
	rel.Namespace = other
	if err := c.Create(ctx, rel); err != nil {
		t.Fatal(err)
	}
	var cond *metav1.Condition
	eventually(t, c, "the release cancelled", func() bool {
		a := &networkv1alpha1.FabricReleaseAuthorization{}
		if err := c.Get(ctx, client.ObjectKey{Namespace: other, Name: rel.Name}, a); err != nil {
			return false
		}
		cond = meta.FindStatusCondition(a.Status.Conditions, ConditionProgressing)
		return a.Status.Phase == networkv1alpha1.FabricReleasePhaseCancelled
	})
	if cond == nil || cond.Reason != reasonInvalidTarget || !strings.Contains(cond.Message, "deployment "+testNode) ||
		!strings.Contains(cond.Message, "cannot read Secrets in namespace "+other) {
		t.Errorf("condition %+v, want InvalidTarget naming the deployment and namespace", cond)
	}
	got := &networkv1alpha1.FabricRouterDeployment{}
	if err := c.Get(ctx, client.ObjectKeyFromObject(dep), got); err != nil || got.Spec.ActivationEpoch != 0 {
		t.Errorf("deployment %+v, %v; want nothing promoted", got.Spec, err)
	}
}
