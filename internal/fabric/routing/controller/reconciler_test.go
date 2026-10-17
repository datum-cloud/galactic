// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/yaml"

	networkv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	"go.datum.net/galactic/internal/fabric/routing/frrimport"
	"go.datum.net/galactic/internal/fabric/routing/revision"
)

const (
	originatePolicy = "originate"
	orphanNode      = "edge-c"
	testNS          = "galactic-system"
	testNode        = "edge-a"
	testClass       = "fabric-frr"
)

// startController runs the reconciler against a real API server holding
// the stack's CRDs and returns a client.
func startController(t *testing.T) client.Client {
	t.Helper()
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("set KUBEBUILDER_ASSETS for the controller envtest")
	}
	paths, err := filepath.Glob(filepath.Join("..", "..", "..", "..", "config", "crd", "galactic.datumapis.com_*.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var crds []*apiextensionsv1.CustomResourceDefinition
	for _, p := range paths {
		base := filepath.Base(p)
		if !strings.Contains(base, "_bgp") && !strings.Contains(base, "_frr") && !strings.Contains(base, "_fabricrouter") {
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
	mgr, err := ctrl.NewManager(cfg, ctrl.Options{Scheme: scheme, Metrics: metricsserver.Options{BindAddress: "0"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := (&Reconciler{Client: mgr.GetClient()}).SetupWithManager(mgr); err != nil {
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

// seed creates the synthetic edge router, everything it references, its
// class and parameters, and its Node.
func seed(t *testing.T, c client.Client) {
	t.Helper()
	ctx := context.Background()
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
		&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: testNode}},
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
		if err := c.Create(ctx, x); err != nil {
			t.Fatalf("create %T %s: %v", x, x.GetName(), err)
		}
	}
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func router(t *testing.T, c client.Client, name string) *networkv1alpha1.BGPRouter {
	t.Helper()
	r := &networkv1alpha1.BGPRouter{}
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: testNS, Name: name}, r); err != nil {
		t.Fatal(err)
	}
	return r
}

func latest(c client.Client) string {
	r := &networkv1alpha1.BGPRouter{}
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: testNS, Name: testNode}, r); err != nil ||
		r.Status.Fabric == nil {
		return ""
	}
	return r.Status.Fabric.LatestRevision
}

func TestControllerCompilesRevisions(t *testing.T) {
	c := startController(t)
	seed(t, c)
	ctx := context.Background()

	eventually(t, "the first revision", func() bool { return latest(c) != "" })
	first := latest(c)
	rev := &networkv1alpha1.FabricRouterRevision{}
	if err := c.Get(ctx, client.ObjectKey{Namespace: testNS, Name: first}, rev); err != nil {
		t.Fatal(err)
	}
	if _, err := revision.Verify(rev); err != nil {
		t.Fatalf("the stored revision does not verify: %v", err)
	}
	if rev.Spec.Target.NodeUID == "" || rev.Spec.Target.RouterUID == "" {
		t.Errorf("revision target lacks UIDs: %+v", rev.Spec.Target)
	}
	conds := router(t, c, testNode).Status.Conditions
	if acc := meta.FindStatusCondition(conds, networkv1alpha1.ConditionTypeAccepted); acc == nil ||
		acc.Status != metav1.ConditionTrue {
		t.Errorf("Accepted = %+v", acc)
	}

	s := &suite{c: c, first: first, rev: rev}
	t.Run("a stored revision cannot change", s.aStoredRevisionCannotChange)

	t.Run("a policy change makes a new revision", s.aPolicyChangeMakesANewRevision)

	t.Run("only the newest revisions are kept", s.onlyTheNewestRevisionsAreKept)

	t.Run("a missing reference keeps the last revision", s.aMissingReferenceKeepsTheLastRevision)

	t.Run("a classless router is not ours", s.aClasslessRouterIsNotOurs)

	t.Run("a router ID stays with the router that had it first", s.aRouterIDStaysWithTheRouterThatHadItFirst)

	t.Run("a deleted latest revision comes back", s.aDeletedLatestRevisionComesBack)

	t.Run("a router waits for its Node", s.aRouterWaitsForItsNode)

	t.Run("revisions another controller owns are never pruned", s.revisionsAnotherControllerOwnsAreNeverPruned)
}

// suite shares one API server across the controller scenarios, which run
// in order against the same router.
type suite struct {
	c     client.Client
	first string
	rev   *networkv1alpha1.FabricRouterRevision
}

// aStoredRevisionCannotChange: a stored revision cannot change.
func (s *suite) aStoredRevisionCannotChange(t *testing.T) {
	c := s.c
	ctx := context.Background()
	changed := s.rev.DeepCopy()
	changed.Spec.Target.NodeName = "elsewhere"
	if err := c.Update(ctx, changed); err == nil || !strings.Contains(err.Error(), "a revision is immutable") {
		t.Errorf("revision update: %v, want the immutability refusal", err)
	}
}

// aPolicyChangeMakesANewRevision: a policy change makes a new revision.
func (s *suite) aPolicyChangeMakesANewRevision(t *testing.T) {
	c := s.c
	ctx := context.Background()
	pol := &networkv1alpha1.BGPPolicy{}
	if err := c.Get(ctx, client.ObjectKey{Namespace: testNS, Name: originatePolicy}, pol); err != nil {
		t.Fatal(err)
	}
	pol.Spec.Terms[0].Description = "changed"
	if err := c.Update(ctx, pol); err != nil {
		t.Fatal(err)
	}
	eventually(t, "a second revision", func() bool { return latest(c) != s.first })
	old := &networkv1alpha1.FabricRouterRevision{}
	if err := c.Get(ctx, client.ObjectKey{Namespace: testNS, Name: s.first}, old); err != nil {
		t.Errorf("the previous revision was not kept: %v", err)
	}
}

// onlyTheNewestRevisionsAreKept: only the newest revisions are kept.
func (s *suite) onlyTheNewestRevisionsAreKept(t *testing.T) {
	c := s.c
	ctx := context.Background()
	for i := range KeepRevisions + 1 {
		pol := &networkv1alpha1.BGPPolicy{}
		if err := c.Get(ctx, client.ObjectKey{Namespace: testNS, Name: originatePolicy}, pol); err != nil {
			t.Fatal(err)
		}
		before := latest(c)
		pol.Spec.Terms[0].Description = "revision " + strconv.Itoa(i)
		if err := c.Update(ctx, pol); err != nil {
			t.Fatal(err)
		}
		eventually(t, "a new revision", func() bool { return latest(c) != before })
	}
	revs := &networkv1alpha1.FabricRouterRevisionList{}
	eventually(t, "pruning", func() bool {
		_ = c.List(ctx, revs, client.InNamespace(testNS), client.MatchingLabels{RouterLabel: testNode})
		return len(revs.Items) <= KeepRevisions
	})
	found := false
	for _, r := range revs.Items {
		found = found || r.Name == latest(c)
	}
	if !found {
		t.Error("the latest revision was pruned")
	}
}

// aMissingReferenceKeepsTheLastRevision: a missing reference keeps the last revision.
func (s *suite) aMissingReferenceKeepsTheLastRevision(t *testing.T) {
	c := s.c
	ctx := context.Background()
	before := latest(c)
	pl := &networkv1alpha1.BGPPrefixList{}
	if err := c.Get(ctx, client.ObjectKey{Namespace: testNS, Name: "edge-services"}, pl); err != nil {
		t.Fatal(err)
	}
	saved := pl.Spec.DeepCopy()
	if err := c.Delete(ctx, pl); err != nil {
		t.Fatal(err)
	}
	eventually(t, "ResolvedRefs=False", func() bool {
		cond := meta.FindStatusCondition(router(t, c, testNode).Status.Conditions, ConditionResolvedRefs)
		return cond != nil && cond.Status == metav1.ConditionFalse
	})
	if got := latest(c); got != before {
		t.Errorf("latest revision moved to %s on a refused compile", got)
	}

	restored := &networkv1alpha1.BGPPrefixList{
		ObjectMeta: metav1.ObjectMeta{Namespace: testNS, Name: "edge-services"}, Spec: *saved,
	}
	if err := c.Create(ctx, restored); err != nil {
		t.Fatal(err)
	}
	eventually(t, "ResolvedRefs=True again", func() bool {
		cond := meta.FindStatusCondition(router(t, c, testNode).Status.Conditions, ConditionResolvedRefs)
		return cond != nil && cond.Status == metav1.ConditionTrue
	})
}

// aClasslessRouterIsNotOurs: a classless router is not ours.
func (s *suite) aClasslessRouterIsNotOurs(t *testing.T) {
	c := s.c
	ctx := context.Background()
	legacy := &networkv1alpha1.BGPRouter{
		ObjectMeta: metav1.ObjectMeta{Namespace: testNS, Name: "overlay"},
		Spec: networkv1alpha1.BGPRouterSpec{
			TargetRef: networkv1alpha1.TargetRef{Kind: "Node", Name: testNode}, LocalASN: 64500,
			RouterID: "192.0.2.77", AddressFamilies: []networkv1alpha1.AddressFamily{
				{AFI: networkv1alpha1.AFIL2VPN, SAFI: networkv1alpha1.SAFIEVPN}},
		},
	}
	if err := c.Create(ctx, legacy); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Second)
	if r := router(t, c, "overlay"); r.Status.Fabric != nil || len(r.Status.Conditions) != 0 {
		t.Errorf("the fabric controller wrote a classless router's status: %+v", r.Status)
	}
}

// aRouterIDStaysWithTheRouterThatHadItFirst: a router ID stays with the router that had it first.
func (s *suite) aRouterIDStaysWithTheRouterThatHadItFirst(t *testing.T) {
	c := s.c
	ctx := context.Background()
	before := latest(c)
	twin := router(t, c, testNode).DeepCopy()
	twin.ObjectMeta = metav1.ObjectMeta{Namespace: testNS, Name: "edge-b"}
	twin.Spec.TargetRef.Name = testNode
	twin.Spec.FRR = nil
	twin.Status = networkv1alpha1.BGPRouterStatus{}
	if err := c.Create(ctx, twin); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the newcomer refused", func() bool {
		cond := meta.FindStatusCondition(router(t, c, "edge-b").Status.Conditions, networkv1alpha1.ConditionTypeAccepted)
		return cond != nil && cond.Reason == reasonDuplicateID
	})
	time.Sleep(500 * time.Millisecond)
	incumbent := router(t, c, testNode)
	if cond := meta.FindStatusCondition(incumbent.Status.Conditions, ConditionResolvedRefs); cond == nil {
		t.Fatal("the incumbent lost its conditions")
	}
	if latest(c) != before {
		t.Error("the newcomer changed the incumbent's revision")
	}

	twin = router(t, c, "edge-b")
	twin.Spec.RouterID = "192.0.2.111"
	if err := c.Update(ctx, twin); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the newcomer accepted", func() bool {
		r := router(t, c, "edge-b")
		cond := meta.FindStatusCondition(r.Status.Conditions, networkv1alpha1.ConditionTypeAccepted)
		return cond != nil && cond.Status == metav1.ConditionTrue && r.Status.Fabric != nil
	})
}

// aDeletedLatestRevisionComesBack: a deleted latest revision comes back.
func (s *suite) aDeletedLatestRevisionComesBack(t *testing.T) {
	c := s.c
	ctx := context.Background()
	name := latest(c)
	if err := c.Delete(ctx, &networkv1alpha1.FabricRouterRevision{
		ObjectMeta: metav1.ObjectMeta{Namespace: testNS, Name: name},
	}); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the revision recreated", func() bool {
		return c.Get(ctx, client.ObjectKey{Namespace: testNS, Name: name}, &networkv1alpha1.FabricRouterRevision{}) == nil
	})
}

// aRouterWaitsForItsNode: a router waits for its Node.
func (s *suite) aRouterWaitsForItsNode(t *testing.T) {
	c := s.c
	ctx := context.Background()
	orphan := router(t, c, testNode).DeepCopy()
	orphan.ObjectMeta = metav1.ObjectMeta{Namespace: testNS, Name: orphanNode}
	orphan.Spec.TargetRef.Name = orphanNode
	orphan.Spec.RouterID = "192.0.2.112"
	orphan.Spec.FRR = nil
	orphan.Status = networkv1alpha1.BGPRouterStatus{}
	if err := c.Create(ctx, orphan); err != nil {
		t.Fatal(err)
	}
	eventually(t, "TargetNotFound", func() bool {
		cond := meta.FindStatusCondition(router(t, c, orphanNode).Status.Conditions, ConditionResolvedRefs)
		return cond != nil && cond.Reason == reasonTargetNotFound
	})
	if err := c.Create(ctx, &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: orphanNode}}); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the router compiled once its Node exists", func() bool {
		return router(t, c, orphanNode).Status.Fabric != nil
	})
}

// revisionsAnotherControllerOwnsAreNeverPruned: revisions another controller owns are never pruned.
func (s *suite) revisionsAnotherControllerOwnsAreNeverPruned(t *testing.T) {
	c := s.c
	ctx := context.Background()
	foreign := &networkv1alpha1.FabricRouterRevision{}
	if err := c.Get(ctx, client.ObjectKey{Namespace: testNS, Name: latest(c)}, foreign); err != nil {
		t.Fatal(err)
	}
	foreign = &networkv1alpha1.FabricRouterRevision{
		ObjectMeta: metav1.ObjectMeta{Namespace: testNS, Name: "foreign", Labels: map[string]string{RouterLabel: testNode}},
		Spec:       foreign.Spec,
	}
	if err := c.Create(ctx, foreign); err != nil {
		t.Fatal(err)
	}
	for i := range KeepRevisions + 1 {
		pol := &networkv1alpha1.BGPPolicy{}
		if err := c.Get(ctx, client.ObjectKey{Namespace: testNS, Name: originatePolicy}, pol); err != nil {
			t.Fatal(err)
		}
		before := latest(c)
		pol.Spec.Terms[0].Description = "foreign " + strconv.Itoa(i)
		if err := c.Update(ctx, pol); err != nil {
			t.Fatal(err)
		}
		eventually(t, "a new revision", func() bool { return latest(c) != before })
	}
	err := c.Get(ctx, client.ObjectKey{Namespace: testNS, Name: "foreign"}, &networkv1alpha1.FabricRouterRevision{})
	if err != nil {
		t.Errorf("a revision this router does not control was pruned: %v", err)
	}
}
