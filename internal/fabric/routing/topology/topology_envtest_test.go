// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package topology

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrlconfig "sigs.k8s.io/controller-runtime/pkg/config"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/yaml"

	networkv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	"go.datum.net/galactic/internal/rbaccheck"
)

const (
	cellA     = "cell-a"
	meshTrans = "mesh"
	zoneLabel = "topology.kubernetes.io/zone"
	member    = "fabric.example/member"
	topoName  = "fabric"
	meshProf  = "mesh-profile"

	resTopologies = "fabrictopologies"
	resEndpoints  = "fabricendpoints"
)

var configDir = filepath.Join("..", "..", "..", "..", "config", "fabric-router-controller")

// env is a running API server and topology controllers.
type env struct {
	t   *testing.T
	c   client.Client
	ctx context.Context
	// writes counts the generator's creates, updates and deletes.
	writes *atomic.Int64
}

// countingClient counts the object writes made through it; status writes
// go through Status() and are not counted.
type countingClient struct {
	client.Client
	writes *atomic.Int64
}

func (c countingClient) Create(ctx context.Context, obj client.Object, opts ...client.CreateOption) error {
	c.writes.Add(1)
	return c.Client.Create(ctx, obj, opts...)
}

func (c countingClient) Update(ctx context.Context, obj client.Object, opts ...client.UpdateOption) error {
	c.writes.Add(1)
	return c.Client.Update(ctx, obj, opts...)
}

func (c countingClient) Delete(ctx context.Context, obj client.Object, opts ...client.DeleteOption) error {
	c.writes.Add(1)
	return c.Client.Delete(ctx, obj, opts...)
}

// start runs the topology and endpoint controllers against a real API
// server holding the fabric CRDs, as the fabric-router-controller
// ServiceAccount bound only to the shipped RBAC and the topology
// component's, so a call the manifests do not grant fails the test.
func start(t *testing.T) *env {
	t.Helper()
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("set KUBEBUILDER_ASSETS for the topology envtest")
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
	te := &envtest.Environment{CRDs: crds}
	cfg, err := te.Start()
	if err != nil {
		t.Fatal(err)
	}
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = networkv1alpha1.AddToScheme(scheme)
	admin, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	if err := admin.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: unitNS}}); err != nil {
		t.Fatal(err)
	}
	rbaccheck.Apply(t, admin, filepath.Join(configDir, "serviceaccount.yaml"), filepath.Join(configDir, "rbac.yaml"),
		filepath.Join(configDir, "components", "topology", "rbac.yaml"))
	sa := rest.CopyConfig(cfg)
	user, groups := rbaccheck.ServiceAccount(unitNS, "fabric-router-controller")
	sa.Impersonate = rest.ImpersonationConfig{UserName: user, Groups: groups}

	skip := true
	mgr, err := ctrl.NewManager(sa, ctrl.Options{
		Scheme: scheme, Metrics: metricsserver.Options{BindAddress: "0"},
		Controller: ctrlconfig.Controller{SkipNameValidation: &skip},
	})
	if err != nil {
		t.Fatal(err)
	}
	writes := &atomic.Int64{}
	if err := (&Reconciler{Client: countingClient{mgr.GetClient(), writes}}).SetupWithManager(mgr); err != nil {
		t.Fatal(err)
	}
	if err := (&EndpointReconciler{Client: mgr.GetClient()}).SetupWithManager(mgr); err != nil {
		t.Fatal(err)
	}
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
		if err := te.Stop(); err != nil {
			t.Errorf("stop API: %v", err)
		}
	})
	return &env{t: t, c: admin, ctx: context.Background(), writes: writes}
}

func (e *env) create(objs ...client.Object) {
	e.t.Helper()
	for _, o := range objs {
		if err := e.c.Create(e.ctx, o); err != nil {
			e.t.Fatalf("create %T %s: %v", o, o.GetName(), err)
		}
	}
}

func (e *env) delete(o client.Object) {
	e.t.Helper()
	if err := e.c.Delete(e.ctx, o); err != nil {
		e.t.Fatalf("delete %T %s: %v", o, o.GetName(), err)
	}
}

// edit reads obj, applies mutate and writes it back, retrying conflicts.
func (e *env) edit(obj client.Object, mutate func(), status bool) {
	e.t.Helper()
	for range 10 {
		if err := e.c.Get(e.ctx, client.ObjectKeyFromObject(obj), obj); err != nil {
			e.t.Fatal(err)
		}
		mutate()
		var err error
		if status {
			err = e.c.Status().Update(e.ctx, obj)
		} else {
			err = e.c.Update(e.ctx, obj)
		}
		if err == nil {
			return
		}
		if !apierrors.IsConflict(err) {
			e.t.Fatalf("update %s: %v", obj.GetName(), err)
		}
	}
	e.t.Fatalf("update %s: kept conflicting", obj.GetName())
}

func (e *env) node(name, zone string) {
	e.create(&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: map[string]string{zoneLabel: zone}}})
}

func (e *env) router(name string, id int, labels map[string]string) *networkv1alpha1.BGPRouter {
	r := router(name, labels)
	r.UID = ""
	r.Spec.Plane = ptr.To(networkv1alpha1.BGPRoutingPlaneUnderlay)
	r.Spec.RouterID = fmt.Sprintf("192.0.2.%d", id)
	r.Spec.AddressFamilies = []networkv1alpha1.AddressFamily{
		{AFI: networkv1alpha1.AFIIPv4, SAFI: networkv1alpha1.SAFIUnicast},
		{AFI: networkv1alpha1.AFIIPv6, SAFI: networkv1alpha1.SAFIUnicast},
	}
	e.create(r)
	return r
}

// endpoint creates an endpoint of cell-a.
func (e *env) endpoint(
	name, routerName, transport, v4, v6 string, labels map[string]string,
) *networkv1alpha1.FabricEndpoint {
	ep := endpoint(name, cellA, routerName, transport, v4, v6, 0, labels)
	ep.UID, ep.CreationTimestamp = "", metav1.Time{}
	e.create(&ep)
	return &ep
}

// generated are the peers in the namespace carrying the managed-by label,
// by name.
func (e *env) generated() map[string]*networkv1alpha1.BGPPeer {
	e.t.Helper()
	list := &networkv1alpha1.BGPPeerList{}
	if err := e.c.List(e.ctx, list, client.InNamespace(unitNS),
		client.MatchingLabels{networkv1alpha1.LabelManagedBy: networkv1alpha1.ManagedByFabricTopology}); err != nil {
		e.t.Fatal(err)
	}
	out := map[string]*networkv1alpha1.BGPPeer{}
	for i := range list.Items {
		if list.Items[i].DeletionTimestamp.IsZero() {
			out[list.Items[i].Name] = &list.Items[i]
		}
	}
	return out
}

func (e *env) topology() *networkv1alpha1.FabricTopology {
	e.t.Helper()
	t := &networkv1alpha1.FabricTopology{}
	if err := e.c.Get(e.ctx, client.ObjectKey{Namespace: unitNS, Name: topoName}, t); err != nil {
		e.t.Fatal(err)
	}
	return t
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// consistently fails if cond stops holding within a few seconds: long
// enough for the controllers to act on whatever was just written.
func consistently(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if !cond() {
			t.Fatalf("%s stopped holding", what)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func names(m map[string]*networkv1alpha1.BGPPeer) string {
	out := make([]string, 0, len(m))
	for n := range m {
		out = append(out, n)
	}
	return listedAll(out)
}

func listedAll(items []string) string {
	sorted := append([]string(nil), items...)
	for i := range sorted {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[j] < sorted[i] {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}
	return strings.Join(sorted, " ")
}

func condition(t *networkv1alpha1.FabricTopology, typ string) *metav1.Condition {
	return meta.FindStatusCondition(t.Status.Conditions, typ)
}

// meshTopology meshes every member's endpoint on the mesh transport over
// both families, with local weight 100 on IPv6.
func meshTopology() *networkv1alpha1.FabricTopology {
	return &networkv1alpha1.FabricTopology{
		ObjectMeta: metav1.ObjectMeta{Name: topoName, Namespace: unitNS},
		Spec: networkv1alpha1.FabricTopologySpec{
			RoutingDomain: unitDomain, Cell: cellA,
			Members: networkv1alpha1.FabricTopologyMembers{
				RouterSelector: &metav1.LabelSelector{MatchLabels: map[string]string{member: "yes"}}},
			Mesh: []networkv1alpha1.FabricMeshRelationship{{
				Name: "private", Transports: []string{meshTrans}, Families: both(),
				Settings: networkv1alpha1.FabricSessionSettings{FamilySettings: []networkv1alpha1.BGPPeerFamilySettings{{
					AFI: networkv1alpha1.AFIIPv6, SAFI: networkv1alpha1.SAFIUnicast,
					FRR: &networkv1alpha1.FRRPeerFamilySettings{Weight: ptr.To[int32](100)}}}},
			}},
		},
	}
}

var isMember = map[string]string{member: "yes"}

// meshFixture creates three member routers on two zones; a3 has only an
// IPv6 address on the mesh.
func (e *env) meshFixture() {
	e.node("node-a1", "z1")
	e.node("node-a2", "z2")
	e.node("node-a3", "z1")
	e.router("a1", 1, isMember)
	e.router("a2", 2, isMember)
	e.router("a3", 3, isMember)
	e.endpoint("a1-mesh", "a1", meshTrans, "10.0.0.1", "fd00::1", nil)
	e.endpoint("a2-mesh", "a2", meshTrans, "10.0.0.2", "fd00::2", nil)
	e.endpoint("a3-mesh", "a3", meshTrans, "", "fd00::3", nil)
}

const meshPeers = "a1-a2-mesh-ipv4 a1-a2-mesh-ipv6 a1-a3-mesh-ipv6 a2-a1-mesh-ipv4 a2-a1-mesh-ipv6 a2-a3-mesh-ipv6 " +
	"a3-a1-mesh-ipv6 a3-a2-mesh-ipv6"

// TestNodeLifecycle: a mesh generates both ends of every session in the
// families both ends carry, rewrites nothing on a resync, adds a node's
// sessions when it appears, and when its endpoint goes keeps them until its
// deployment commits the retiring promotion.
func TestNodeLifecycle(t *testing.T) {
	e := start(t)
	e.meshFixture()
	e.create(meshTopology())
	eventually(t, "the mesh", func() bool { return names(e.generated()) == meshPeers })

	p := e.generated()["a1-a2-mesh-ipv6"]
	if p.Spec.RouterRef.Name != "a1" || p.Spec.Address != "fd00::2" || *p.Spec.UpdateSource != "fd00::1" ||
		p.Spec.PeerASN != unitASN || len(p.Spec.FamilySettings) != 1 || *p.Spec.FamilySettings[0].FRR.Weight != 100 {
		t.Errorf("a1-a2-mesh-ipv6 spec %+v", p.Spec)
	}
	if p.Labels[networkv1alpha1.LabelPeerFailureDomain] != "z2" || p.Labels[networkv1alpha1.LabelPeerCell] != cellA ||
		p.Annotations[networkv1alpha1.AnnotationRelationship] != "mesh/private" ||
		p.Annotations[networkv1alpha1.AnnotationRemoteEndpoint] != "a2-mesh" {
		t.Errorf("a1-a2-mesh-ipv6 labels %v annotations %v", p.Labels, p.Annotations)
	}
	if ref := metav1.GetControllerOf(p); ref == nil || ref.Kind != "FabricTopology" || ref.Name != topoName {
		t.Errorf("controller %v", ref)
	}
	if v4 := e.generated()["a1-a2-mesh-ipv4"]; len(v4.Spec.FamilySettings) != 0 {
		t.Errorf("the IPv6 weight reached the IPv4 peer: %+v", v4.Spec.FamilySettings)
	}
	eventually(t, "Ready", func() bool {
		topo := e.topology()
		c := condition(topo, networkv1alpha1.ConditionTypeReady)
		return c != nil && c.Status == metav1.ConditionTrue && topo.Status.Generated == 8 && topo.Status.Members == 3
	})
	eventually(t, "endpoint status", func() bool {
		ep := &networkv1alpha1.FabricEndpoint{}
		_ = e.c.Get(e.ctx, client.ObjectKey{Namespace: unitNS, Name: "a1-mesh"}, ep)
		c := meta.FindStatusCondition(ep.Status.Conditions, networkv1alpha1.FabricEndpointConditionReady)
		return ep.Status.Local && c != nil && c.Status == metav1.ConditionTrue &&
			c.Reason == networkv1alpha1.FabricEndpointReasonLocal
	})

	// A resync writes nothing: no update, even one the API server would
	// find empty.
	versions := map[string]string{}
	for n, p := range e.generated() {
		versions[n] = p.ResourceVersion
	}
	before := e.writes.Load()
	topo := e.topology()
	e.edit(topo, func() { topo.Spec.MaxSessionsPerRouter = 65 }, false)
	eventually(t, "the resync", func() bool {
		t := e.topology()
		return t.Status.ObservedGeneration == t.Generation
	})
	for n, p := range e.generated() {
		if versions[n] != p.ResourceVersion {
			t.Errorf("%s rewritten on a resync", n)
		}
	}
	if n := e.writes.Load() - before; n != 0 {
		t.Errorf("%d peer writes on a resync", n)
	}

	// A new node joins: its sessions appear on every member.
	e.node("node-a4", "z2")
	a4 := e.router("a4", 4, isMember)
	ep4 := e.endpoint("a4-mesh", "a4", meshTrans, "10.0.0.4", "fd00::4", nil)
	toA4 := []string{"a1-a4-mesh-ipv4", "a1-a4-mesh-ipv6", "a2-a4-mesh-ipv4", "a2-a4-mesh-ipv6", "a3-a4-mesh-ipv6",
		"a4-a1-mesh-ipv4", "a4-a1-mesh-ipv6", "a4-a2-mesh-ipv4", "a4-a2-mesh-ipv6", "a4-a3-mesh-ipv6"}
	all := listedAll(append(strings.Fields(meshPeers), toA4...))
	eventually(t, "a4's sessions", func() bool { return names(e.generated()) == all })

	// Its endpoint goes while it still runs: every session stays.
	e.delete(ep4)
	eventually(t, "a4's sessions retained", func() bool {
		t := e.topology()
		return t.Status.Retained == 10 && t.Status.MissingEndpoints == 1
	})
	if got := names(e.generated()); got != all {
		t.Fatalf("sessions after the endpoint went: %s", got)
	}

	// A retiring promotion not yet committed keeps them.
	node4 := &corev1.Node{}
	if err := e.c.Get(e.ctx, client.ObjectKey{Name: "node-a4"}, node4); err != nil {
		t.Fatal(err)
	}
	dep := &networkv1alpha1.FabricRouterDeployment{
		ObjectMeta: metav1.ObjectMeta{Name: "a4", Namespace: unitNS},
		Spec: networkv1alpha1.FabricRouterDeploymentSpec{
			RouterRef: networkv1alpha1.FabricObjectIdentity{Name: "a4", UID: string(a4.UID)},
			Target:    networkv1alpha1.FabricNodeIdentity{NodeName: "node-a4", NodeUID: string(node4.UID)},
			Source:    networkv1alpha1.FabricConfigSourceCRD,
		},
	}
	e.create(dep)
	digest := strings.Repeat("ab", 32)
	e.edit(dep, func() {
		dep.Spec.ActivationEpoch = 1
		dep.Spec.ActiveRevisionRef = &networkv1alpha1.LocalObjectRef{Name: "a4-" + digest[:10]}
		dep.Spec.ActivationDependencyDigest = digest
		dep.Spec.AuthorizationRef = &networkv1alpha1.FabricObjectIdentity{Name: "retire", UID: "retire-uid"}
		dep.Spec.Activation = &networkv1alpha1.FabricActivationSettings{ApplyTimeoutSeconds: 5}
		dep.Spec.Recovery = &networkv1alpha1.FabricRecovery{Retired: true}
	}, false)
	consistently(t, "a4's sessions while its retirement is uncommitted",
		func() bool { return names(e.generated()) == all })

	// Once the agent commits it, a4's sessions go, on every member.
	e.edit(dep, func() { dep.Status.AppliedEpoch = 1 }, true)
	eventually(t, "a4's sessions released", func() bool { return names(e.generated()) == meshPeers })
}

// TestMemberLeavesAndDrain: deleting a router releases its sessions at
// once; a router that only leaves the member selector keeps them until the
// topology drains it.
func TestMemberLeavesAndDrain(t *testing.T) {
	e := start(t)
	e.meshFixture()
	e.create(meshTopology())
	eventually(t, "the mesh", func() bool { return names(e.generated()) == meshPeers })

	a3 := &networkv1alpha1.BGPRouter{ObjectMeta: metav1.ObjectMeta{Name: "a3", Namespace: unitNS}}
	e.delete(a3)
	ab := "a1-a2-mesh-ipv4 a1-a2-mesh-ipv6 a2-a1-mesh-ipv4 a2-a1-mesh-ipv6"
	eventually(t, "a3's sessions released", func() bool { return names(e.generated()) == ab })

	a2 := &networkv1alpha1.BGPRouter{ObjectMeta: metav1.ObjectMeta{Name: "a2", Namespace: unitNS}}
	e.edit(a2, func() { a2.Labels = nil }, false)
	eventually(t, "a2's sessions retained", func() bool {
		t := e.topology()
		return t.Status.Retained == 4 && t.Status.Members == 1
	})
	consistently(t, "a2's sessions", func() bool { return names(e.generated()) == ab })

	topo := e.topology()
	e.edit(topo, func() {
		topo.Spec.Drain = &networkv1alpha1.FabricTopologyDrain{Routers: []networkv1alpha1.LocalObjectRef{{Name: "a2"}}}
	}, false)
	eventually(t, "a2's sessions drained", func() bool { return len(e.generated()) == 0 })
}

// TestCellLifecycle: a reflector peers with another cell's clients from
// their records alone, in the families they carry, recording their cell
// and failure domain; a new cell's records add sessions, a deleted record
// releases its sessions, and a record that stays but stops matching keeps
// them.
func TestCellLifecycle(t *testing.T) {
	e := start(t)
	e.node("node-rr", "z1")
	e.router("rr", 1, isMember)
	e.endpoint("a-rr-public", "rr", transportP, "198.51.100.1", "2001:db8:a::1", reflectorRole)
	remote := func(name, cell, routerName, v6, fd string) *networkv1alpha1.FabricEndpoint {
		ep := endpoint(name, cell, routerName, transportP, "", v6, 0, clientRole)
		ep.UID, ep.CreationTimestamp = "", metav1.Time{}
		ep.Spec.FailureDomain = ptr.To(fd)
		e.create(&ep)
		return &ep
	}
	b1 := remote("b-c1-public", cellB, "c1", "2001:db8:b::1", "b-z1")
	b2 := remote("b-c2-public", cellB, "c2", "2001:db8:b::2", "b-z2")
	topo := reflectionTopology(cellA, "rr")
	topo.Name = topoName
	topo.Spec.Members = networkv1alpha1.FabricTopologyMembers{
		RouterSelector: &metav1.LabelSelector{MatchLabels: isMember}}
	e.create(topo)
	bPeers := "rr-b-c1-public-ipv6 rr-b-c2-public-ipv6"
	eventually(t, "sessions toward cell-b", func() bool { return names(e.generated()) == bPeers })
	p := e.generated()["rr-b-c1-public-ipv6"]
	if p.Labels[networkv1alpha1.LabelPeerCell] != cellB || p.Labels[networkv1alpha1.LabelPeerFailureDomain] != "b-z1" ||
		p.Spec.FamilySettings[0].RouteReflectorClient == nil || !*p.Spec.FamilySettings[0].RouteReflectorClient {
		t.Errorf("rr-b-c1-public-ipv6: labels %v settings %+v", p.Labels, p.Spec.FamilySettings)
	}
	eventually(t, "remote endpoint status", func() bool {
		ep := &networkv1alpha1.FabricEndpoint{}
		_ = e.c.Get(e.ctx, client.ObjectKeyFromObject(b1), ep)
		c := meta.FindStatusCondition(ep.Status.Conditions, networkv1alpha1.FabricEndpointConditionReady)
		return !ep.Status.Local && c != nil && c.Reason == networkv1alpha1.FabricEndpointReasonRemote
	})

	// A new cell's records arrive.
	remote("c-c1-public", "cell-c", "c1", "2001:db8:c::1", "c-z1")
	withC := bPeers + " rr-c-c1-public-ipv6"
	eventually(t, "sessions toward cell-c", func() bool { return names(e.generated()) == withC })

	// cell-b deletes one record: its session goes.
	e.delete(b1)
	withoutB1 := "rr-b-c2-public-ipv6 rr-c-c1-public-ipv6"
	eventually(t, "the deleted record's session released", func() bool { return names(e.generated()) == withoutB1 })

	// A record that stops matching is not a deletion: its session stays.
	e.edit(b2, func() { b2.Labels = map[string]string{roleLabel: "other"} }, false)
	eventually(t, "the unmatched record's session retained",
		func() bool { return e.topology().Status.Retained == 1 })
	consistently(t, "the unmatched record's session", func() bool { return names(e.generated()) == withoutB1 })

	// Deleting that record releases it.
	e.delete(b2)
	eventually(t, "its session released", func() bool { return names(e.generated()) == "rr-c-c1-public-ipv6" })
}

// TestConflictsAndOwnership: a hand-authored peer toward an address the
// topology would generate, or holding a generated name, blocks only that
// session and is never touched; a peer carrying the generated labels
// without the topology's controller reference is never touched either;
// removing the hand-authored peer lets the generated one in.
func TestConflictsAndOwnership(t *testing.T) {
	e := start(t)
	e.node("node-a1", "z1")
	e.node("node-a2", "z2")
	e.router("a1", 1, isMember)
	e.router("a2", 2, isMember)
	e.endpoint("a1-mesh", "a1", meshTrans, "10.0.0.1", "fd00::1", nil)
	e.endpoint("a2-mesh", "a2", meshTrans, "10.0.0.2", "fd00::2", nil)
	peer := func(name, address string, labels map[string]string) *networkv1alpha1.BGPPeer {
		return &networkv1alpha1.BGPPeer{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: unitNS, Labels: labels},
			Spec: networkv1alpha1.BGPPeerSpec{
				RouterTarget: networkv1alpha1.RouterTarget{RouterRef: &networkv1alpha1.RouterRef{Name: "a1"}},
				PeerASN:      unitASN, Address: address,
				AddressFamilies: []networkv1alpha1.AddressFamily{{AFI: networkv1alpha1.AFIIPv6, SAFI: networkv1alpha1.SAFIUnicast}},
			},
		}
	}
	hand := peer("hand", "fd00::2", nil)
	squatter := peer("a1-a2-mesh-ipv4", "fd00::99", nil)
	spoof := peer("spoof", "fd00::98", map[string]string{
		networkv1alpha1.LabelManagedBy:      networkv1alpha1.ManagedByFabricTopology,
		networkv1alpha1.LabelFabricTopology: topoName})
	e.create(hand, squatter, spoof)
	e.create(meshTopology())

	eventually(t, "the conflicts", func() bool {
		topo := e.topology()
		c := condition(topo, networkv1alpha1.FabricTopologyConditionConflicts)
		return c != nil && c.Status == metav1.ConditionTrue && topo.Status.Conflicting == 2 && topo.Status.Generated == 2
	})
	got := e.generated()
	if got["a2-a1-mesh-ipv4"] == nil || got["a2-a1-mesh-ipv6"] == nil || got["a1-a2-mesh-ipv6"] != nil {
		t.Errorf("generated %s", names(got))
	}
	check := func(p *networkv1alpha1.BGPPeer) {
		now := &networkv1alpha1.BGPPeer{}
		if err := e.c.Get(e.ctx, client.ObjectKeyFromObject(p), now); err != nil {
			t.Fatalf("%s: %v", p.Name, err)
		}
		if now.ResourceVersion != p.ResourceVersion {
			t.Errorf("%s was changed", p.Name)
		}
	}
	consistently(t, "the unmanaged peers", func() bool {
		for _, p := range []*networkv1alpha1.BGPPeer{hand, squatter, spoof} {
			check(p)
		}
		return true
	})
	if c := condition(e.topology(), networkv1alpha1.ConditionTypeReady); c.Status != metav1.ConditionFalse {
		t.Errorf("Ready %s with blocked sessions", c.Status)
	}

	e.delete(hand)
	eventually(t, "the generated peer replacing the hand-authored one", func() bool {
		return e.generated()["a1-a2-mesh-ipv6"] != nil && e.topology().Status.Conflicting == 1
	})

	// An endpoint claiming an address an older one holds is in conflict
	// and generates nothing. Creation times have a resolution of a second,
	// and within one the name decides, which would favour a1-dup.
	dup := e.endpoint("a2-dup", "a2", "other", "", "fd00::77", nil)
	time.Sleep(1100 * time.Millisecond)
	dup2 := e.endpoint("a1-dup", "a1", "other", "", "fd00::77", nil)
	eventually(t, "the address conflict", func() bool {
		ep := &networkv1alpha1.FabricEndpoint{}
		_ = e.c.Get(e.ctx, client.ObjectKeyFromObject(dup2), ep)
		c := meta.FindStatusCondition(ep.Status.Conditions, networkv1alpha1.FabricEndpointConditionConflict)
		return c != nil && c.Status == metav1.ConditionTrue && c.Reason == networkv1alpha1.FabricEndpointReasonAddressInUse
	})
	ep := &networkv1alpha1.FabricEndpoint{}
	if err := e.c.Get(e.ctx, client.ObjectKeyFromObject(dup), ep); err != nil {
		t.Fatal(err)
	}
	if c := meta.FindStatusCondition(ep.Status.Conditions, networkv1alpha1.FabricEndpointConditionConflict); c == nil ||
		c.Status != metav1.ConditionFalse {
		t.Errorf("the older endpoint lost its address: %+v", c)
	}
}

// TestRefsAndLimit: a missing profile holds every write until it exists;
// exceeding the session limit changes nothing.
func TestRefsAndLimit(t *testing.T) {
	e := start(t)
	e.meshFixture()
	topo := meshTopology()
	topo.Spec.Mesh[0].Settings.PeerProfileRef = &networkv1alpha1.LocalObjectRef{Name: meshProf}
	topo.Spec.Mesh[0].Families = []networkv1alpha1.FabricSessionFamily{networkv1alpha1.FabricSessionFamilyIPv6}
	e.create(topo)
	eventually(t, "ResolvedRefs False", func() bool {
		c := condition(e.topology(), networkv1alpha1.FabricTopologyConditionResolvedRefs)
		return c != nil && c.Status == metav1.ConditionFalse
	})
	consistently(t, "no peers without the profile", func() bool { return len(e.generated()) == 0 })

	e.create(&networkv1alpha1.BGPPeerProfile{
		ObjectMeta: metav1.ObjectMeta{Name: meshProf, Namespace: unitNS},
		Spec: networkv1alpha1.BGPPeerProfileSpec{AddressFamilies: []networkv1alpha1.BGPPeerFamilySettings{
			{AFI: networkv1alpha1.AFIIPv6, SAFI: networkv1alpha1.SAFIUnicast}}},
	})
	eventually(t, "the mesh", func() bool { return len(e.generated()) == 6 })
	for n, p := range e.generated() {
		if p.Spec.PeerProfileRef == nil || p.Spec.PeerProfileRef.Name != meshProf || len(p.Spec.AddressFamilies) != 0 {
			t.Errorf("%s: profile %v families %v", n, p.Spec.PeerProfileRef, p.Spec.AddressFamilies)
		}
	}

	// Over the limit nothing is written, not even the IPv4 sessions the
	// same edit adds.
	e.edit(topo, func() {
		topo.Spec.MaxSessionsPerRouter = 1
		topo.Spec.Mesh[0].Families = both()
	}, false)
	eventually(t, "Accepted False", func() bool {
		c := condition(e.topology(), networkv1alpha1.ConditionTypeAccepted)
		return c != nil && c.Status == metav1.ConditionFalse &&
			c.Reason == networkv1alpha1.FabricTopologyReasonTooManySessions
	})
	consistently(t, "the mesh untouched over the limit", func() bool { return len(e.generated()) == 6 })
}

// TestTopologyRBACCoversEveryCall checks the topology component's RBAC
// grants what the generator needs beyond the controller's own RBAC, and
// nothing it should not have.
func TestTopologyRBACCoversEveryCall(t *testing.T) {
	cfg := rbaccheck.Start(t)
	admin, err := client.New(cfg, client.Options{})
	if err != nil {
		t.Fatal(err)
	}
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: unitNS}}
	if err := admin.Create(context.Background(), ns); err != nil {
		t.Fatal(err)
	}
	rbaccheck.Apply(t, admin, filepath.Join(configDir, "serviceaccount.yaml"), filepath.Join(configDir, "rbac.yaml"),
		filepath.Join(configDir, "components", "topology", "rbac.yaml"))
	const g = "galactic.datumapis.com"
	allowed := rbaccheck.Each(rbaccheck.Read, g, unitNS, resTopologies, resEndpoints, "bgppeers",
		"bgprouters", "bgppeerprofiles", "bgppolicies", "fabricrouterdeployments")
	allowed = append(allowed, rbaccheck.Each(rbaccheck.Read, "", "", "nodes")...)
	allowed = append(allowed, rbaccheck.Each([]string{rbaccheck.Patch}, g, unitNS,
		resTopologies, "fabrictopologies/status", "fabricendpoints/status")...)
	allowed = append(allowed, rbaccheck.Each([]string{rbaccheck.Update}, g, unitNS, "fabrictopologies/finalizers")...)
	allowed = append(allowed, rbaccheck.Each([]string{rbaccheck.Create, rbaccheck.Update, rbaccheck.Delete}, g, unitNS,
		"bgppeers")...)
	denied := []rbaccheck.Access{
		{Verb: rbaccheck.Create, Group: g, Resource: resTopologies, Namespace: unitNS},
		{Verb: rbaccheck.Update, Group: g, Resource: resTopologies, Namespace: unitNS},
		{Verb: rbaccheck.Delete, Group: g, Resource: resTopologies, Namespace: unitNS},
		{Verb: rbaccheck.Patch, Group: g, Resource: resEndpoints, Namespace: unitNS},
		{Verb: rbaccheck.Create, Group: g, Resource: resEndpoints, Namespace: unitNS},
		{Verb: rbaccheck.Update, Group: g, Resource: resEndpoints, Namespace: unitNS},
		{Verb: rbaccheck.Delete, Group: g, Resource: resEndpoints, Namespace: unitNS},
		{Verb: rbaccheck.Update, Group: g, Resource: "fabricendpoints/status", Namespace: unitNS},
		{Verb: rbaccheck.Patch, Group: g, Resource: "bgppeers/status", Namespace: unitNS},
		{Verb: rbaccheck.Create, Group: g, Resource: "bgppolicies", Namespace: unitNS},
		{Verb: rbaccheck.Update, Group: g, Resource: "bgprouters", Namespace: unitNS},
		{Verb: rbaccheck.Get, Resource: "secrets", Namespace: unitNS},
	}
	user, groups := rbaccheck.ServiceAccount(unitNS, "fabric-router-controller")
	rbaccheck.Check(t, admin, user, groups, allowed, denied)
}

// TestTopologyComponent: the component adds --topology and its RBAC to the
// controller's Deployment.
func TestTopologyComponent(t *testing.T) {
	out := string(rbaccheck.Kustomize(t, []string{filepath.Join(configDir, "base")},
		[]string{filepath.Join(configDir, "components", "topology")}))
	for _, want := range []string{"- --topology", "name: fabric-router-controller-topology", "kind: ClusterRoleBinding"} {
		if !strings.Contains(out, want) {
			t.Errorf("the build lacks %q", want)
		}
	}
}

// allPeers are every peer in the namespace, by name.
func (e *env) allPeers() map[string]*networkv1alpha1.BGPPeer {
	e.t.Helper()
	list := &networkv1alpha1.BGPPeerList{}
	if err := e.c.List(e.ctx, list, client.InNamespace(unitNS)); err != nil {
		e.t.Fatal(err)
	}
	out := map[string]*networkv1alpha1.BGPPeer{}
	for i := range list.Items {
		out[list.Items[i].Name] = &list.Items[i]
	}
	return out
}

// TestDeleteHandsPeersToManualControl: deleting a topology drops no
// session. Its peers stay, with the same UIDs and specs, and lose the
// controller reference and generated labels, so the garbage collector has
// nothing to delete; envtest runs no garbage collector, so the owner
// references are the evidence. A topology created again reports them as
// conflicts and adopts none, until an operator deletes one.
func TestDeleteHandsPeersToManualControl(t *testing.T) {
	e := start(t)
	e.meshFixture()
	topo := meshTopology()
	e.create(topo)
	eventually(t, "the mesh", func() bool { return names(e.generated()) == meshPeers })
	eventually(t, "the finalizer", func() bool {
		return slices.Contains(e.topology().Finalizers, networkv1alpha1.FabricTopologyFinalizer)
	})
	before := e.allPeers()
	uid := e.topology().UID

	e.delete(topo)
	eventually(t, "the topology gone", func() bool {
		err := e.c.Get(e.ctx, client.ObjectKeyFromObject(topo), &networkv1alpha1.FabricTopology{})
		return apierrors.IsNotFound(err)
	})
	after := e.allPeers()
	if len(after) != len(before) {
		t.Fatalf("%d peers before the deletion, %d after", len(before), len(after))
	}
	for n, p := range after {
		was := before[n]
		if was == nil || was.UID != p.UID || !equality.Semantic.DeepEqual(was.Spec, p.Spec) {
			t.Errorf("%s replaced or changed", n)
		}
		for _, ref := range p.OwnerReferences {
			if ref.UID == uid {
				t.Errorf("%s still owned by the deleted topology", n)
			}
		}
		if _, ok := p.Labels[networkv1alpha1.LabelManagedBy]; ok {
			t.Errorf("%s still labelled as generated", n)
		}
		if p.Annotations[networkv1alpha1.AnnotationReleasedFromTopology] != topoName {
			t.Errorf("%s: annotations %v", n, p.Annotations)
		}
	}

	// Created again, it adopts nothing.
	e.create(meshTopology())
	eventually(t, "every session a conflict", func() bool {
		t := e.topology()
		c := condition(t, networkv1alpha1.FabricTopologyConditionConflicts)
		return c != nil && c.Status == metav1.ConditionTrue && t.Status.Conflicting == 8 && t.Status.Generated == 0
	})
	consistently(t, "the released peers", func() bool {
		for n, p := range e.allPeers() {
			if p.ResourceVersion != after[n].ResourceVersion {
				return false
			}
		}
		return len(e.generated()) == 0
	})

	// The adoption path: delete a released peer and the topology
	// generates its own.
	e.delete(after["a1-a2-mesh-ipv6"])
	eventually(t, "the generated replacement", func() bool {
		p := e.generated()["a1-a2-mesh-ipv6"]
		return p != nil && metav1.GetControllerOf(p) != nil && e.topology().Status.Conflicting == 7
	})
}
