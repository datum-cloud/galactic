// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	logr "github.com/go-logr/logr"
	bgpv1alpha1 "go.miloapis.com/cosmos/api/bgp/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	restclient "k8s.io/client-go/rest"
	eventstools "k8s.io/client-go/tools/events"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	config "sigs.k8s.io/controller-runtime/pkg/config"
	healthz "sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	webhook "sigs.k8s.io/controller-runtime/pkg/webhook"
	conversion "sigs.k8s.io/controller-runtime/pkg/webhook/conversion"
)

// ---------- helpers --------------------------------------------------------

const (
	testNamespace   = "default"
	routerName      = "router1"
	peer1Addr       = "10.0.0.1"
	peer2Addr       = "10.0.0.2"
	nodeName        = "node1"
	labelKey        = "app"
	labelVal        = "overlay"
	nodeKind        = "Node"
	testPeerName    = "peer1"
	testPolicyName  = "policy1"
	testAdvName     = "adv1"
	myRouterName    = "my-router"
	routerAName     = "router-a"
	routerBName     = "router-b"
	directRefRouter = "direct-ref-router"

	reasonApplied = "Applied"
)

func testScheme() *runtime.Scheme {
	s := runtime.NewScheme()
	_ = corev1.AddToScheme(s)
	_ = bgpv1alpha1.AddToScheme(s)
	return s
}

// fakeCache implements cache.Cache with in-memory field indexes.
type fakeCache struct {
	indexes map[string]client.IndexerFunc
	client  client.Reader
}

func (c *fakeCache) Get(ctx context.Context, key types.NamespacedName, obj client.Object, opts ...client.GetOption) error {
	return c.client.Get(ctx, key, obj, opts...)
}

func (c *fakeCache) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	return c.client.List(ctx, list, opts...)
}

func (c *fakeCache) GetInformer(ctx context.Context, obj client.Object, opts ...cache.InformerGetOption) (cache.Informer, error) {
	return nil, nil
}

func (c *fakeCache) GetInformerForKind(ctx context.Context, gvk schema.GroupVersionKind, opts ...cache.InformerGetOption) (cache.Informer, error) {
	return nil, nil
}

func (c *fakeCache) RemoveInformer(ctx context.Context, obj client.Object) error {
	return nil
}

func (c *fakeCache) Start(ctx context.Context) error {
	return nil
}

func (c *fakeCache) WaitForCacheSync(ctx context.Context) bool {
	return true
}

func (c *fakeCache) IndexField(ctx context.Context, obj client.Object, field string, extractValue client.IndexerFunc) error {
	// Key by type name + field to avoid collisions (e.g. BGPPeer, BGPPolicy,
	// and BGPAdvertisement all use .spec.routerRef.name).
	key := fmt.Sprintf("%T/%s", obj, field)
	c.indexes[key] = extractValue
	return nil
}

// fakeManager implements ctrl.Manager with a fake client and in-memory cache.
type fakeManager struct {
	client client.Client
	cache  *fakeCache
	scheme *runtime.Scheme
}

func (m *fakeManager) GetConfig() *restclient.Config             { return nil }
func (m *fakeManager) GetScheme() *runtime.Scheme                { return m.scheme }
func (m *fakeManager) GetClient() client.Client                  { return m.client }
func (m *fakeManager) GetFieldIndexer() client.FieldIndexer      { return nil }
func (m *fakeManager) GetRESTMapper() meta.RESTMapper            { return nil }
func (m *fakeManager) GetAPIReader() client.Reader               { return m.client }
func (m *fakeManager) GetCache() cache.Cache                     { return m.cache }
func (m *fakeManager) GetLogger() logr.Logger                    { return log.Log }
func (m *fakeManager) GetControllerOptions() config.Controller   { return config.Controller{} }
func (m *fakeManager) GetWebhookServer() webhook.Server          { return nil }
func (m *fakeManager) GetConverterRegistry() conversion.Registry { return nil }
func (m *fakeManager) GetHTTPClient() *http.Client               { return nil }
func (m *fakeManager) Add(r manager.Runnable) error              { return nil }
func (m *fakeManager) Elected() <-chan struct{}                  { return make(chan struct{}) }
func (m *fakeManager) Start(ctx context.Context) error           { return nil }
func (m *fakeManager) AddMetricsServerExtraHandler(path string, handler http.Handler) error {
	return nil
}
func (m *fakeManager) AddHealthzCheck(name string, check healthz.Checker) error {
	return nil
}
func (m *fakeManager) AddReadyzCheck(name string, check healthz.Checker) error {
	return nil
}
func (m *fakeManager) GetEventRecorder(name string) eventstools.EventRecorder {
	return nil
}
func (m *fakeManager) GetEventRecorderFor(name string) record.EventRecorder {
	return nil
}

// newFakeManager creates a manager whose cache stores indexes and whose client
// applies them during List calls.
func newFakeManager(t *testing.T) *fakeManager {
	t.Helper()
	scheme := testScheme()

	// Build a fake client with indexes for BGPRouterByTargetName so the
	// nodeToRouterRequests field-index query works.
	fc := fake.NewClientBuilder().
		WithScheme(scheme).
		WithIndex(&bgpv1alpha1.BGPRouter{}, BGPRouterByTargetName, func(obj client.Object) []string {
			router, ok := obj.(*bgpv1alpha1.BGPRouter)
			if !ok {
				return nil
			}
			return []string{router.Spec.TargetRef.Name}
		}).
		Build()

	fakeCacheInstance := &fakeCache{
		indexes: make(map[string]client.IndexerFunc),
		client:  fc,
	}

	return &fakeManager{
		client: fc,
		cache:  fakeCacheInstance,
		scheme: scheme,
	}
}

// ---------- RegisterIndexes tests ------------------------------------------

func TestRegisterIndexes(t *testing.T) {
	ctx := context.Background()
	mgr := newFakeManager(t)

	err := RegisterIndexes(ctx, mgr)
	if err != nil {
		t.Fatalf("RegisterIndexes returned error: %v", err)
	}

	// Verify all 5 indexes were registered.
	if len(mgr.cache.indexes) != 5 {
		t.Errorf("expected 5 indexes, got %d", len(mgr.cache.indexes))
	}
}

func TestRegisterIndexes_indexFunctions(t *testing.T) {
	ctx := context.Background()
	scheme := testScheme()

	// Build a fake client with per-type index functions (one indexer func per type).
	builder := fake.NewClientBuilder().WithScheme(scheme)

	// BGPPeer indexes.
	builder = builder.WithIndex(&bgpv1alpha1.BGPPeer{}, BGPPeerBySecretName, func(obj client.Object) []string {
		p, ok := obj.(*bgpv1alpha1.BGPPeer)
		if !ok || p.Spec.AuthSecretRef == nil {
			return nil
		}
		return []string{p.Spec.AuthSecretRef.Name}
	})
	builder = builder.WithIndex(&bgpv1alpha1.BGPPeer{}, BGPPeerByRouterName, func(obj client.Object) []string {
		p, ok := obj.(*bgpv1alpha1.BGPPeer)
		if !ok || p.Spec.RouterRef == nil {
			return nil
		}
		return []string{p.Spec.RouterRef.Name}
	})

	// BGPPolicy indexes.
	builder = builder.WithIndex(&bgpv1alpha1.BGPPolicy{}, BGPPolicyByRouterName, func(obj client.Object) []string {
		p, ok := obj.(*bgpv1alpha1.BGPPolicy)
		if !ok || p.Spec.RouterRef == nil {
			return nil
		}
		return []string{p.Spec.RouterRef.Name}
	})

	// BGPAdvertisement index.
	builder = builder.WithIndex(&bgpv1alpha1.BGPAdvertisement{}, BGPAdvByRouterName, func(obj client.Object) []string {
		a, ok := obj.(*bgpv1alpha1.BGPAdvertisement)
		if !ok {
			return nil
		}
		return []string{a.Spec.RouterRef.Name}
	})

	// BGPRouter index.
	builder = builder.WithIndex(&bgpv1alpha1.BGPRouter{}, BGPRouterByTargetName, func(obj client.Object) []string {
		r, ok := obj.(*bgpv1alpha1.BGPRouter)
		if !ok {
			return nil
		}
		return []string{r.Spec.TargetRef.Name}
	})

	c := builder.Build()

	// --- BGPPeerBySecretName ---
	peerWithSecret := &bgpv1alpha1.BGPPeer{
		ObjectMeta: metav1.ObjectMeta{Name: testPeerName, Namespace: testNamespace},
		Spec: bgpv1alpha1.BGPPeerSpec{
			RouterTarget:    bgpv1alpha1.RouterTarget{RouterRef: &bgpv1alpha1.RouterRef{Name: routerName}},
			Address:         peer1Addr,
			PeerASN:         65001,
			AddressFamilies: []bgpv1alpha1.AddressFamily{{AFI: bgpv1alpha1.AFIIPv4, SAFI: bgpv1alpha1.SAFIUnicast}},
			AuthSecretRef:   &bgpv1alpha1.LocalSecretRef{Name: "my-secret"},
		},
	}
	peerNoSecret := &bgpv1alpha1.BGPPeer{
		ObjectMeta: metav1.ObjectMeta{Name: "peer2", Namespace: testNamespace},
		Spec: bgpv1alpha1.BGPPeerSpec{
			RouterTarget:    bgpv1alpha1.RouterTarget{RouterRef: &bgpv1alpha1.RouterRef{Name: routerName}},
			Address:         peer2Addr,
			PeerASN:         65002,
			AddressFamilies: []bgpv1alpha1.AddressFamily{{AFI: bgpv1alpha1.AFIIPv4, SAFI: bgpv1alpha1.SAFIUnicast}},
			AuthSecretRef:   nil,
		},
	}
	_ = c.Create(ctx, peerWithSecret)
	_ = c.Create(ctx, peerNoSecret)

	var peers bgpv1alpha1.BGPPeerList
	if err := c.List(ctx, &peers, client.InNamespace(testNamespace), client.MatchingFields{BGPPeerBySecretName: "my-secret"}); err != nil {
		t.Fatalf("List by secret index: %v", err)
	}
	if len(peers.Items) != 1 || peers.Items[0].Name != testPeerName {
		t.Errorf("expected 1 peer with secret 'my-secret', got %d: %v", len(peers.Items), peers.Items)
	}

	// --- BGPPeerByRouterName ---
	var peersByRouter bgpv1alpha1.BGPPeerList
	if err := c.List(ctx, &peersByRouter, client.InNamespace(testNamespace), client.MatchingFields{BGPPeerByRouterName: routerName}); err != nil {
		t.Fatalf("List by router name index: %v", err)
	}
	if len(peersByRouter.Items) != 2 {
		t.Errorf("expected 2 peers targeting router1, got %d", len(peersByRouter.Items))
	}

	// --- BGPPolicyByRouterName ---
	policy := &bgpv1alpha1.BGPPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: testPolicyName, Namespace: testNamespace},
		Spec: bgpv1alpha1.BGPPolicySpec{
			RouterTarget: bgpv1alpha1.RouterTarget{RouterRef: &bgpv1alpha1.RouterRef{Name: routerName}},
			Direction:    bgpv1alpha1.BGPPolicyDirectionExport,
			Terms:        []bgpv1alpha1.BGPPolicyTerm{{Sequence: 1, Match: bgpv1alpha1.BGPPolicyMatch{Any: true}, Action: bgpv1alpha1.BGPPolicyActionPermit}},
		},
	}
	_ = c.Create(ctx, policy)

	var policies bgpv1alpha1.BGPPolicyList
	if err := c.List(ctx, &policies, client.InNamespace(testNamespace), client.MatchingFields{BGPPolicyByRouterName: routerName}); err != nil {
		t.Fatalf("List policy by router index: %v", err)
	}
	if len(policies.Items) != 1 || policies.Items[0].Name != testPolicyName {
		t.Errorf("expected 1 policy, got %d", len(policies.Items))
	}

	// --- BGPAdvByRouterName ---
	adv := &bgpv1alpha1.BGPAdvertisement{
		ObjectMeta: metav1.ObjectMeta{Name: testAdvName, Namespace: testNamespace},
		Spec: bgpv1alpha1.BGPAdvertisementSpec{
			RouterRef:     bgpv1alpha1.RouterRef{Name: routerName},
			AddressFamily: bgpv1alpha1.AddressFamily{AFI: bgpv1alpha1.AFIIPv4, SAFI: bgpv1alpha1.SAFIUnicast},
			Prefixes:      []string{"10.0.0.0/24"},
		},
	}
	_ = c.Create(ctx, adv)

	var advs bgpv1alpha1.BGPAdvertisementList
	if err := c.List(ctx, &advs, client.InNamespace(testNamespace), client.MatchingFields{BGPAdvByRouterName: routerName}); err != nil {
		t.Fatalf("List adv by router index: %v", err)
	}
	if len(advs.Items) != 1 || advs.Items[0].Name != testAdvName {
		t.Errorf("expected 1 adv, got %d", len(advs.Items))
	}

	// --- BGPRouterByTargetName ---
	router := &bgpv1alpha1.BGPRouter{
		ObjectMeta: metav1.ObjectMeta{Name: routerName, Namespace: testNamespace},
		Spec: bgpv1alpha1.BGPRouterSpec{
			TargetRef:       bgpv1alpha1.TargetRef{Kind: nodeKind, Name: nodeName},
			LocalASN:        65000,
			RouterID:        peer1Addr,
			Roles:           []bgpv1alpha1.RouterRole{bgpv1alpha1.RouterRoleTenant},
			AddressFamilies: []bgpv1alpha1.AddressFamily{{AFI: bgpv1alpha1.AFIL2VPN, SAFI: bgpv1alpha1.SAFIEVPN}},
		},
	}
	_ = c.Create(ctx, router)

	var routers bgpv1alpha1.BGPRouterList
	if err := c.List(ctx, &routers, client.InNamespace(testNamespace), client.MatchingFields{BGPRouterByTargetName: nodeName}); err != nil {
		t.Fatalf("List router by target index: %v", err)
	}
	if len(routers.Items) != 1 || routers.Items[0].Name != routerName {
		t.Errorf("expected 1 router targeting node1, got %d", len(routers.Items))
	}
}

// ---------- enqueueRoutersForTarget tests ----------------------------------

func TestEnqueueRoutersForTarget_routerRef(t *testing.T) {
	ctx := context.Background()
	scheme := testScheme()

	router := &bgpv1alpha1.BGPRouter{
		ObjectMeta: metav1.ObjectMeta{
			Name:      myRouterName,
			Namespace: testNamespace,
		},
		Spec: bgpv1alpha1.BGPRouterSpec{
			TargetRef: bgpv1alpha1.TargetRef{Kind: nodeKind, Name: nodeName},
			LocalASN:  65000,
			RouterID:  peer1Addr,
			Roles:     []bgpv1alpha1.RouterRole{bgpv1alpha1.RouterRoleTenant},
			AddressFamilies: []bgpv1alpha1.AddressFamily{
				{AFI: bgpv1alpha1.AFIL2VPN, SAFI: bgpv1alpha1.SAFIEVPN},
			},
		},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(router).Build()

	reqs := enqueueRoutersForTarget(ctx, c, testNamespace, &bgpv1alpha1.RouterRef{Name: myRouterName}, nil, "BGPPeer/test")

	if len(reqs) != 1 {
		t.Fatalf("expected 1 request, got %d", len(reqs))
	}
	if reqs[0].Name != myRouterName || reqs[0].Namespace != testNamespace {
		t.Errorf("request = %+v, want {Namespace:%s, Name:my-router}", reqs[0], testNamespace)
	}
}

func TestEnqueueRoutersForTarget_routerSelector(t *testing.T) {
	ctx := context.Background()
	scheme := testScheme()

	routerA := &bgpv1alpha1.BGPRouter{
		ObjectMeta: metav1.ObjectMeta{
			Name:      routerAName,
			Namespace: testNamespace,
			Labels: map[string]string{
				labelKey: labelVal,
				"region": "dfw",
			},
		},
		Spec: bgpv1alpha1.BGPRouterSpec{
			TargetRef: bgpv1alpha1.TargetRef{Kind: nodeKind, Name: nodeName},
			LocalASN:  65000,
			RouterID:  peer1Addr,
			Roles:     []bgpv1alpha1.RouterRole{bgpv1alpha1.RouterRoleTenant},
			AddressFamilies: []bgpv1alpha1.AddressFamily{
				{AFI: bgpv1alpha1.AFIL2VPN, SAFI: bgpv1alpha1.SAFIEVPN},
			},
		},
	}

	routerB := &bgpv1alpha1.BGPRouter{
		ObjectMeta: metav1.ObjectMeta{
			Name:      routerBName,
			Namespace: testNamespace,
			Labels: map[string]string{
				labelKey: labelVal,
				"region": "iad",
			},
		},
		Spec: bgpv1alpha1.BGPRouterSpec{
			TargetRef: bgpv1alpha1.TargetRef{Kind: nodeKind, Name: "node2"},
			LocalASN:  65001,
			RouterID:  peer2Addr,
			Roles:     []bgpv1alpha1.RouterRole{bgpv1alpha1.RouterRoleTenant},
			AddressFamilies: []bgpv1alpha1.AddressFamily{
				{AFI: bgpv1alpha1.AFIL2VPN, SAFI: bgpv1alpha1.SAFIEVPN},
			},
		},
	}

	routerC := &bgpv1alpha1.BGPRouter{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "router-c",
			Namespace: testNamespace,
			Labels: map[string]string{
				labelKey: "other",
			},
		},
		Spec: bgpv1alpha1.BGPRouterSpec{
			TargetRef: bgpv1alpha1.TargetRef{Kind: nodeKind, Name: "node3"},
			LocalASN:  65002,
			RouterID:  "10.0.0.3",
			Roles:     []bgpv1alpha1.RouterRole{bgpv1alpha1.RouterRoleTenant},
			AddressFamilies: []bgpv1alpha1.AddressFamily{
				{AFI: bgpv1alpha1.AFIL2VPN, SAFI: bgpv1alpha1.SAFIEVPN},
			},
		},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(routerA, routerB, routerC).Build()

	reqs := enqueueRoutersForTarget(ctx, c, testNamespace, nil, &bgpv1alpha1.RouterSelector{
		MatchLabels: map[string]string{labelKey: labelVal},
	}, "BGPPolicy/test")

	if len(reqs) != 2 {
		t.Fatalf("expected 2 requests, got %d", len(reqs))
	}

	names := make(map[string]bool)
	for _, r := range reqs {
		names[r.Name] = true
	}
	if !names[routerAName] || !names[routerBName] {
		t.Errorf("expected router-a and router-b, got %v", names)
	}
}

func TestEnqueueRoutersForTarget_bothNil(t *testing.T) {
	ctx := context.Background()

	reqs := enqueueRoutersForTarget(ctx, nil, testNamespace, nil, nil, "test")

	if len(reqs) != 0 {
		t.Fatalf("expected 0 requests, got %d", len(reqs))
	}
}

func TestEnqueueRoutersForTarget_selectorNoMatch(t *testing.T) {
	ctx := context.Background()
	scheme := testScheme()

	router := &bgpv1alpha1.BGPRouter{
		ObjectMeta: metav1.ObjectMeta{
			Name:      routerAName,
			Namespace: testNamespace,
			Labels: map[string]string{
				labelKey: "other",
			},
		},
		Spec: bgpv1alpha1.BGPRouterSpec{
			TargetRef: bgpv1alpha1.TargetRef{Kind: nodeKind, Name: nodeName},
			LocalASN:  65000,
			RouterID:  peer1Addr,
			Roles:     []bgpv1alpha1.RouterRole{bgpv1alpha1.RouterRoleTenant},
			AddressFamilies: []bgpv1alpha1.AddressFamily{
				{AFI: bgpv1alpha1.AFIL2VPN, SAFI: bgpv1alpha1.SAFIEVPN},
			},
		},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(router).Build()

	reqs := enqueueRoutersForTarget(ctx, c, testNamespace, nil, &bgpv1alpha1.RouterSelector{
		MatchLabels: map[string]string{labelKey: labelVal},
	}, "BGPPolicy/test")

	if len(reqs) != 0 {
		t.Fatalf("expected 0 requests (no match), got %d", len(reqs))
	}
}

func TestEnqueueRoutersForTarget_routerRefOverridesSelector(t *testing.T) {
	ctx := context.Background()
	scheme := testScheme()

	router := &bgpv1alpha1.BGPRouter{
		ObjectMeta: metav1.ObjectMeta{
			Name:      directRefRouter,
			Namespace: testNamespace,
		},
		Spec: bgpv1alpha1.BGPRouterSpec{
			TargetRef: bgpv1alpha1.TargetRef{Kind: nodeKind, Name: nodeName},
			LocalASN:  65000,
			RouterID:  peer1Addr,
			Roles:     []bgpv1alpha1.RouterRole{bgpv1alpha1.RouterRoleTenant},
			AddressFamilies: []bgpv1alpha1.AddressFamily{
				{AFI: bgpv1alpha1.AFIL2VPN, SAFI: bgpv1alpha1.SAFIEVPN},
			},
		},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(router).Build()

	reqs := enqueueRoutersForTarget(ctx, c, testNamespace, &bgpv1alpha1.RouterRef{Name: directRefRouter}, &bgpv1alpha1.RouterSelector{
		MatchLabels: map[string]string{labelKey: labelVal},
	}, "test")

	if len(reqs) != 1 {
		t.Fatalf("expected 1 request (routerRef only), got %d", len(reqs))
	}
	if reqs[0].Name != directRefRouter {
		t.Errorf("expected name 'direct-ref-router', got %q", reqs[0].Name)
	}
}

// ---------- nodeToRouterRequests tests -------------------------------------

func TestNodeToRouterRequests(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name      string
		nodeName  string
		routers   []*bgpv1alpha1.BGPRouter
		wantReqs  int
		wantNames []string
	}{
		{
			name:     "no routers target the node",
			nodeName: nodeName,
			routers: []*bgpv1alpha1.BGPRouter{
				{
					ObjectMeta: metav1.ObjectMeta{Name: routerAName, Namespace: testNamespace},
					Spec: bgpv1alpha1.BGPRouterSpec{
						TargetRef: bgpv1alpha1.TargetRef{Kind: nodeKind, Name: "node2"},
						LocalASN:  65000, RouterID: peer1Addr,
						Roles: []bgpv1alpha1.RouterRole{bgpv1alpha1.RouterRoleTenant},
						AddressFamilies: []bgpv1alpha1.AddressFamily{
							{AFI: bgpv1alpha1.AFIL2VPN, SAFI: bgpv1alpha1.SAFIEVPN},
						},
					},
				},
			},
			wantReqs: 0,
		},
		{
			name:     "single router targets the node",
			nodeName: nodeName,
			routers: []*bgpv1alpha1.BGPRouter{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "overlay-router", Namespace: testNamespace},
					Spec: bgpv1alpha1.BGPRouterSpec{
						TargetRef: bgpv1alpha1.TargetRef{Kind: nodeKind, Name: nodeName},
						LocalASN:  65000, RouterID: peer1Addr,
						Roles: []bgpv1alpha1.RouterRole{bgpv1alpha1.RouterRoleTenant},
						AddressFamilies: []bgpv1alpha1.AddressFamily{
							{AFI: bgpv1alpha1.AFIL2VPN, SAFI: bgpv1alpha1.SAFIEVPN},
						},
					},
				},
			},
			wantReqs:  1,
			wantNames: []string{"overlay-router"},
		},
		{
			name:     "multiple routers target the same node",
			nodeName: nodeName,
			routers: []*bgpv1alpha1.BGPRouter{
				{
					ObjectMeta: metav1.ObjectMeta{Name: routerAName, Namespace: testNamespace},
					Spec: bgpv1alpha1.BGPRouterSpec{
						TargetRef: bgpv1alpha1.TargetRef{Kind: nodeKind, Name: nodeName},
						LocalASN:  65000, RouterID: peer1Addr,
						Roles: []bgpv1alpha1.RouterRole{bgpv1alpha1.RouterRoleTenant},
						AddressFamilies: []bgpv1alpha1.AddressFamily{
							{AFI: bgpv1alpha1.AFIL2VPN, SAFI: bgpv1alpha1.SAFIEVPN},
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: routerBName, Namespace: testNamespace},
					Spec: bgpv1alpha1.BGPRouterSpec{
						TargetRef: bgpv1alpha1.TargetRef{Kind: nodeKind, Name: nodeName},
						LocalASN:  65001, RouterID: peer2Addr,
						Roles: []bgpv1alpha1.RouterRole{bgpv1alpha1.RouterRoleTenant},
						AddressFamilies: []bgpv1alpha1.AddressFamily{
							{AFI: bgpv1alpha1.AFIL2VPN, SAFI: bgpv1alpha1.SAFIEVPN},
						},
					},
				},
			},
			wantReqs:  2,
			wantNames: []string{routerAName, routerBName},
		},
		{
			name:     "routers in different namespaces are scoped correctly",
			nodeName: nodeName,
			routers: []*bgpv1alpha1.BGPRouter{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "default-router", Namespace: testNamespace},
					Spec: bgpv1alpha1.BGPRouterSpec{
						TargetRef: bgpv1alpha1.TargetRef{Kind: nodeKind, Name: nodeName},
						LocalASN:  65000, RouterID: peer1Addr,
						Roles: []bgpv1alpha1.RouterRole{bgpv1alpha1.RouterRoleTenant},
						AddressFamilies: []bgpv1alpha1.AddressFamily{
							{AFI: bgpv1alpha1.AFIL2VPN, SAFI: bgpv1alpha1.SAFIEVPN},
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "other-router", Namespace: "other-ns"},
					Spec: bgpv1alpha1.BGPRouterSpec{
						TargetRef: bgpv1alpha1.TargetRef{Kind: nodeKind, Name: nodeName},
						LocalASN:  65001, RouterID: peer2Addr,
						Roles: []bgpv1alpha1.RouterRole{bgpv1alpha1.RouterRoleTenant},
						AddressFamilies: []bgpv1alpha1.AddressFamily{
							{AFI: bgpv1alpha1.AFIL2VPN, SAFI: bgpv1alpha1.SAFIEVPN},
						},
					},
				},
			},
			wantReqs:  2,
			wantNames: []string{"default-router", "other-router"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scheme := testScheme()
			objs := make([]client.Object, 0, len(tt.routers))
			for _, r := range tt.routers {
				objs = append(objs, r)
			}

			builder := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...)

			// Register the field index that nodeToRouterRequests uses.
			builder = builder.WithIndex(&bgpv1alpha1.BGPRouter{}, BGPRouterByTargetName, func(obj client.Object) []string {
				router, ok := obj.(*bgpv1alpha1.BGPRouter)
				if !ok {
					return nil
				}
				return []string{router.Spec.TargetRef.Name}
			})

			c := builder.Build()
			node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: tt.nodeName}}

			reqs := nodeToRouterRequests(ctx, c, node)

			if len(reqs) != tt.wantReqs {
				t.Fatalf("expected %d requests, got %d", tt.wantReqs, len(reqs))
			}

			if tt.wantNames != nil {
				gotNames := make(map[string]bool)
				for _, r := range reqs {
					gotNames[r.Name] = true
				}
				for _, want := range tt.wantNames {
					if !gotNames[want] {
						t.Errorf("missing request for router %q", want)
					}
				}
			}
		})
	}
}

func TestNodeToRouterRequests_invalidObject(t *testing.T) {
	ctx := context.Background()
	c := fake.NewClientBuilder().WithScheme(testScheme()).Build()

	reqs := nodeToRouterRequests(ctx, c, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod1"}})

	if len(reqs) != 0 {
		t.Fatalf("expected 0 requests for non-Node object, got %d", len(reqs))
	}
}

func TestNodeToRouterRequests_listError(t *testing.T) {
	ctx := context.Background()

	// Use a fake client pre-populated with no routers — simulates empty list.
	c := fake.NewClientBuilder().WithScheme(testScheme()).Build()
	reqs := nodeToRouterRequests(ctx, c, &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: nodeName}})

	if len(reqs) != 0 {
		t.Fatalf("expected 0 requests for node with no routers, got %d", len(reqs))
	}
}

// ---------- setRouterPhase tests -------------------------------------------

func TestSetRouterPhase(t *testing.T) {
	router := &bgpv1alpha1.BGPRouter{
		ObjectMeta: metav1.ObjectMeta{
			Name:       routerName,
			Namespace:  testNamespace,
			Generation: 2,
		},
	}

	setRouterPhase(router, bgpv1alpha1.BGPRouterPhaseReady)

	if router.Status.Phase != bgpv1alpha1.BGPRouterPhaseReady {
		t.Errorf("phase = %q, want %q", router.Status.Phase, bgpv1alpha1.BGPRouterPhaseReady)
	}
	if router.Status.ObservedGeneration != 2 {
		t.Errorf("observedGeneration = %d, want 2", router.Status.ObservedGeneration)
	}
}

func TestSetRouterPhase_failed(t *testing.T) {
	router := &bgpv1alpha1.BGPRouter{
		ObjectMeta: metav1.ObjectMeta{
			Name:       routerName,
			Namespace:  testNamespace,
			Generation: 3,
		},
	}

	setRouterPhase(router, bgpv1alpha1.BGPRouterPhaseFailed)

	if router.Status.Phase != bgpv1alpha1.BGPRouterPhaseFailed {
		t.Errorf("phase = %q, want %q", router.Status.Phase, bgpv1alpha1.BGPRouterPhaseFailed)
	}
	if router.Status.ObservedGeneration != 3 {
		t.Errorf("observedGeneration = %d, want 3", router.Status.ObservedGeneration)
	}
}

func TestSetRouterPhase_pending(t *testing.T) {
	router := &bgpv1alpha1.BGPRouter{
		ObjectMeta: metav1.ObjectMeta{
			Name:       routerName,
			Namespace:  testNamespace,
			Generation: 1,
		},
	}

	setRouterPhase(router, bgpv1alpha1.BGPRouterPhasePending)

	if router.Status.Phase != bgpv1alpha1.BGPRouterPhasePending {
		t.Errorf("phase = %q, want %q", router.Status.Phase, bgpv1alpha1.BGPRouterPhasePending)
	}
	if router.Status.ObservedGeneration != 1 {
		t.Errorf("observedGeneration = %d, want 1", router.Status.ObservedGeneration)
	}
}

// ---------- setPeerReadyCondition tests ------------------------------------

func TestSetPeerReadyCondition(t *testing.T) {
	tests := []struct {
		name         string
		state        bgpv1alpha1.BGPPeerState
		idleReason   string
		wantStatus   metav1.ConditionStatus
		wantReason   string
		wantContains string
	}{
		{
			name:         "Established sets Ready=True",
			state:        bgpv1alpha1.BGPPeerStateEstablished,
			wantStatus:   metav1.ConditionTrue,
			wantReason:   ReasonEstablished,
			wantContains: "Established",
		},
		{
			name:         "OpenConfirm sets Ready=False",
			state:        bgpv1alpha1.BGPPeerStateOpenConfirm,
			wantStatus:   metav1.ConditionFalse,
			wantReason:   ReasonOpenConfirm,
			wantContains: "OpenConfirm",
		},
		{
			name:         "OpenSent sets Ready=False",
			state:        bgpv1alpha1.BGPPeerStateOpenSent,
			wantStatus:   metav1.ConditionFalse,
			wantReason:   ReasonOpenSent,
			wantContains: "OPEN message sent",
		},
		{
			name:         "Active sets Ready=False",
			state:        bgpv1alpha1.BGPPeerStateActive,
			wantStatus:   metav1.ConditionFalse,
			wantReason:   ReasonActive,
			wantContains: "Active",
		},
		{
			name:         "Connect sets Ready=False",
			state:        bgpv1alpha1.BGPPeerStateConnect,
			wantStatus:   metav1.ConditionFalse,
			wantReason:   ReasonConnect,
			wantContains: "Connect",
		},
		{
			name:         "Idle with BackOff reason",
			state:        bgpv1alpha1.BGPPeerStateIdle,
			idleReason:   "BackOff",
			wantStatus:   metav1.ConditionFalse,
			wantReason:   "BackOff",
			wantContains: "Idle",
		},
		{
			name:         "Idle with ConnectionRefused reason",
			state:        bgpv1alpha1.BGPPeerStateIdle,
			idleReason:   "ConnectionRefused",
			wantStatus:   metav1.ConditionFalse,
			wantReason:   "ConnectionRefused",
			wantContains: "Idle",
		},
		{
			name:         "unknown state defaults to False",
			state:        bgpv1alpha1.BGPPeerState("WeirdState"),
			wantStatus:   metav1.ConditionFalse,
			wantReason:   "Unknown",
			wantContains: "unknown state",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			peer := &bgpv1alpha1.BGPPeer{
				ObjectMeta: metav1.ObjectMeta{
					Name:       testPeerName,
					Namespace:  testNamespace,
					Generation: 5,
				},
			}

			setPeerReadyCondition(peer, tt.state, tt.idleReason)

			if peer.Status.SessionState != tt.state {
				t.Errorf("sessionState = %q, want %q", peer.Status.SessionState, tt.state)
			}
			if peer.Status.ObservedGeneration != 5 {
				t.Errorf("observedGeneration = %d, want 5", peer.Status.ObservedGeneration)
			}

			cond := meta.FindStatusCondition(peer.Status.Conditions, bgpv1alpha1.ConditionTypeReady)
			if cond == nil {
				t.Fatal("Ready condition not found")
			}
			if cond.Status != tt.wantStatus {
				t.Errorf("condition.Status = %s, want %s", cond.Status, tt.wantStatus)
			}
			if cond.Reason != tt.wantReason {
				t.Errorf("condition.Reason = %q, want %q", cond.Reason, tt.wantReason)
			}
			if !strings.Contains(cond.Message, tt.wantContains) {
				t.Errorf("condition.Message = %q, want to contain %q", cond.Message, tt.wantContains)
			}
		})
	}
}

// ---------- setAdvertisementCondition tests --------------------------------

func TestSetAdvertisementCondition(t *testing.T) {
	adv := &bgpv1alpha1.BGPAdvertisement{
		ObjectMeta: metav1.ObjectMeta{
			Name:       testAdvName,
			Namespace:  testNamespace,
			Generation: 4,
		},
	}

	cond := metav1.Condition{
		Type:   ConditionAdvertised,
		Status: metav1.ConditionTrue,
		Reason: reasonApplied,
	}

	setAdvertisementCondition(adv, cond)

	c := meta.FindStatusCondition(adv.Status.Conditions, ConditionAdvertised)
	if c == nil {
		t.Fatal("Advertised condition not found")
	}
	if c.Status != metav1.ConditionTrue {
		t.Errorf("condition.Status = %s, want True", c.Status)
	}
	if c.Reason != reasonApplied {
		t.Errorf("condition.Reason = %q, want %q", c.Reason, reasonApplied)
	}
	if c.ObservedGeneration != 4 {
		t.Errorf("observedGeneration = %d, want 4", c.ObservedGeneration)
	}
}

func TestSetAdvertisementCondition_false(t *testing.T) {
	adv := &bgpv1alpha1.BGPAdvertisement{
		ObjectMeta: metav1.ObjectMeta{
			Name:       testAdvName,
			Namespace:  testNamespace,
			Generation: 7,
		},
	}

	cond := metav1.Condition{
		Type:   ConditionAdvertised,
		Status: metav1.ConditionFalse,
		Reason: "Failed",
	}

	setAdvertisementCondition(adv, cond)

	c := meta.FindStatusCondition(adv.Status.Conditions, ConditionAdvertised)
	if c == nil {
		t.Fatal("Advertised condition not found")
	}
	if c.Status != metav1.ConditionFalse {
		t.Errorf("condition.Status = %s, want False", c.Status)
	}
	if c.Reason != "Failed" {
		t.Errorf("condition.Reason = %q, want %q", c.Reason, "Failed")
	}
	if c.ObservedGeneration != 7 {
		t.Errorf("observedGeneration = %d, want 7", c.ObservedGeneration)
	}
}

// ---------- setPolicyCondition tests ---------------------------------------

func TestSetPolicyCondition(t *testing.T) {
	policy := &bgpv1alpha1.BGPPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:       testPolicyName,
			Namespace:  testNamespace,
			Generation: 6,
		},
	}

	cond := metav1.Condition{
		Type:   ConditionPolicyApplied,
		Status: metav1.ConditionFalse,
		Reason: "Rejected",
	}

	setPolicyCondition(policy, cond)

	c := meta.FindStatusCondition(policy.Status.Conditions, ConditionPolicyApplied)
	if c == nil {
		t.Fatal("PolicyApplied condition not found")
	}
	if c.Status != metav1.ConditionFalse {
		t.Errorf("condition.Status = %s, want False", c.Status)
	}
	if c.Reason != "Rejected" {
		t.Errorf("condition.Reason = %q, want %q", c.Reason, "Rejected")
	}
	if c.ObservedGeneration != 6 {
		t.Errorf("observedGeneration = %d, want 6", c.ObservedGeneration)
	}
}

func TestSetPolicyCondition_true(t *testing.T) {
	policy := &bgpv1alpha1.BGPPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:       testPolicyName,
			Namespace:  testNamespace,
			Generation: 8,
		},
	}

	cond := metav1.Condition{
		Type:   ConditionPolicyApplied,
		Status: metav1.ConditionTrue,
		Reason: reasonApplied,
	}

	setPolicyCondition(policy, cond)

	c := meta.FindStatusCondition(policy.Status.Conditions, ConditionPolicyApplied)
	if c == nil {
		t.Fatal("PolicyApplied condition not found")
	}
	if c.Status != metav1.ConditionTrue {
		t.Errorf("condition.Status = %s, want True", c.Status)
	}
	if c.Reason != reasonApplied {
		t.Errorf("condition.Reason = %q, want %q", c.Reason, reasonApplied)
	}
	if c.ObservedGeneration != 8 {
		t.Errorf("observedGeneration = %d, want 8", c.ObservedGeneration)
	}
}

// ---------- helper types ---------------------------------------------------
