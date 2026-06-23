// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package reconcile

import (
	"context"
	"strings"
	"testing"
	"time"

	"go.datum.net/galactic/internal/model"
	bgpv1alpha1 "go.miloapis.com/cosmos/api/bgp/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

var testScheme = runtime.NewScheme()

const (
	namespace             = "default"
	nodeName              = "node1"
	peerAddr              = "192.0.2.1"
	routerID              = "10.0.0.1"
	prefix                = "192.168.1.0/24"
	routerName            = "overlay-router"
	nextHop               = "2001:db8::1"
	appLabel              = "app"
	appValue              = "galactic"
	tierLabel             = "tier"
	tierFrontend          = "frontend"
	directionImport       = "import"
	errUnsupportedAFISAFI = "unsupported AFI/SAFI"
)

func init() {
	_ = corev1.AddToScheme(testScheme)
	_ = bgpv1alpha1.AddToScheme(testScheme)
}

func fakeClient(objs ...client.Object) client.Client {
	return fake.NewClientBuilder().
		WithScheme(testScheme).
		WithStatusSubresource(&bgpv1alpha1.BGPRouter{}, &bgpv1alpha1.BGPPeer{}, &bgpv1alpha1.BGPAdvertisement{}, &bgpv1alpha1.BGPPolicy{}).
		WithIndex(&bgpv1alpha1.BGPAdvertisement{}, ".spec.routerRef.name", func(obj client.Object) []string {
			adv, ok := obj.(*bgpv1alpha1.BGPAdvertisement)
			if !ok || adv.Spec.RouterRef.Name == "" {
				return nil
			}
			return []string{adv.Spec.RouterRef.Name}
		}).
		WithObjects(objs...).
		Build()
}

// testRouter returns a BGPRouter targeting nodeName with the given roles.
func testRouter(name, nodeName string, roles []bgpv1alpha1.RouterRole, labels map[string]string) *bgpv1alpha1.BGPRouter {
	r := &bgpv1alpha1.BGPRouter{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: bgpv1alpha1.BGPRouterSpec{
			TargetRef: bgpv1alpha1.TargetRef{
				Kind: "Node",
				Name: nodeName,
			},
			LocalASN:        65000,
			RouterID:        routerID,
			AddressFamilies: []bgpv1alpha1.AddressFamily{{AFI: bgpv1alpha1.AFIL2VPN, SAFI: bgpv1alpha1.SAFIEVPN}},
		},
	}
	if len(roles) > 0 {
		r.Spec.Roles = roles
	}
	r.Labels = labels
	return r
}

// testNode returns a corev1.Node with the given IPv6 InternalIP address (IPv4 defaults to routerID).
func testNode(ipv6 string) *corev1.Node {
	addrs := []corev1.NodeAddress{
		{Type: corev1.NodeInternalIP, Address: routerID},
	}
	if ipv6 != "" {
		addrs = append(addrs, corev1.NodeAddress{Type: corev1.NodeInternalIP, Address: ipv6})
	}
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: nodeName},
		Status: corev1.NodeStatus{
			Addresses: addrs,
		},
	}
}

// testPeer returns a BGPPeer binding to routerName via routerRef.
func testPeer(name, routerName string, afs []bgpv1alpha1.AddressFamily, authSecret string) *bgpv1alpha1.BGPPeer {
	p := &bgpv1alpha1.BGPPeer{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: bgpv1alpha1.BGPPeerSpec{
			RouterTarget:    bgpv1alpha1.RouterTarget{RouterRef: &bgpv1alpha1.RouterRef{Name: routerName}},
			PeerASN:         65001,
			Address:         peerAddr,
			AddressFamilies: afs,
		},
	}
	if authSecret != "" {
		p.Spec.AuthSecretRef = &bgpv1alpha1.LocalSecretRef{Name: authSecret}
	}
	return p
}

// testPeerSelector returns a BGPPeer binding via routerSelector.
func testPeerSelector(name, labelKey, labelVal string, afs []bgpv1alpha1.AddressFamily) *bgpv1alpha1.BGPPeer {
	return &bgpv1alpha1.BGPPeer{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: bgpv1alpha1.BGPPeerSpec{
			RouterTarget: bgpv1alpha1.RouterTarget{
				RouterSelector: &bgpv1alpha1.RouterSelector{
					MatchLabels: map[string]string{labelKey: labelVal},
				},
			},
			PeerASN:         65001,
			Address:         peerAddr,
			AddressFamilies: afs,
		},
	}
}

// testPolicy returns a BGPPolicy binding to routerName via routerRef.
func testPolicy(name, routerName string, terms []bgpv1alpha1.BGPPolicyTerm) *bgpv1alpha1.BGPPolicy {
	return &bgpv1alpha1.BGPPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: bgpv1alpha1.BGPPolicySpec{
			RouterTarget: bgpv1alpha1.RouterTarget{RouterRef: &bgpv1alpha1.RouterRef{Name: routerName}},
			Direction:    directionImport,
			Terms:        terms,
		},
	}
}

// testPolicySelector returns a BGPPolicy binding via routerSelector.
func testPolicySelector(name, labelKey, labelVal string, direction bgpv1alpha1.BGPPolicyDirection, terms []bgpv1alpha1.BGPPolicyTerm) *bgpv1alpha1.BGPPolicy {
	return &bgpv1alpha1.BGPPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: bgpv1alpha1.BGPPolicySpec{
			RouterTarget: bgpv1alpha1.RouterTarget{
				RouterSelector: &bgpv1alpha1.RouterSelector{
					MatchLabels: map[string]string{labelKey: labelVal},
				},
			},
			Direction: direction,
			Terms:     terms,
		},
	}
}

// testAdv returns a BGPAdvertisement for the given router.
func testAdv(name, routerName string, af bgpv1alpha1.AddressFamily, prefixes []string) *bgpv1alpha1.BGPAdvertisement {
	return &bgpv1alpha1.BGPAdvertisement{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: bgpv1alpha1.BGPAdvertisementSpec{
			RouterRef:     bgpv1alpha1.RouterRef{Name: routerName},
			AddressFamily: af,
			Prefixes:      prefixes,
		},
	}
}

// testAuthSecret returns a Secret with a "password" key.
func testAuthSecret(name string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Data: map[string][]byte{"password": []byte("s3cret")},
	}
}

func TestBuildDesiredRouter(t *testing.T) {
	ctx := context.Background()

	peer := testPeer("peer1", routerName, []bgpv1alpha1.AddressFamily{
		{AFI: bgpv1alpha1.AFIIPv4, SAFI: bgpv1alpha1.SAFIUnicast},
	}, "")
	adv := testAdv("adv1", routerName, bgpv1alpha1.AddressFamily{AFI: bgpv1alpha1.AFIL2VPN, SAFI: bgpv1alpha1.SAFIEVPN},
		[]string{prefix})
	policy := testPolicy("pol1", routerName, []bgpv1alpha1.BGPPolicyTerm{
		{Sequence: 10, Match: bgpv1alpha1.BGPPolicyMatch{Any: true}, Action: bgpv1alpha1.BGPPolicyActionPermit},
	})
	node := testNode(nextHop)
	router := testRouter(routerName, nodeName, []bgpv1alpha1.RouterRole{bgpv1alpha1.RouterRoleTenant}, nil)

	tests := []struct {
		name    string
		objects []client.Object
		router  *bgpv1alpha1.BGPRouter
		wantErr string
		check   func(t *testing.T, dr *model.DesiredRouter)
		wantNil bool
	}{
		{
			name:    "happy path with peers, policies, and advertisements",
			objects: []client.Object{router, peer, adv, policy, node},
			router:  router,
			check: func(t *testing.T, dr *model.DesiredRouter) {
				t.Helper()
				if dr.Name != routerName {
					t.Errorf("DesiredRouter.Name = %q, want %q", dr.Name, routerName)
				}
				if dr.LocalASN != 65000 {
					t.Errorf("DesiredRouter.LocalASN = %d, want 65000", dr.LocalASN)
				}
				if dr.RouterID != routerID {
					t.Errorf("DesiredRouter.RouterID = %q, want %q", dr.RouterID, routerID)
				}
				if len(dr.Peers) != 1 {
					t.Fatalf("len(Peers) = %d, want 1", len(dr.Peers))
				}
				if dr.Peers[0].Name != "peer1" {
					t.Errorf("Peer[0].Name = %q, want %q", dr.Peers[0].Name, "peer1")
				}
				if len(dr.Advertisements) != 1 {
					t.Fatalf("len(Advertisements) = %d, want 1", len(dr.Advertisements))
				}
				if dr.Advertisements[0].NextHop != nextHop {
					t.Errorf("Advertisement[0].NextHop = %q, want %q", dr.Advertisements[0].NextHop, nextHop)
				}
				if len(dr.Policies) != 1 {
					t.Fatalf("len(Policies) = %d, want 1", len(dr.Policies))
				}
			},
		},
		{
			name:    "wrong node returns nil",
			objects: []client.Object{testRouter("other-router", "node2", []bgpv1alpha1.RouterRole{bgpv1alpha1.RouterRoleTenant}, nil), node},
			router:  testRouter("other-router", "node2", []bgpv1alpha1.RouterRole{bgpv1alpha1.RouterRoleTenant}, nil),
			wantNil: true,
		},
		{
			name:    "wrong role returns nil",
			objects: []client.Object{testRouter("overlay-router", nodeName, []bgpv1alpha1.RouterRole{bgpv1alpha1.RouterRoleFabric}, nil), node},
			router:  testRouter("overlay-router", nodeName, []bgpv1alpha1.RouterRole{bgpv1alpha1.RouterRoleFabric}, nil),
			wantNil: true,
		},
		{
			name:    "multi-role returns error",
			objects: []client.Object{testRouter("overlay-router", nodeName, []bgpv1alpha1.RouterRole{bgpv1alpha1.RouterRoleTenant, bgpv1alpha1.RouterRoleFabric}, nil), node},
			router:  testRouter("overlay-router", nodeName, []bgpv1alpha1.RouterRole{bgpv1alpha1.RouterRoleTenant, bgpv1alpha1.RouterRoleFabric}, nil),
			wantErr: "multi-role routers not supported",
		},
		{
			name:    "missing node returns error",
			objects: []client.Object{router},
			wantErr: "get node node1",
		},
		{
			name:    "missing auth secret returns error",
			objects: []client.Object{router, testPeer("peer1", "overlay-router", nil, "no-such-secret"), node},
			wantErr: "get auth secret default/no-such-secret for peer peer1",
		},
		{
			name:    "missing peer auth secret returns error",
			objects: []client.Object{router, testPeer("peer1", "overlay-router", nil, "no-such-secret"), node},
			wantErr: "get auth secret default/no-such-secret for peer peer1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k8s := fakeClient(tt.objects...)
			r := New(k8s, nodeName, "tenant")
			router := router
			if tt.router != nil {
				router = tt.router
			}
			dr, err := r.BuildDesiredRouter(ctx, router)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error %q does not contain %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantNil {
				if dr != nil {
					t.Fatalf("expected nil DesiredRouter, got %+v", dr)
				}
				return
			}
			if tt.check != nil {
				tt.check(t, dr)
			}
		})
	}
}

func TestBuildDesiredRouter_EVPNNoIPv6(t *testing.T) {
	ctx := context.Background()
	router := testRouter(routerName, nodeName, []bgpv1alpha1.RouterRole{bgpv1alpha1.RouterRoleTenant}, nil)
	// Node with only IPv4, no IPv6.
	node := testNode("")
	adv := testAdv("adv1", routerName, bgpv1alpha1.AddressFamily{AFI: bgpv1alpha1.AFIL2VPN, SAFI: bgpv1alpha1.SAFIEVPN},
		[]string{prefix})

	k8s := fakeClient(router, adv, node)
	r := New(k8s, nodeName, "tenant")
	_, err := r.BuildDesiredRouter(ctx, router)
	if err == nil {
		t.Fatal("expected error for EVPN without IPv6, got nil")
	}
	if !strings.Contains(err.Error(), "no IPv6 InternalIP") {
		t.Fatalf("error %q does not contain 'no IPv6 InternalIP'", err)
	}
}

func TestBuildDesiredRouter_EVPNWithIPv6(t *testing.T) {
	ctx := context.Background()
	router := testRouter(routerName, nodeName, []bgpv1alpha1.RouterRole{bgpv1alpha1.RouterRoleTenant}, nil)
	node := testNode(nextHop)
	adv := testAdv("adv1", routerName, bgpv1alpha1.AddressFamily{AFI: bgpv1alpha1.AFIL2VPN, SAFI: bgpv1alpha1.SAFIEVPN},
		[]string{prefix})

	k8s := fakeClient(router, adv, node)
	r := New(k8s, nodeName, "tenant")
	dr, err := r.BuildDesiredRouter(ctx, router)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dr == nil {
		t.Fatal("expected non-nil DesiredRouter")
	}
	if dr.Advertisements[0].NextHop != nextHop {
		t.Errorf("NextHop = %q, want %q", dr.Advertisements[0].NextHop, nextHop)
	}
}

func TestBuildDesiredRouter_AuthSecret(t *testing.T) {
	ctx := context.Background()
	secret := testAuthSecret("peer-auth")
	peer := testPeer("peer1", routerName, nil, "peer-auth")
	router := testRouter(routerName, nodeName, []bgpv1alpha1.RouterRole{bgpv1alpha1.RouterRoleTenant}, nil)
	node := testNode(nextHop)

	k8s := fakeClient(router, peer, secret, node)
	r := New(k8s, nodeName, "tenant")
	dr, err := r.BuildDesiredRouter(ctx, router)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dr == nil {
		t.Fatal("expected non-nil DesiredRouter")
	}
	if len(dr.Peers) != 1 {
		t.Fatalf("len(Peers) = %d, want 1", len(dr.Peers))
	}
	if dr.Peers[0].AuthPassword != "s3cret" {
		t.Errorf("AuthPassword = %q, want %q", dr.Peers[0].AuthPassword, "s3cret")
	}
}

func TestGatherPeers(t *testing.T) {
	ctx := context.Background()
	router := testRouter(routerName, nodeName, []bgpv1alpha1.RouterRole{bgpv1alpha1.RouterRoleTenant}, map[string]string{appLabel: appValue})

	tests := []struct {
		name    string
		objects []client.Object
		router  *bgpv1alpha1.BGPRouter
		wantErr string
		check   func(t *testing.T, peers []model.DesiredPeer)
	}{
		{
			name: "peer via routerRef",
			objects: []client.Object{
				router,
				testPeer("peer-ref", "overlay-router", nil, ""),
			},
			check: func(t *testing.T, peers []model.DesiredPeer) {
				if len(peers) != 1 {
					t.Fatalf("len(peers) = %d, want 1", len(peers))
				}
				if peers[0].Name != "peer-ref" {
					t.Errorf("peers[0].Name = %q, want %q", peers[0].Name, "peer-ref")
				}
			},
		},
		{
			name: "peer via routerSelector",
			objects: []client.Object{
				router,
				testPeerSelector("peer-sel", "app", "galactic", nil),
			},
			check: func(t *testing.T, peers []model.DesiredPeer) {
				if len(peers) != 1 {
					t.Fatalf("len(peers) = %d, want 1", len(peers))
				}
				if peers[0].Name != "peer-sel" {
					t.Errorf("peers[0].Name = %q, want %q", peers[0].Name, "peer-sel")
				}
			},
		},
		{
			name: "peer via routerSelector with matchExpressions",
			objects: []client.Object{
				func() *bgpv1alpha1.BGPRouter {
					r := testRouter(routerName, nodeName, []bgpv1alpha1.RouterRole{bgpv1alpha1.RouterRoleTenant}, nil)
					r.Labels = map[string]string{"tier": tierFrontend}
					return r
				}(),
				&bgpv1alpha1.BGPPeer{
					ObjectMeta: metav1.ObjectMeta{Name: "peer-expr", Namespace: namespace},
					Spec: bgpv1alpha1.BGPPeerSpec{
						RouterTarget: bgpv1alpha1.RouterTarget{
							RouterSelector: &bgpv1alpha1.RouterSelector{
								MatchExpressions: []metav1.LabelSelectorRequirement{
									{Key: tierLabel, Operator: metav1.LabelSelectorOpIn, Values: []string{tierFrontend}},
								},
							},
						},
						PeerASN:         65001,
						Address:         peerAddr,
						AddressFamilies: nil,
					},
				},
			},
			router: func() *bgpv1alpha1.BGPRouter {
				r := testRouter(routerName, nodeName, []bgpv1alpha1.RouterRole{bgpv1alpha1.RouterRoleTenant}, nil)
				r.Labels = map[string]string{"tier": tierFrontend}
				return r
			}(),
			check: func(t *testing.T, peers []model.DesiredPeer) {
				if len(peers) != 1 {
					t.Fatalf("len(peers) = %d, want 1", len(peers))
				}
				if peers[0].Name != "peer-expr" {
					t.Errorf("peers[0].Name = %q, want %q", peers[0].Name, "peer-expr")
				}
			},
		},
		{
			name: "non-matching peer is skipped",
			objects: []client.Object{
				router,
				testPeer("peer-other", "other-router", nil, ""),
			},
			check: func(t *testing.T, peers []model.DesiredPeer) {
				if len(peers) != 0 {
					t.Fatalf("len(peers) = %d, want 0", len(peers))
				}
			},
		},
		{
			name: "invalid AFI returns error",
			objects: []client.Object{
				router,
				&bgpv1alpha1.BGPPeer{
					ObjectMeta: metav1.ObjectMeta{Name: "peer-bad", Namespace: namespace},
					Spec: bgpv1alpha1.BGPPeerSpec{
						RouterTarget: bgpv1alpha1.RouterTarget{RouterRef: &bgpv1alpha1.RouterRef{Name: "overlay-router"}},
						PeerASN:      65001,
						Address:      peerAddr,
						AddressFamilies: []bgpv1alpha1.AddressFamily{
							{AFI: bgpv1alpha1.AFIIPv4, SAFI: bgpv1alpha1.SAFIEVPN},
						},
					},
				},
			},
			wantErr: "invalid address family",
		},
		{
			name: "peer with timers",
			objects: []client.Object{
				router,
				func() *bgpv1alpha1.BGPPeer {
					p := testPeer("peer-timer", "overlay-router", nil, "")
					p.Spec.HoldTime = &metav1.Duration{Duration: 90 * time.Second}
					p.Spec.KeepaliveTime = &metav1.Duration{Duration: 30 * time.Second}
					return p
				}(),
			},
			check: func(t *testing.T, peers []model.DesiredPeer) {
				if len(peers) != 1 {
					t.Fatalf("len(peers) = %d, want 1", len(peers))
				}
				if peers[0].HoldTime != 90*time.Second {
					t.Errorf("HoldTime = %v, want %v", peers[0].HoldTime, 90*time.Second)
				}
				if peers[0].KeepaliveTime != 30*time.Second {
					t.Errorf("KeepaliveTime = %v, want %v", peers[0].KeepaliveTime, 30*time.Second)
				}
			},
		},
		{
			name: "auth secret resolution",
			objects: []client.Object{
				router,
				testPeer("peer-auth", "overlay-router", nil, "my-secret"),
				testAuthSecret("my-secret"),
			},
			check: func(t *testing.T, peers []model.DesiredPeer) {
				if len(peers) != 1 {
					t.Fatalf("len(peers) = %d, want 1", len(peers))
				}
				if peers[0].AuthPassword != "s3cret" {
					t.Errorf("AuthPassword = %q, want %q", peers[0].AuthPassword, "s3cret")
				}
			},
		},
		{
			name: "auth secret missing returns error",
			objects: []client.Object{
				router,
				testPeer("peer-auth", "overlay-router", nil, "missing-secret"),
			},
			wantErr: "get auth secret default/missing-secret for peer peer-auth",
		},
		{
			name: "invalid AFI on peer returns error",
			objects: []client.Object{
				router,
				&bgpv1alpha1.BGPPeer{
					ObjectMeta: metav1.ObjectMeta{Name: "peer-bad", Namespace: namespace},
					Spec: bgpv1alpha1.BGPPeerSpec{
						RouterTarget: bgpv1alpha1.RouterTarget{RouterRef: &bgpv1alpha1.RouterRef{Name: "overlay-router"}},
						PeerASN:      65001,
						Address:      peerAddr,
						AddressFamilies: []bgpv1alpha1.AddressFamily{
							{AFI: bgpv1alpha1.AFIIPv4, SAFI: bgpv1alpha1.SAFIEVPN},
						},
					},
				},
			},
			wantErr: "invalid address family",
		},
		{
			name: "invalid keepalive > holdTime/3 returns error",
			objects: []client.Object{
				router,
				func() *bgpv1alpha1.BGPPeer {
					p := testPeer("peer-bad-timer", "overlay-router", nil, "")
					p.Spec.HoldTime = &metav1.Duration{Duration: 90 * time.Second}
					p.Spec.KeepaliveTime = &metav1.Duration{Duration: 31 * time.Second}
					return p
				}(),
			},
			wantErr: "keepaliveTime 31s must be <= holdTime/3 (30s)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k8s := fakeClient(tt.objects...)
			r := New(k8s, nodeName, "tenant")
			router := router
			if tt.router != nil {
				router = tt.router
			}
			peers, err := r.gatherPeers(ctx, router)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error %q does not contain %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.check != nil {
				tt.check(t, peers)
			}
		})
	}
}

func TestGatherPolicies(t *testing.T) {
	ctx := context.Background()
	router := testRouter(routerName, nodeName, []bgpv1alpha1.RouterRole{bgpv1alpha1.RouterRoleTenant}, map[string]string{appLabel: appValue})

	tests := []struct {
		name    string
		objects []client.Object
		wantErr string
		check   func(t *testing.T, policies []model.DesiredPolicy)
	}{
		{
			name: "policy via routerRef",
			objects: []client.Object{
				router,
				testPolicy("pol-ref", "overlay-router", []bgpv1alpha1.BGPPolicyTerm{
					{Sequence: 10, Match: bgpv1alpha1.BGPPolicyMatch{Any: true}, Action: bgpv1alpha1.BGPPolicyActionPermit},
				}),
			},
			check: func(t *testing.T, policies []model.DesiredPolicy) {
				if len(policies) != 1 {
					t.Fatalf("len(policies) = %d, want 1", len(policies))
				}
				if policies[0].Name != "pol-ref" {
					t.Errorf("policies[0].Name = %q, want %q", policies[0].Name, "pol-ref")
				}
			},
		},
		{
			name: "policy via routerSelector",
			objects: []client.Object{
				router,
				testPolicySelector("pol-sel", "app", "galactic", bgpv1alpha1.BGPPolicyDirectionExport, []bgpv1alpha1.BGPPolicyTerm{
					{Sequence: 20, Match: bgpv1alpha1.BGPPolicyMatch{Any: true}, Action: bgpv1alpha1.BGPPolicyActionDeny},
				}),
			},
			check: func(t *testing.T, policies []model.DesiredPolicy) {
				if len(policies) != 1 {
					t.Fatalf("len(policies) = %d, want 1", len(policies))
				}
				if policies[0].Name != "pol-sel" {
					t.Errorf("policies[0].Name = %q, want %q", policies[0].Name, "pol-sel")
				}
			},
		},
		{
			name: "non-matching policy is skipped",
			objects: []client.Object{
				router,
				testPolicy("pol-other", "other-router", nil),
			},
			check: func(t *testing.T, policies []model.DesiredPolicy) {
				if len(policies) != 0 {
					t.Fatalf("len(policies) = %d, want 0", len(policies))
				}
			},
		},
		{
			name: "invalid term config any+addressFamilies",
			objects: []client.Object{
				router,
				testPolicy("pol-bad", "overlay-router", []bgpv1alpha1.BGPPolicyTerm{
					{
						Sequence: 10,
						Match: bgpv1alpha1.BGPPolicyMatch{
							Any:             true,
							AddressFamilies: []bgpv1alpha1.AddressFamily{{AFI: bgpv1alpha1.AFIIPv4, SAFI: bgpv1alpha1.SAFIUnicast}},
						},
						Action: bgpv1alpha1.BGPPolicyActionPermit,
					},
				}),
			},
			wantErr: "any=true is mutually exclusive with addressFamilies",
		},
		{
			name: "term sorting ascending by sequence",
			objects: []client.Object{
				router,
				testPolicy("pol-sort", "overlay-router", []bgpv1alpha1.BGPPolicyTerm{
					{Sequence: 30, Match: bgpv1alpha1.BGPPolicyMatch{Any: true}, Action: bgpv1alpha1.BGPPolicyActionPermit},
					{Sequence: 10, Match: bgpv1alpha1.BGPPolicyMatch{Any: true}, Action: bgpv1alpha1.BGPPolicyActionDeny},
					{Sequence: 20, Match: bgpv1alpha1.BGPPolicyMatch{Any: true}, Action: bgpv1alpha1.BGPPolicyActionPermit},
				}),
			},
			check: func(t *testing.T, policies []model.DesiredPolicy) {
				if len(policies) != 1 {
					t.Fatalf("len(policies) = %d, want 1", len(policies))
				}
				terms := policies[0].Terms
				if len(terms) != 3 {
					t.Fatalf("len(terms) = %d, want 3", len(terms))
				}
				for i, term := range terms {
					wantSeq := int32(i+1) * 10
					if term.Sequence != wantSeq {
						t.Errorf("terms[%d].Sequence = %d, want %d", i, term.Sequence, wantSeq)
					}
				}
			},
		},
		{
			name: "policy with set actions",
			objects: []client.Object{
				router,
				testPolicy("pol-set", "overlay-router", []bgpv1alpha1.BGPPolicyTerm{
					{
						Sequence: 10,
						Match:    bgpv1alpha1.BGPPolicyMatch{Any: true},
						Action:   bgpv1alpha1.BGPPolicyActionPermit,
						Set: &bgpv1alpha1.PolicySetActions{
							Communities: &bgpv1alpha1.CommunitySet{
								Add:    []string{"65000:1", "65000:2"},
								Remove: []string{"65000:3"},
							},
							LocalPreference: func() *uint32 { u := uint32(200); return &u }(),
						},
					},
				}),
			},
			check: func(t *testing.T, policies []model.DesiredPolicy) {
				if len(policies) != 1 {
					t.Fatalf("len(policies) = %d, want 1", len(policies))
				}
				term := policies[0].Terms[0]
				if term.Set == nil {
					t.Fatal("Set is nil, want non-nil")
				}
				if len(term.Set.CommunitiesAdd) != 2 {
					t.Errorf("CommunitiesAdd len = %d, want 2", len(term.Set.CommunitiesAdd))
				}
				if len(term.Set.CommunitiesRemove) != 1 {
					t.Errorf("CommunitiesRemove len = %d, want 1", len(term.Set.CommunitiesRemove))
				}
				if term.Set.LocalPreference == nil {
					t.Fatal("LocalPreference is nil, want non-nil")
				}
				if *term.Set.LocalPreference != 200 {
					t.Errorf("LocalPreference = %d, want 200", *term.Set.LocalPreference)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k8s := fakeClient(tt.objects...)
			r := New(k8s, nodeName, "tenant")
			policies, err := r.gatherPolicies(ctx, router)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error %q does not contain %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.check != nil {
				tt.check(t, policies)
			}
		})
	}
}

func TestValidateAFI(t *testing.T) {
	tests := []struct {
		name    string
		af      bgpv1alpha1.AddressFamily
		wantErr string
	}{
		{
			name: "ipv4/unicast valid",
			af:   bgpv1alpha1.AddressFamily{AFI: bgpv1alpha1.AFIIPv4, SAFI: bgpv1alpha1.SAFIUnicast},
		},
		{
			name: "ipv6/unicast valid",
			af:   bgpv1alpha1.AddressFamily{AFI: bgpv1alpha1.AFIIPv6, SAFI: bgpv1alpha1.SAFIUnicast},
		},
		{
			name: "l2vpn/evpn valid",
			af:   bgpv1alpha1.AddressFamily{AFI: bgpv1alpha1.AFIL2VPN, SAFI: bgpv1alpha1.SAFIEVPN},
		},
		{
			name:    "ipv4/evpn invalid",
			af:      bgpv1alpha1.AddressFamily{AFI: bgpv1alpha1.AFIIPv4, SAFI: bgpv1alpha1.SAFIEVPN},
			wantErr: errUnsupportedAFISAFI,
		},
		{
			name:    "ipv6/evpn invalid",
			af:      bgpv1alpha1.AddressFamily{AFI: bgpv1alpha1.AFIIPv6, SAFI: bgpv1alpha1.SAFIEVPN},
			wantErr: errUnsupportedAFISAFI,
		},
		{
			name:    "l2vpn/unicast invalid",
			af:      bgpv1alpha1.AddressFamily{AFI: bgpv1alpha1.AFIL2VPN, SAFI: bgpv1alpha1.SAFIUnicast},
			wantErr: errUnsupportedAFISAFI,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateAFI(tt.af)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error %q does not contain %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestValidateAFIsAll(t *testing.T) {
	tests := []struct {
		name    string
		afs     []bgpv1alpha1.AddressFamily
		wantErr string
	}{
		{
			name: "all valid",
			afs: []bgpv1alpha1.AddressFamily{
				{AFI: bgpv1alpha1.AFIIPv4, SAFI: bgpv1alpha1.SAFIUnicast},
				{AFI: bgpv1alpha1.AFIIPv6, SAFI: bgpv1alpha1.SAFIUnicast},
			},
		},
		{
			name: "empty list valid",
			afs:  nil,
		},
		{
			name:    "first invalid",
			afs:     []bgpv1alpha1.AddressFamily{{AFI: bgpv1alpha1.AFIL2VPN, SAFI: bgpv1alpha1.SAFIUnicast}},
			wantErr: errUnsupportedAFISAFI,
		},
		{
			name:    "second invalid",
			afs:     []bgpv1alpha1.AddressFamily{{AFI: bgpv1alpha1.AFIIPv4, SAFI: bgpv1alpha1.SAFIUnicast}, {AFI: bgpv1alpha1.AFIIPv6, SAFI: bgpv1alpha1.SAFIEVPN}},
			wantErr: errUnsupportedAFISAFI,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateAFIsAll(tt.afs)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error %q does not contain %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestValidateTimers(t *testing.T) {
	h90 := &metav1.Duration{Duration: 90 * time.Second}
	k30 := &metav1.Duration{Duration: 30 * time.Second}
	k31 := &metav1.Duration{Duration: 31 * time.Second}
	h0 := &metav1.Duration{Duration: 0}

	tests := []struct {
		name      string
		holdTime  *metav1.Duration
		keepalive *metav1.Duration
		wantErr   string
	}{
		{
			name:      "both nil valid",
			holdTime:  nil,
			keepalive: nil,
		},
		{
			name:      "holdTime nil valid",
			holdTime:  nil,
			keepalive: k30,
		},
		{
			name:      "keepalive nil valid",
			holdTime:  h90,
			keepalive: nil,
		},
		{
			name:      "valid keepalive <= holdTime/3",
			holdTime:  h90,
			keepalive: k30,
		},
		{
			name:      "keepalive exactly holdTime/3 valid",
			holdTime:  h90,
			keepalive: k30,
		},
		{
			name:      "keepalive > holdTime/3 invalid",
			holdTime:  h90,
			keepalive: k31,
			wantErr:   "keepaliveTime 31s must be <= holdTime/3 (30s)",
		},
		{
			name:      "holdTime zero valid (disabled)",
			holdTime:  h0,
			keepalive: k30,
		},
		{
			name:      "both zero valid",
			holdTime:  h0,
			keepalive: h0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateTimers(tt.holdTime, tt.keepalive)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error %q does not contain %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestResolveNodeIPv6(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name    string
		node    *corev1.Node
		wantIP  string
		wantNil bool
		wantErr string
	}{
		{
			name:   "IPv6 InternalIP selected",
			node:   testNode(nextHop),
			wantIP: nextHop,
		},
		{
			name:   "only IPv4 returns empty",
			node:   testNode(""),
			wantIP: "",
		},
		{
			name: "no addresses returns empty",
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{Name: nodeName},
			},
			wantIP: "",
		},
		{
			name:    "node not found returns error",
			node:    nil,
			wantErr: "get node node1",
		},
		{
			name: "multiple IPv6 returns first",
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{Name: nodeName},
				Status: corev1.NodeStatus{
					Addresses: []corev1.NodeAddress{
						{Type: corev1.NodeInternalIP, Address: "fd00::1"},
						{Type: corev1.NodeInternalIP, Address: nextHop},
						{Type: corev1.NodeInternalIP, Address: routerID},
					},
				},
			},
			wantIP: "fd00::1",
		},
		{
			name: "IPv4 InternalIP skipped",
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{Name: nodeName},
				Status: corev1.NodeStatus{
					Addresses: []corev1.NodeAddress{
						{Type: corev1.NodeInternalIP, Address: routerID},
						{Type: corev1.NodeExternalIP, Address: "198.51.100.1"},
						{Type: corev1.NodeInternalIP, Address: nextHop},
					},
				},
			},
			wantIP: nextHop,
		},
		{
			name: "external IPv6 skipped",
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{Name: nodeName},
				Status: corev1.NodeStatus{
					Addresses: []corev1.NodeAddress{
						{Type: corev1.NodeExternalIP, Address: nextHop},
						{Type: corev1.NodeInternalIP, Address: routerID},
					},
				},
			},
			wantIP: "",
		},
		{
			name: "invalid IP parsed skipped",
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{Name: nodeName},
				Status: corev1.NodeStatus{
					Addresses: []corev1.NodeAddress{
						{Type: corev1.NodeInternalIP, Address: "not-an-ip"},
						{Type: corev1.NodeInternalIP, Address: nextHop},
					},
				},
			},
			wantIP: nextHop,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var objs []client.Object
			if tt.node != nil {
				objs = append(objs, tt.node)
			}
			k8s := fakeClient(objs...)
			r := New(k8s, nodeName, "tenant")
			ip, err := r.resolveNodeIPv6(ctx, nodeName)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error %q does not contain %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if ip != tt.wantIP {
				t.Errorf("resolveNodeIPv6() = %q, want %q", ip, tt.wantIP)
			}
		})
	}
}

func TestPeerTargetsRouter(t *testing.T) {
	router := testRouter(routerName, nodeName, []bgpv1alpha1.RouterRole{bgpv1alpha1.RouterRoleTenant}, map[string]string{appLabel: appValue})

	tests := []struct {
		name   string
		peer   *bgpv1alpha1.BGPPeer
		router *bgpv1alpha1.BGPRouter
		want   bool
	}{
		{
			name:   "routerRef match",
			peer:   testPeer("peer1", "overlay-router", nil, ""),
			router: router,
			want:   true,
		},
		{
			name:   "routerRef no match",
			peer:   testPeer("peer1", "other-router", nil, ""),
			router: router,
			want:   false,
		},
		{
			name:   "routerSelector match",
			peer:   testPeerSelector("peer1", "app", "galactic", nil),
			router: router,
			want:   true,
		},
		{
			name:   "routerSelector no match",
			peer:   testPeerSelector("peer1", "app", "other", nil),
			router: router,
			want:   false,
		},
		{
			name:   "neither set returns false",
			peer:   &bgpv1alpha1.BGPPeer{Spec: bgpv1alpha1.BGPPeerSpec{PeerASN: 65001, Address: peerAddr}},
			router: router,
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := peerTargetsRouter(tt.peer, tt.router)
			if got != tt.want {
				t.Errorf("peerTargetsRouter() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPolicyTargetsRouter(t *testing.T) {
	router := testRouter(routerName, nodeName, []bgpv1alpha1.RouterRole{bgpv1alpha1.RouterRoleTenant}, map[string]string{appLabel: appValue})

	tests := []struct {
		name   string
		policy *bgpv1alpha1.BGPPolicy
		router *bgpv1alpha1.BGPRouter
		want   bool
	}{
		{
			name:   "routerRef match",
			policy: testPolicy("pol1", "overlay-router", nil),
			router: router,
			want:   true,
		},
		{
			name:   "routerRef no match",
			policy: testPolicy("pol1", "other-router", nil),
			router: router,
			want:   false,
		},
		{
			name:   "routerSelector match",
			policy: testPolicySelector("pol1", "app", "galactic", directionImport, nil),
			router: router,
			want:   true,
		},
		{
			name:   "routerSelector no match",
			policy: testPolicySelector("pol1", "app", "other", directionImport, nil),
			router: router,
			want:   false,
		},
		{
			name:   "neither set returns false",
			policy: &bgpv1alpha1.BGPPolicy{Spec: bgpv1alpha1.BGPPolicySpec{Direction: directionImport}},
			router: router,
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := policyTargetsRouter(tt.policy, tt.router)
			if got != tt.want {
				t.Errorf("policyTargetsRouter() = %v, want %v", got, tt.want)
			}
		})
	}
}
