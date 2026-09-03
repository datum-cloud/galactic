// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package ingresssidecar

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"go.datum.net/galactic/internal/crdnames"
	"go.datum.net/galactic/internal/plumbing/intf"
	bgpv1alpha1 "go.datum.net/network/api/v1alpha1"
)

const (
	gatewayTestNamespace = "galactic-system"
	gatewayTestNode      = "worker-1"
	gatewayTestVPC       = "2"
	gatewayTestRT        = "65000:2"
	gatewayTestASN       = 65000
)

func gatewayTestScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := bgpv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme: %v", err)
	}
	return scheme
}

// newGatewayTestRouter returns a BGPRouter named after, and targeting,
// gatewayTestNode -- every test in this file uses a single-router, single-
// node fixture, so router name and target node are always the same value.
func newGatewayTestRouter() *bgpv1alpha1.BGPRouter {
	return &bgpv1alpha1.BGPRouter{
		ObjectMeta: metav1.ObjectMeta{Namespace: gatewayTestNamespace, Name: gatewayTestNode},
		Spec: bgpv1alpha1.BGPRouterSpec{
			TargetRef: bgpv1alpha1.TargetRef{Kind: "Node", Name: gatewayTestNode},
			LocalASN:  gatewayTestASN,
			RouterID:  "10.0.0.1",
		},
	}
}

// stubPodEntryPoint makes podEntryPointFn return a fixed pod entry point
// for the duration of one test. A unit test's own namespace has no primary
// interface, so PublishGateway's real read of one cannot succeed here --
// and what it reads is a plain kernel attribute, not behaviour these tests
// are about.
func stubPodEntryPoint(t *testing.T) {
	t.Helper()
	prev := podEntryPointFn
	podEntryPointFn = func() (int, net.HardwareAddr, error) {
		return 24, net.HardwareAddr{0x9a, 0x91, 0xc0, 0x8d, 0x83, 0xf1}, nil
	}
	t.Cleanup(func() { podEntryPointFn = prev })
}

func TestPublishGateway_CreatesVRFInstanceAndAdvertisement(t *testing.T) {
	stubPodEntryPoint(t)
	ctx := context.Background()
	scheme := gatewayTestScheme(t)
	router := newGatewayTestRouter()
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(router).Build()

	pub := NewK8sGatewayPublisher(fakeClient, gatewayTestNode, gatewayTestNamespace)
	addr := net.ParseIP("fd20:0:2::4:0:0")
	if err := pub.PublishGateway(ctx, gatewayTestVPC, addr); err != nil {
		t.Fatalf("PublishGateway: %v", err)
	}

	vrfName := crdnames.BGPVRFInstanceName(gatewayTestVPC, gatewayTestNode)
	vrf := &bgpv1alpha1.BGPVRFInstance{}
	if err := fakeClient.Get(ctx, types.NamespacedName{Namespace: gatewayTestNamespace, Name: vrfName}, vrf); err != nil {
		t.Fatalf("get BGPVRFInstance %s: %v", vrfName, err)
	}
	if vrf.Spec.VRFID != 1 {
		t.Errorf("VRFID = %d, want 1 (first free slot)", vrf.Spec.VRFID)
	}
	if len(vrf.Spec.ImportRouteTargets) != 1 || vrf.Spec.ImportRouteTargets[0].Value != gatewayTestRT {
		t.Errorf("ImportRouteTargets = %v, want [%s]", vrf.Spec.ImportRouteTargets, gatewayTestRT)
	}

	advName := crdnames.BGPAdvertisementName(gatewayTestVPC, ingressVPCAttachment, gatewayTestNode)
	adv := &bgpv1alpha1.BGPAdvertisement{}
	if err := fakeClient.Get(ctx, types.NamespacedName{Namespace: gatewayTestNamespace, Name: advName}, adv); err != nil {
		t.Fatalf("get BGPAdvertisement %s: %v", advName, err)
	}
	if adv.Spec.RouterRef.Name != gatewayTestNode {
		t.Errorf("RouterRef.Name = %q, want %s", adv.Spec.RouterRef.Name, gatewayTestNode)
	}
	if len(adv.Spec.Prefixes) != 1 || string(adv.Spec.Prefixes[0]) != "fd20:0:2::4:0:0/128" {
		t.Errorf("Prefixes = %v, want [fd20:0:2::4:0:0/128]", adv.Spec.Prefixes)
	}
	if len(adv.Spec.Communities) != 1 || string(adv.Spec.Communities[0]) != gatewayTestRT {
		t.Errorf("Communities = %v, want [%s]", adv.Spec.Communities, gatewayTestRT)
	}
	if adv.Spec.VRFID == nil || *adv.Spec.VRFID != 1 {
		t.Errorf("VRFID = %v, want 1", adv.Spec.VRFID)
	}
	if adv.Spec.Function == nil || *adv.Spec.Function != bgpv1alpha1.SRv6FunctionEndDT46 {
		t.Errorf("Function = %v, want End.DT46", adv.Spec.Function)
	}
}

func TestPublishGateway_ReusesExistingVRFID(t *testing.T) {
	stubPodEntryPoint(t)
	ctx := context.Background()
	scheme := gatewayTestScheme(t)
	router := newGatewayTestRouter()
	existingVRF := &bgpv1alpha1.BGPVRFInstance{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: gatewayTestNamespace,
			Name:      crdnames.BGPVRFInstanceName(gatewayTestVPC, gatewayTestNode),
		},
		Spec: bgpv1alpha1.BGPVRFInstanceSpec{
			RouterTarget:       bgpv1alpha1.RouterTarget{RouterRef: &bgpv1alpha1.RouterRef{Name: gatewayTestNode}},
			VRFID:              7,
			ImportRouteTargets: []bgpv1alpha1.RouteTarget{{Value: gatewayTestRT}},
			ExportRouteTargets: []bgpv1alpha1.RouteTarget{{Value: gatewayTestRT}},
		},
	}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(router, existingVRF).Build()

	pub := NewK8sGatewayPublisher(fakeClient, gatewayTestNode, gatewayTestNamespace)
	if err := pub.PublishGateway(ctx, gatewayTestVPC, net.ParseIP("fd20:0:2::4:0:0")); err != nil {
		t.Fatalf("PublishGateway: %v", err)
	}

	adv := &bgpv1alpha1.BGPAdvertisement{}
	advName := crdnames.BGPAdvertisementName(gatewayTestVPC, ingressVPCAttachment, gatewayTestNode)
	if err := fakeClient.Get(ctx, types.NamespacedName{Namespace: gatewayTestNamespace, Name: advName}, adv); err != nil {
		t.Fatalf("get BGPAdvertisement: %v", err)
	}
	if adv.Spec.VRFID == nil || *adv.Spec.VRFID != 7 {
		t.Errorf("VRFID = %v, want 7 (reused from existing BGPVRFInstance)", adv.Spec.VRFID)
	}
}

func TestPublishGateway_AvoidsCollisionWithOtherVPCOnSameNode(t *testing.T) {
	stubPodEntryPoint(t)
	ctx := context.Background()
	scheme := gatewayTestScheme(t)
	router := newGatewayTestRouter()
	otherVPCVRF := &bgpv1alpha1.BGPVRFInstance{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: gatewayTestNamespace,
			Name:      crdnames.BGPVRFInstanceName("70", gatewayTestNode),
		},
		Spec: bgpv1alpha1.BGPVRFInstanceSpec{
			RouterTarget:       bgpv1alpha1.RouterTarget{RouterRef: &bgpv1alpha1.RouterRef{Name: gatewayTestNode}},
			VRFID:              1,
			ImportRouteTargets: []bgpv1alpha1.RouteTarget{{Value: "65000:70"}},
			ExportRouteTargets: []bgpv1alpha1.RouteTarget{{Value: "65000:70"}},
		},
	}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(router, otherVPCVRF).Build()

	pub := NewK8sGatewayPublisher(fakeClient, gatewayTestNode, gatewayTestNamespace)
	if err := pub.PublishGateway(ctx, gatewayTestVPC, net.ParseIP("fd20:0:2::4:0:0")); err != nil {
		t.Fatalf("PublishGateway: %v", err)
	}

	vrfName := crdnames.BGPVRFInstanceName(gatewayTestVPC, gatewayTestNode)
	vrf := &bgpv1alpha1.BGPVRFInstance{}
	if err := fakeClient.Get(ctx, types.NamespacedName{Namespace: gatewayTestNamespace, Name: vrfName}, vrf); err != nil {
		t.Fatalf("get BGPVRFInstance: %v", err)
	}
	if vrf.Spec.VRFID != 2 {
		t.Errorf("VRFID = %d, want 2 (1 already used by VPC 70 on this node)", vrf.Spec.VRFID)
	}
}

func TestPublishGateway_NoBGPRouterForNode(t *testing.T) {
	scheme := gatewayTestScheme(t)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	pub := NewK8sGatewayPublisher(fakeClient, gatewayTestNode, gatewayTestNamespace)
	if err := pub.PublishGateway(context.Background(), gatewayTestVPC, net.ParseIP("fd20:0:2::4:0:0")); err == nil {
		t.Fatal("expected an error when no BGPRouter targets this node, got nil")
	}
}

func TestPublishGateway_RejectsUnspecifiedAddress(t *testing.T) {
	scheme := gatewayTestScheme(t)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	pub := NewK8sGatewayPublisher(fakeClient, gatewayTestNode, gatewayTestNamespace)
	if err := pub.PublishGateway(context.Background(), gatewayTestVPC, net.IPv6zero); err == nil {
		t.Fatal("expected an error for an unspecified address, got nil")
	}
	if err := pub.PublishGateway(context.Background(), gatewayTestVPC, nil); err == nil {
		t.Fatal("expected an error for a nil address, got nil")
	}
}

func TestWithdrawGateway_DeletesAdvertisementOnlyNotVRFInstance(t *testing.T) {
	stubPodEntryPoint(t)
	ctx := context.Background()
	scheme := gatewayTestScheme(t)
	router := newGatewayTestRouter()
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(router).Build()

	pub := NewK8sGatewayPublisher(fakeClient, gatewayTestNode, gatewayTestNamespace)
	if err := pub.PublishGateway(ctx, gatewayTestVPC, net.ParseIP("fd20:0:2::4:0:0")); err != nil {
		t.Fatalf("PublishGateway: %v", err)
	}
	if err := pub.WithdrawGateway(ctx, gatewayTestVPC); err != nil {
		t.Fatalf("WithdrawGateway: %v", err)
	}

	adv := &bgpv1alpha1.BGPAdvertisement{}
	advName := crdnames.BGPAdvertisementName(gatewayTestVPC, ingressVPCAttachment, gatewayTestNode)
	err := fakeClient.Get(ctx, types.NamespacedName{Namespace: gatewayTestNamespace, Name: advName}, adv)
	if !apierrors.IsNotFound(err) {
		t.Errorf("BGPAdvertisement still exists after WithdrawGateway (err=%v), want NotFound", err)
	}

	vrf := &bgpv1alpha1.BGPVRFInstance{}
	vrfName := crdnames.BGPVRFInstanceName(gatewayTestVPC, gatewayTestNode)
	if err := fakeClient.Get(ctx, types.NamespacedName{Namespace: gatewayTestNamespace, Name: vrfName}, vrf); err != nil {
		t.Errorf("BGPVRFInstance was removed by WithdrawGateway (it's shared, not this publisher's to delete): %v", err)
	}
}

func TestWithdrawGateway_NotFoundIsNoop(t *testing.T) {
	scheme := gatewayTestScheme(t)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	pub := NewK8sGatewayPublisher(fakeClient, gatewayTestNode, gatewayTestNamespace)
	if err := pub.WithdrawGateway(context.Background(), gatewayTestVPC); err != nil {
		t.Fatalf("WithdrawGateway on a never-published vpc: %v", err)
	}
}

func TestVpcRouteTarget(t *testing.T) {
	for _, vpc := range []string{"2", "70", "1b4"} {
		hex, err := intf.Base62ToHex(vpc)
		if err != nil {
			t.Fatalf("intf.Base62ToHex(%q): %v", vpc, err)
		}
		v, err := strconv.ParseUint(hex, 16, 64)
		if err != nil {
			t.Fatalf("parse hex %q: %v", hex, err)
		}
		want := fmt.Sprintf("65000:%d", uint32(v))

		got, err := vpcRouteTarget(65000, vpc)
		if err != nil {
			t.Fatalf("vpcRouteTarget(65000, %q): unexpected error: %v", vpc, err)
		}
		if got != want {
			t.Errorf("vpcRouteTarget(65000, %q) = %q, want %q", vpc, got, want)
		}
	}

	if _, err := vpcRouteTarget(65000, "!!!"); err == nil {
		t.Error("vpcRouteTarget with a non-base62 vpc: expected an error, got nil")
	}
}

// fakeGatewayPublisher/fakeGatewayResolver back the Store-level wiring
// tests in store_test.go — no real k8s or kernel calls, matching
// fakeBackend's own rationale.
type fakeGatewayPublisher struct {
	published   map[string]net.IP
	withdrawn   []string
	publishErr  error
	withdrawErr error
}

func newFakeGatewayPublisher() *fakeGatewayPublisher {
	return &fakeGatewayPublisher{published: make(map[string]net.IP)}
}

func (f *fakeGatewayPublisher) PublishGateway(_ context.Context, vpc string, addr net.IP) error {
	if f.publishErr != nil {
		return f.publishErr
	}
	f.published[vpc] = addr
	return nil
}

func (f *fakeGatewayPublisher) WithdrawGateway(_ context.Context, vpc string) error {
	if f.withdrawErr != nil {
		return f.withdrawErr
	}
	f.withdrawn = append(f.withdrawn, vpc)
	delete(f.published, vpc)
	return nil
}

type fakeGatewayResolver struct {
	addrs map[string]net.IP
}

func newFakeGatewayResolver() *fakeGatewayResolver {
	return &fakeGatewayResolver{addrs: make(map[string]net.IP)}
}

func (f *fakeGatewayResolver) ResolveGatewayAddress(vpc string) (net.IP, error) {
	if addr, ok := f.addrs[vpc]; ok {
		return addr, nil
	}
	return nil, fmt.Errorf("vpc %s: %w", vpc, ErrGatewayAddressNotProvisioned)
}

// TestPublishGateway_RecordsPodEntryPoint pins the half of this return path
// that only this side can supply. internal/installer keys its route and
// permanent neighbor off these two annotations and has no other source for
// them: reading them itself would mean entering this pod's namespace, which
// needs a privilege the node agent does not carry. An advertisement without
// them is one the host silently skips.
func TestPublishGateway_RecordsPodEntryPoint(t *testing.T) {
	stubPodEntryPoint(t)

	ctx := context.Background()
	scheme := gatewayTestScheme(t)
	router := newGatewayTestRouter()
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(router).Build()
	p := NewK8sGatewayPublisher(fakeClient, gatewayTestNode, gatewayTestNamespace)

	if err := p.PublishGateway(ctx, "2", net.ParseIP("fd30:e2e:3a5::1")); err != nil {
		t.Fatalf("PublishGateway: %v", err)
	}

	adv := &bgpv1alpha1.BGPAdvertisement{}
	name := crdnames.BGPAdvertisementName("2", ingressVPCAttachment, gatewayTestNode)
	if err := fakeClient.Get(ctx,
		types.NamespacedName{Name: name, Namespace: gatewayTestNamespace}, adv); err != nil {
		t.Fatalf("get BGPAdvertisement %s: %v", name, err)
	}

	if got := adv.Annotations[crdnames.AnnotationIngressHostIfindex]; got != "24" {
		t.Errorf("%s = %q, want %q", crdnames.AnnotationIngressHostIfindex, got, "24")
	}
	if got := adv.Annotations[crdnames.AnnotationIngressHostMAC]; got != "9a:91:c0:8d:83:f1" {
		t.Errorf("%s = %q, want %q", crdnames.AnnotationIngressHostMAC, got, "9a:91:c0:8d:83:f1")
	}
}

// TestPublishGateway_RefusesWithoutAnEntryPoint covers a pod with no way in.
// Publishing anyway would advertise a return path into EVPN that no node
// could complete, and remote nodes would encapsulate replies toward a SID
// that blackholes them -- worse than not advertising at all.
func TestPublishGateway_RefusesWithoutAnEntryPoint(t *testing.T) {
	prev := podEntryPointFn
	podEntryPointFn = func() (int, net.HardwareAddr, error) {
		return 0, nil, errors.New("no primary interface")
	}
	t.Cleanup(func() { podEntryPointFn = prev })

	ctx := context.Background()
	scheme := gatewayTestScheme(t)
	router := newGatewayTestRouter()
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(router).Build()
	p := NewK8sGatewayPublisher(fakeClient, gatewayTestNode, gatewayTestNamespace)

	if err := p.PublishGateway(ctx, "2", net.ParseIP("fd30:e2e:3a5::1")); err == nil {
		t.Fatal("PublishGateway() error = nil, want an error when the pod has no entry point")
	}

	adv := &bgpv1alpha1.BGPAdvertisement{}
	name := crdnames.BGPAdvertisementName("2", ingressVPCAttachment, gatewayTestNode)
	err := fakeClient.Get(ctx, types.NamespacedName{Name: name, Namespace: gatewayTestNamespace}, adv)
	if err == nil {
		t.Error("an advertisement was created despite the pod having no entry point")
	}
}
