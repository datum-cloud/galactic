// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package hostscope

import (
	"context"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	bgpv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	"go.datum.net/galactic/internal/cloud/galactic"
	"go.datum.net/galactic/internal/crdnames"
)

const (
	testPod   = "pod-1"
	testAtt   = "att-1"
	testAttID = "e80"
	testNS    = "galactic-system"
	testNode  = "node-a"
	testVPC   = "AbC123"
)

func advScheme() *runtime.Scheme {
	s := runtime.NewScheme()
	utilruntime.Must(bgpv1alpha1.AddToScheme(s))
	return s
}

func instance() *bgpv1alpha1.BGPVRFInstance {
	return &bgpv1alpha1.BGPVRFInstance{
		ObjectMeta: metav1.ObjectMeta{Name: crdnames.BGPVRFInstanceName(testVPC, testNode), Namespace: testNS},
		Spec: bgpv1alpha1.BGPVRFInstanceSpec{
			RouterTarget:       bgpv1alpha1.RouterTarget{RouterRef: &bgpv1alpha1.RouterRef{Name: "router-a"}},
			VRFID:              9,
			ExportRouteTargets: []bgpv1alpha1.RouteTarget{{Value: "64512:7"}},
		},
	}
}

// TestAdvertise publishes a claim's addresses as /128s under the VPC's
// BGPVRFInstance with End.DT46, rewrites the pod on a move, and deletes only
// Worker's own advertisements of the VPC on this node when they are no longer
// wanted.
func TestAdvertise(t *testing.T) {
	ctx := context.Background()
	// Advertisements Worker must leave alone: CNI's for the same VPC, and
	// another node's Worker's.
	cni := &bgpv1alpha1.BGPAdvertisement{ObjectMeta: metav1.ObjectMeta{Name: "cni", Namespace: testNS}}
	otherNode := &bgpv1alpha1.BGPAdvertisement{ObjectMeta: metav1.ObjectMeta{Name: "other-node", Namespace: testNS,
		Labels: map[string]string{crdnames.LabelWorkerVPC: testVPC, crdnames.LabelWorkerNode: "node-b"}}}
	k8s := fake.NewClientBuilder().WithScheme(advScheme()).
		WithObjects(instance(), cni, otherNode).Build()
	k := &Kernel{K8s: k8s, Namespace: testNS, Node: testNode}

	gw := netip.MustParseAddr("2001:db8:ff::1")
	want := []Advertisement{{AttachmentUID: testAtt, PodUID: testPod,
		Addresses: []netip.Addr{gw, gw, netip.MustParseAddr("192.0.2.1")}}}
	if ok, err := k.Current(ctx, testVPC, want); err != nil || ok {
		t.Fatalf("Current before publishing = %t, %v; want false", ok, err)
	}
	if err := k.Advertise(ctx, testVPC, want); err != nil {
		t.Fatal(err)
	}
	if ok, err := k.Current(ctx, testVPC, want); err != nil || !ok {
		t.Fatalf("Current after publishing = %t, %v; want true", ok, err)
	}
	name := crdnames.WorkerAdvertisementName(testVPC, testAtt, testNode)
	checkAdvertisement(t, k8s, name, testPod)

	// The VPC's instance moves to another VRF ID: the advertisement is no
	// longer current, and publishing again follows the instance.
	inst := &bgpv1alpha1.BGPVRFInstance{}
	if err := k8s.Get(ctx, client.ObjectKey{Namespace: testNS,
		Name: crdnames.BGPVRFInstanceName(testVPC, testNode)}, inst); err != nil {
		t.Fatal(err)
	}
	inst.Spec.VRFID = 10
	if err := k8s.Update(ctx, inst); err != nil {
		t.Fatal(err)
	}
	if ok, _ := k.Current(ctx, testVPC, want); ok {
		t.Fatal("Current = true after the instance's VRF ID changed")
	}
	inst.Spec.VRFID = 9
	if err := k8s.Update(ctx, inst); err != nil {
		t.Fatal(err)
	}

	// The owner's pod is replaced: the same advertisement names the new pod.
	want[0].PodUID = "pod-2"
	if ok, _ := k.Current(ctx, testVPC, want); ok {
		t.Fatal("Current = true after the pod changed")
	}
	if err := k.Advertise(ctx, testVPC, want); err != nil {
		t.Fatal(err)
	}
	checkAdvertisement(t, k8s, name, "pod-2")

	// Nothing wanted: Worker's own advertisement goes, the others stay.
	if err := k.Advertise(ctx, testVPC, nil); err != nil {
		t.Fatal(err)
	}
	var list bgpv1alpha1.BGPAdvertisementList
	if err := k8s.List(ctx, &list, client.InNamespace(testNS)); err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(list.Items))
	for _, a := range list.Items {
		names = append(names, a.Name)
	}
	if len(names) != 2 || names[0] != "cni" || names[1] != "other-node" {
		t.Fatalf("advertisements left = %v, want only CNI's and the other node's", names)
	}
	if ok, err := k.Current(ctx, testVPC, nil); err != nil || !ok {
		t.Fatalf("Current(nil) = %t, %v; want true once withdrawn", ok, err)
	}
}

// TestAdvertiseNeedsTheVPCInstance refuses to publish without the VPC's
// BGPVRFInstance, which carries the VRFID remote nodes return traffic with.
func TestAdvertiseNeedsTheVPCInstance(t *testing.T) {
	k := &Kernel{K8s: fake.NewClientBuilder().WithScheme(advScheme()).Build(), Namespace: testNS, Node: testNode}
	err := k.Advertise(context.Background(), testVPC, []Advertisement{{AttachmentUID: testAtt, PodUID: testPod,
		Addresses: []netip.Addr{netip.MustParseAddr("2001:db8:ff::1")}}})
	if err == nil {
		t.Fatal("Advertise without the VPC's BGPVRFInstance succeeded")
	}
}

// checkAdvertisement checks that the advertisement name publishes the
// claim's IPv6 address as a /128 under the VPC instance's router, VRF ID 9,
// End.DT46 and route target, for pod.
func checkAdvertisement(t *testing.T, k8s client.Client, name, pod string) {
	t.Helper()
	var adv bgpv1alpha1.BGPAdvertisement
	if err := k8s.Get(context.Background(), client.ObjectKey{Namespace: testNS, Name: name}, &adv); err != nil {
		t.Fatal(err)
	}
	if got := adv.Spec.Prefixes; len(got) != 1 || got[0] != "2001:db8:ff::1/128" {
		t.Fatalf("prefixes = %v, want only the IPv6 address as a /128", got)
	}
	if adv.Spec.RouterRef.Name != "router-a" || adv.Spec.VRFID == nil || *adv.Spec.VRFID != 9 ||
		adv.Spec.Function == nil || *adv.Spec.Function != bgpv1alpha1.SRv6FunctionEndDT46 ||
		len(adv.Spec.Communities) != 1 || adv.Spec.Communities[0] != "64512:7" {
		t.Fatalf("spec = %+v, want the VPC instance's router, VRFID 9, End.DT46 and its route target", adv.Spec)
	}
	if adv.Labels[crdnames.LabelWorkerAttachment] != testAtt || adv.Annotations[crdnames.AnnotationWorkerPod] != pod {
		t.Fatalf("metadata = %v %v, want the claim's attachment and %s", adv.Labels, adv.Annotations, pod)
	}
	for key := range adv.Annotations {
		if strings.HasPrefix(key, crdnames.AnnotationNetNS) {
			t.Fatalf("annotation %s would let galactic-router's GC judge the advertisement", key)
		}
	}
}

// TestAdvertiseNamesTheAttachmentsOwnAdvertisement names the advertisement
// after the attachment's base62 identifier, the name galactic-controller
// reads an attachment's tenant advertisement by, replaces a UID-named one an
// earlier Worker left.
func TestAdvertiseNamesTheAttachmentsOwnAdvertisement(t *testing.T) {
	ctx := context.Background()
	gw := []netip.Addr{netip.MustParseAddr("2001:db8:ff::1")}
	old := &bgpv1alpha1.BGPAdvertisement{ObjectMeta: metav1.ObjectMeta{
		Name: crdnames.WorkerAdvertisementName(testVPC, testAtt, testNode), Namespace: testNS,
		Labels: map[string]string{crdnames.LabelWorkerVPC: testVPC, crdnames.LabelWorkerNode: testNode}}}
	k8s := fake.NewClientBuilder().WithScheme(advScheme()).WithObjects(instance(), old).Build()
	k := &Kernel{K8s: k8s, Namespace: testNS, Node: testNode}
	want := []Advertisement{{AttachmentUID: testAtt, AttachmentID: testAttID, PodUID: testPod, Addresses: gw}}
	if err := k.Advertise(ctx, testVPC, want); err != nil {
		t.Fatal(err)
	}
	name := crdnames.BGPAdvertisementName(testVPC, testAttID, testNode)
	if identity := galactic.AdvertisementName(testVPC, testAttID); name != identity+"-"+testNode {
		t.Fatalf("name %s is not the controller's %s-%s", name, identity, testNode)
	}
	var list bgpv1alpha1.BGPAdvertisementList
	if err := k8s.List(ctx, &list, client.InNamespace(testNS)); err != nil {
		t.Fatal(err)
	}
	if len(list.Items) != 1 || list.Items[0].Name != name {
		t.Fatalf("advertisements = %v, want only %s", list.Items, name)
	}
	if ok, err := k.Current(ctx, testVPC, want); err != nil || !ok {
		t.Fatalf("Current with the canonical name = %t, %v; want true", ok, err)
	}

	// A recreated attachment can keep the same tenant ID and get a new UID.
	// The controller still needs the canonical advertisement.
	want[0].AttachmentUID = "att-2"
	if ok, err := k.Current(ctx, testVPC, want); err != nil || ok {
		t.Fatalf("Current with a replaced attachment UID = %t, %v; want false", ok, err)
	}
	if err := k.Advertise(ctx, testVPC, want); err != nil {
		t.Fatal(err)
	}
	var adv bgpv1alpha1.BGPAdvertisement
	if err := k8s.Get(ctx, client.ObjectKey{Namespace: testNS, Name: name}, &adv); err != nil {
		t.Fatal(err)
	}
	if uid := adv.Labels[crdnames.LabelWorkerAttachment]; uid != want[0].AttachmentUID {
		t.Fatalf("canonical advertisement attachment UID = %q, want %q", uid, want[0].AttachmentUID)
	}
}

func TestIssue1494WorkerAndCNIAdvertisementsCoexist(t *testing.T) {
	ctx := context.Background()
	cni := &bgpv1alpha1.BGPAdvertisement{ObjectMeta: metav1.ObjectMeta{
		Namespace:   testNS,
		Name:        crdnames.BGPAdvertisementName(testVPC, testAttID, testNode),
		Annotations: map[string]string{crdnames.AnnotationNoAddressing: crdnames.AnnotationNoAddressingValue},
	}}
	k8s := fake.NewClientBuilder().WithScheme(advScheme()).WithObjects(instance(), cni).Build()
	k := &Kernel{K8s: k8s, Namespace: testNS, Node: testNode}
	var original bgpv1alpha1.BGPAdvertisement
	if err := k8s.Get(ctx, client.ObjectKeyFromObject(cni), &original); err != nil {
		t.Fatal(err)
	}
	checkCNI := func() {
		t.Helper()
		var got bgpv1alpha1.BGPAdvertisement
		if err := k8s.Get(ctx, client.ObjectKeyFromObject(cni), &got); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, original) {
			t.Fatalf("CNI advertisement changed: got %+v, want %+v", got, original)
		}
	}
	want := []Advertisement{{AttachmentUID: testAtt, AttachmentID: testAttID, PodUID: testPod,
		Addresses: []netip.Addr{netip.MustParseAddr("2001:db8:ff::1")}}}
	if err := k.Advertise(ctx, testVPC, want); err != nil {
		t.Fatalf("publish Worker return route alongside CNI: %v", err)
	}
	name := crdnames.WorkerAdvertisementName(testVPC, testAtt, testNode)
	checkAdvertisement(t, k8s, name, testPod)
	if ok, err := k.Current(ctx, testVPC, want); err != nil || !ok {
		t.Fatalf("Current with the UID name = %t, %v; want true", ok, err)
	}
	checkCNI()

	if err := k.Advertise(ctx, testVPC, nil); err != nil {
		t.Fatal(err)
	}
	key := client.ObjectKey{Namespace: testNS, Name: name}
	if err := k8s.Get(ctx, key, &bgpv1alpha1.BGPAdvertisement{}); !apierrors.IsNotFound(err) {
		t.Fatalf("Worker advertisement after cleanup: %v; want NotFound", err)
	}
	checkCNI()
}

func TestAdvertisePreservesCNIAfterItReusesWorkerName(t *testing.T) {
	ctx := context.Background()
	k8s := fake.NewClientBuilder().WithScheme(advScheme()).WithObjects(instance()).Build()
	k := &Kernel{K8s: k8s, Namespace: testNS, Node: testNode}
	want := []Advertisement{{AttachmentUID: testAtt, AttachmentID: testAttID, PodUID: testPod,
		Addresses: []netip.Addr{netip.MustParseAddr("2001:db8:ff::1")}}}
	if err := k.Advertise(ctx, testVPC, want); err != nil {
		t.Fatal(err)
	}
	key := client.ObjectKey{Namespace: testNS, Name: crdnames.BGPAdvertisementName(testVPC, testAttID, testNode)}
	var cni bgpv1alpha1.BGPAdvertisement
	if err := k8s.Get(ctx, key, &cni); err != nil {
		t.Fatal(err)
	}
	// CNI ADD records its container and prefixes on the canonical object.
	cni.Annotations[crdnames.NetNSKey("sandbox-a")] = "/run/netns/sandbox-a"
	cni.Spec.Prefixes = []bgpv1alpha1.Prefix{"2001:db8:ab::/64"}
	if err := k8s.Update(ctx, &cni); err != nil {
		t.Fatal(err)
	}
	if err := k.Advertise(ctx, testVPC, want); err != nil {
		t.Fatal(err)
	}
	checkAdvertisement(t, k8s, crdnames.WorkerAdvertisementName(testVPC, testAtt, testNode), testPod)
	if ok, err := k.Current(ctx, testVPC, want); err != nil || !ok {
		t.Fatalf("Current after CNI reused the tenant name = %t, %v; want true", ok, err)
	}
	if err := k.Advertise(ctx, testVPC, nil); err != nil {
		t.Fatal(err)
	}
	var got bgpv1alpha1.BGPAdvertisement
	if err := k8s.Get(ctx, key, &got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, cni) {
		t.Fatalf("CNI advertisement changed: got %+v, want %+v", got, cni)
	}
}
