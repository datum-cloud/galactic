// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package installer

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	nadv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	bgpv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	"go.datum.net/galactic/internal/crdnames"
	"go.datum.net/galactic/internal/plumbing/srv6"
)

const (
	repairNode       = "node-a"
	repairPodNS      = "tenant"
	repairVPC        = "abc"
	repairAttachment = "def"
	repairNAD        = "vpc-net"
	repairPodAddr    = "fd00:10::5"
	repairLocator    = "2001:db8:ff01::/48"
	repairNodeID     = int32(7)
	repairVRFID      = int32(3)
)

func repairClient(t *testing.T, objs ...client.Object) client.Client {
	t.Helper()
	s := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(s))
	utilruntime.Must(bgpv1alpha1.AddToScheme(s))
	return fake.NewClientBuilder().WithScheme(s).WithObjects(objs...).
		WithIndex(&corev1.Pod{}, podNodeNameField, func(o client.Object) []string {
			return []string{o.(*corev1.Pod).Spec.NodeName}
		}).Build()
}

func repairNADObject(plugins string) *unstructured.Unstructured {
	nad := &unstructured.Unstructured{}
	nad.SetGroupVersionKind(nadGVK)
	nad.SetNamespace(repairPodNS)
	nad.SetName(repairNAD)
	_ = unstructured.SetNestedField(nad.Object,
		fmt.Sprintf(`{"cniVersion":"1.0.0","name":"x","plugins":[%s]}`, plugins), "spec", "config")
	return nad
}

func galacticNAD() *unstructured.Unstructured {
	return repairNADObject(fmt.Sprintf(
		`{"type":"galactic-veth","vpc":%q,"vpcattachment":%q},{"type":"galactic-bgp","vpc":%q,"vpcattachment":%q}`,
		repairVPC, repairAttachment, repairVPC, repairAttachment))
}

func repairPod(name, node string, phase corev1.PodPhase, statuses ...nadv1.NetworkStatus) *corev1.Pod {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: name, Namespace: repairPodNS, UID: types.UID("uid-" + name),
		},
		Spec:   corev1.PodSpec{NodeName: node},
		Status: corev1.PodStatus{Phase: phase},
	}
	if statuses != nil {
		raw, _ := json.Marshal(statuses)
		pod.Annotations = map[string]string{nadv1.NetworkStatusAnnot: string(raw)}
	}
	return pod
}

func galacticStatus(ips ...string) nadv1.NetworkStatus {
	return nadv1.NetworkStatus{Name: repairPodNS + "/" + repairNAD, IPs: ips}
}

func defaultStatus() nadv1.NetworkStatus {
	return nadv1.NetworkStatus{Name: "cilium", IPs: []string{"10.0.0.5"}, Default: true}
}

func repairIdentity() []client.Object {
	return []client.Object{
		router(repairNode, repairLocator, repairNodeID),
		&bgpv1alpha1.BGPVRFInstance{
			ObjectMeta: metav1.ObjectMeta{
				Name: crdnames.BGPVRFInstanceName(repairVPC, repairNode), Namespace: testNamespace,
			},
			Spec: bgpv1alpha1.BGPVRFInstanceSpec{VRFID: repairVRFID},
		},
	}
}

func getRepairSlice(t *testing.T, k8s client.Client, podName string) (*discoveryv1.EndpointSlice, bool) {
	t.Helper()
	slice := &discoveryv1.EndpointSlice{}
	err := k8s.Get(context.Background(), client.ObjectKey{Name: podName, Namespace: repairPodNS}, slice)
	if err != nil {
		return nil, false
	}
	return slice, true
}

func TestRepairEndpointSlicesRecreatesMissingSlice(t *testing.T) {
	pod := repairPod("web-0", repairNode, corev1.PodRunning, defaultStatus(), galacticStatus(repairPodAddr))
	k8s := repairClient(t, append(repairIdentity(), galacticNAD(), pod)...)

	result, err := repairEndpointSlices(context.Background(), k8s, testNamespace, repairNode)
	if err != nil {
		t.Fatalf("repairEndpointSlices() error = %v", err)
	}
	if result.Restored != 1 || result.Skipped != 0 {
		t.Fatalf("result = %+v, want 1 restored, 0 skipped", result)
	}

	slice, ok := getRepairSlice(t, k8s, "web-0")
	if !ok {
		t.Fatal("EndpointSlice not recreated")
	}
	wantSID, err := srv6.ComputeSID(repairLocator, repairNodeID, repairVRFID, bgpv1alpha1.SRv6FunctionEndDT46)
	if err != nil {
		t.Fatalf("ComputeSID: %v", err)
	}
	if got := slice.Annotations[crdnames.AnnotationSID]; got != wantSID.String() {
		t.Errorf("SID annotation = %q, want %q", got, wantSID)
	}
	wantTenantID := crdnames.TenantIdentifier(repairVPC, repairAttachment)
	if got := slice.Labels[crdnames.LabelTenantID]; got != wantTenantID {
		t.Errorf("tenant label = %q, want %q", got, wantTenantID)
	}
	if _, ok := slice.Annotations[crdnames.AnnotationSandboxID]; ok {
		t.Error("recreated slice carries a sandbox annotation, want none")
	}
	if len(slice.Endpoints) != 1 || slice.Endpoints[0].Addresses[0] != repairPodAddr {
		t.Errorf("Endpoints = %+v, want address %s", slice.Endpoints, repairPodAddr)
	}
	if owners := slice.OwnerReferences; len(owners) != 1 || owners[0].UID != pod.UID {
		t.Errorf("OwnerReferences = %+v, want pod %s", owners, pod.UID)
	}
}

func TestRepairEndpointSlicesLeavesExistingSlice(t *testing.T) {
	pod := repairPod("web-0", repairNode, corev1.PodRunning, galacticStatus(repairPodAddr))
	existing := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name: "web-0", Namespace: repairPodNS,
			Annotations: map[string]string{crdnames.AnnotationSandboxID: "sandbox"},
		},
		AddressType: discoveryv1.AddressTypeIPv6,
		Endpoints:   []discoveryv1.Endpoint{{Addresses: []string{"fd00:10::99"}}},
	}
	k8s := repairClient(t, append(repairIdentity(), galacticNAD(), pod, existing)...)

	result, err := repairEndpointSlices(context.Background(), k8s, testNamespace, repairNode)
	if err != nil || result.Restored != 0 {
		t.Fatalf("repairEndpointSlices() = (%+v, %v), want nothing restored", result, err)
	}
	slice, _ := getRepairSlice(t, k8s, "web-0")
	if slice.Endpoints[0].Addresses[0] != "fd00:10::99" || slice.Annotations[crdnames.AnnotationSandboxID] != "sandbox" {
		t.Errorf("existing EndpointSlice was modified: %+v", slice)
	}
}

func TestRepairEndpointSlicesSkipsPodsWithNothingToRepair(t *testing.T) {
	deleting := repairPod("deleting", repairNode, corev1.PodRunning, galacticStatus(repairPodAddr))
	now := metav1.Now()
	deleting.DeletionTimestamp = &now
	deleting.Finalizers = []string{"test/hold"}

	plainNAD := repairNADObject(`{"type":"bridge"}`)
	plainNAD.SetName("plain")

	pods := []client.Object{
		repairPod("other-node", "node-b", corev1.PodRunning, galacticStatus(repairPodAddr)),
		repairPod("pending", repairNode, corev1.PodPending, galacticStatus(repairPodAddr)),
		deleting,
		repairPod("no-status", repairNode, corev1.PodRunning),
		repairPod("ipv4-only", repairNode, corev1.PodRunning, galacticStatus("192.0.2.5")),
		repairPod("not-galactic", repairNode, corev1.PodRunning,
			nadv1.NetworkStatus{Name: repairPodNS + "/plain", IPs: []string{repairPodAddr}}),
	}
	k8s := repairClient(t, append(append(repairIdentity(), galacticNAD(), plainNAD), pods...)...)

	result, err := repairEndpointSlices(context.Background(), k8s, testNamespace, repairNode)
	if err != nil {
		t.Fatalf("repairEndpointSlices() error = %v", err)
	}
	if result.Restored != 0 || result.Skipped != 0 {
		t.Fatalf("result = %+v, want nothing restored or skipped", result)
	}
	for _, p := range pods {
		if _, ok := getRepairSlice(t, k8s, p.GetName()); ok {
			t.Errorf("EndpointSlice created for pod %s", p.GetName())
		}
	}
}

func TestRepairEndpointSlicesSkipsUnresolvableAttachments(t *testing.T) {
	cases := []struct {
		name string
		objs []client.Object
	}{
		{name: "definition missing", objs: repairIdentity()},
		{name: "no BGPRouter for the node", objs: []client.Object{galacticNAD()}},
		{name: "no BGPVRFInstance for the VPC", objs: []client.Object{
			router(repairNode, repairLocator, repairNodeID), galacticNAD(),
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bad := repairPod("bad", repairNode, corev1.PodRunning, galacticStatus(repairPodAddr))
			k8s := repairClient(t, append(tc.objs, bad)...)

			result, err := repairEndpointSlices(context.Background(), k8s, testNamespace, repairNode)
			if err != nil {
				t.Fatalf("repairEndpointSlices() error = %v, want a skip, not a failed pass", err)
			}
			if result.Skipped != 1 || result.Restored != 0 {
				t.Fatalf("result = %+v, want 1 skipped", result)
			}
			if _, ok := getRepairSlice(t, k8s, "bad"); ok {
				t.Error("EndpointSlice created for an unresolvable attachment")
			}
		})
	}
}

// TestRepairEndpointSlicesNoSRv6Identity matches ADD on a node whose router has
// no SRv6 identity: the slice is published without a SID.
func TestRepairEndpointSlicesNoSRv6Identity(t *testing.T) {
	pod := repairPod("web-0", repairNode, corev1.PodRunning, galacticStatus(repairPodAddr+"/64"))
	k8s := repairClient(t, router(repairNode, "", 0), galacticNAD(), pod)

	result, err := repairEndpointSlices(context.Background(), k8s, testNamespace, repairNode)
	if err != nil || result.Restored != 1 {
		t.Fatalf("repairEndpointSlices() = (%+v, %v), want 1 restored", result, err)
	}
	slice, _ := getRepairSlice(t, k8s, "web-0")
	if _, ok := slice.Annotations[crdnames.AnnotationSID]; ok {
		t.Error("SID annotation present, want none without an SRv6 identity")
	}
	if slice.Endpoints[0].Addresses[0] != repairPodAddr {
		t.Errorf("address = %q, want %q (prefix length stripped)", slice.Endpoints[0].Addresses[0], repairPodAddr)
	}
}
