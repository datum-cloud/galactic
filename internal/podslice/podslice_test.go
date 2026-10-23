// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package podslice

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"go.datum.net/galactic/internal/crdnames"
)

const (
	testPodName      = "web-0"
	testPodNamespace = "default"
	testPodUID       = types.UID("11111111-1111-1111-1111-111111111111")
	testPodAddr      = "fd00::1"
	testVPC          = "abc"
	testAttachment   = "def"
	testOldSandbox   = "sandbox-old"
	testNewSandbox   = "sandbox-new"
)

var testSID = netip.MustParseAddr("fd00:1::1")

var testScheme = func() *runtime.Scheme {
	s := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(s))
	return s
}()

func fakeClient(objs ...client.Object) client.Client {
	return fake.NewClientBuilder().WithScheme(testScheme).WithObjects(objs...).Build()
}

func testPod() *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      testPodName,
			Namespace: testPodNamespace,
			UID:       testPodUID,
		},
	}
}

func testEndpoint(sandboxID string) Endpoint {
	return Endpoint{
		VPC:           testVPC,
		VPCAttachment: testAttachment,
		Addr:          net.ParseIP(testPodAddr),
		SID:           testSID,
		SandboxID:     sandboxID,
	}
}

func getSlice(t *testing.T, k8s client.Client) (*discoveryv1.EndpointSlice, error) {
	t.Helper()
	got := &discoveryv1.EndpointSlice{}
	err := k8s.Get(context.Background(), client.ObjectKey{Name: testPodName, Namespace: testPodNamespace}, got)
	return got, err
}

// checkPublished asserts every field Publish and Restore write.
func checkPublished(t *testing.T, got *discoveryv1.EndpointSlice, wantSandbox string) {
	t.Helper()
	wantTenantID := crdnames.TenantIdentifier(testVPC, testAttachment)
	if got.Labels[crdnames.LabelTenantID] != wantTenantID {
		t.Errorf("label %s = %q, want %q", crdnames.LabelTenantID, got.Labels[crdnames.LabelTenantID], wantTenantID)
	}
	if got.Annotations[crdnames.AnnotationTenantID] != wantTenantID {
		t.Errorf("annotation %s = %q, want %q",
			crdnames.AnnotationTenantID, got.Annotations[crdnames.AnnotationTenantID], wantTenantID)
	}
	if got.Annotations[crdnames.AnnotationSID] != testSID.String() {
		t.Errorf("annotation %s = %q, want %q",
			crdnames.AnnotationSID, got.Annotations[crdnames.AnnotationSID], testSID.String())
	}
	gotSandbox, ok := got.Annotations[crdnames.AnnotationSandboxID]
	if wantSandbox == "" && ok {
		t.Errorf("annotation %s = %q, want absent", crdnames.AnnotationSandboxID, gotSandbox)
	} else if gotSandbox != wantSandbox {
		t.Errorf("annotation %s = %q, want %q", crdnames.AnnotationSandboxID, gotSandbox, wantSandbox)
	}
	if got.AddressType != discoveryv1.AddressTypeIPv6 {
		t.Errorf("AddressType = %q, want %q", got.AddressType, discoveryv1.AddressTypeIPv6)
	}
	if len(got.Endpoints) != 1 || len(got.Endpoints[0].Addresses) != 1 || got.Endpoints[0].Addresses[0] != testPodAddr {
		t.Fatalf("Endpoints = %+v, want a single endpoint with address %q", got.Endpoints, testPodAddr)
	}
	if got.Endpoints[0].Conditions.Ready == nil || !*got.Endpoints[0].Conditions.Ready {
		t.Errorf("Endpoints[0].Conditions.Ready = %v, want true", got.Endpoints[0].Conditions.Ready)
	}
	if ref := got.Endpoints[0].TargetRef; ref == nil || ref.UID != testPodUID {
		t.Errorf("Endpoints[0].TargetRef = %+v, want pod UID %s", ref, testPodUID)
	}

	owners := got.GetOwnerReferences()
	if len(owners) != 1 || owners[0].Name != testPodName || owners[0].UID != testPodUID {
		t.Fatalf("OwnerReferences = %+v, want a single owner referencing pod %s (UID %s)",
			owners, testPodName, testPodUID)
	}
	if owners[0].Controller != nil && *owners[0].Controller {
		t.Error("owner reference Controller = true, want false/nil (SetOwnerReference, not SetControllerReference)")
	}
}

func TestPublishFreshPublish(t *testing.T) {
	k8s := fakeClient(testPod())

	if err := Publish(context.Background(), k8s, testPodNamespace, testPodName, testEndpoint(testNewSandbox)); err != nil {
		t.Fatalf("Publish() = %v, want nil", err)
	}

	got, err := getSlice(t, k8s)
	if err != nil {
		t.Fatalf("get EndpointSlice after publish: %v", err)
	}
	checkPublished(t, got, testNewSandbox)
}

func TestPublishSRv6NotConfiguredOmitsSID(t *testing.T) {
	k8s := fakeClient(testPod())
	ep := testEndpoint(testNewSandbox)
	ep.SID = netip.Addr{} // zero value: SID not computed

	if err := Publish(context.Background(), k8s, testPodNamespace, testPodName, ep); err != nil {
		t.Fatalf("Publish() = %v, want nil", err)
	}

	got, err := getSlice(t, k8s)
	if err != nil {
		t.Fatalf("get EndpointSlice after publish: %v", err)
	}
	if _, ok := got.Annotations[crdnames.AnnotationSID]; ok {
		t.Errorf("annotation %s present = %q, want absent when SID was not computed",
			crdnames.AnnotationSID, got.Annotations[crdnames.AnnotationSID])
	}
}

// TestPublishUpdateInPlace covers a slice an earlier sandbox wrote: the new
// sandbox's ADD refreshes every field, including the sandbox annotation.
func TestPublishUpdateInPlace(t *testing.T) {
	existing := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      testPodName,
			Namespace: testPodNamespace,
			Labels:    map[string]string{crdnames.LabelTenantID: "stale-tenant"},
			Annotations: map[string]string{
				crdnames.AnnotationSandboxID: testOldSandbox,
			},
		},
		AddressType: discoveryv1.AddressTypeIPv6,
		Endpoints:   []discoveryv1.Endpoint{{Addresses: []string{"fd00::dead"}}},
	}
	k8s := fakeClient(testPod(), existing)

	if err := Publish(context.Background(), k8s, testPodNamespace, testPodName, testEndpoint(testNewSandbox)); err != nil {
		t.Fatalf("Publish() = %v, want nil", err)
	}

	got, err := getSlice(t, k8s)
	if err != nil {
		t.Fatalf("get EndpointSlice after update: %v", err)
	}
	checkPublished(t, got, testNewSandbox)
}

func TestPublishNamingCollisionNotOverwritten(t *testing.T) {
	foreign := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      testPodName,
			Namespace: testPodNamespace,
			Labels:    map[string]string{"kubernetes.io/service-name": "some-service"},
		},
		AddressType: discoveryv1.AddressTypeIPv4,
	}
	k8s := fakeClient(testPod(), foreign)

	err := Publish(context.Background(), k8s, testPodNamespace, testPodName, testEndpoint(testNewSandbox))
	if err == nil {
		t.Fatal("Publish() = nil, want an error for a non-tenant-labeled name collision")
	}
	if !strings.Contains(err.Error(), crdnames.LabelTenantID) {
		t.Errorf("error %q does not mention %s", err, crdnames.LabelTenantID)
	}

	got, err := getSlice(t, k8s)
	if err != nil {
		t.Fatalf("get EndpointSlice after refused publish: %v", err)
	}
	if got.AddressType != discoveryv1.AddressTypeIPv4 {
		t.Errorf("foreign EndpointSlice was mutated: AddressType = %q, want unchanged %q",
			got.AddressType, discoveryv1.AddressTypeIPv4)
	}
}

func TestPublishOwningPodNotFound(t *testing.T) {
	k8s := fakeClient()

	err := Publish(context.Background(), k8s, testPodNamespace, testPodName, testEndpoint(testNewSandbox))
	if err == nil {
		t.Fatal("Publish() = nil, want an error when the owning Pod does not exist")
	}
	if !apierrors.IsNotFound(err) {
		t.Errorf("Publish() = %v, want an error wrapping not-found", err)
	}
}

func TestRestore(t *testing.T) {
	t.Run("creates a missing slice without a sandbox annotation", func(t *testing.T) {
		k8s := fakeClient(testPod())

		created, err := Restore(context.Background(), k8s, testPod(), testEndpoint(""))
		if err != nil || !created {
			t.Fatalf("Restore() = (%v, %v), want (true, nil)", created, err)
		}
		got, err := getSlice(t, k8s)
		if err != nil {
			t.Fatalf("get EndpointSlice after restore: %v", err)
		}
		checkPublished(t, got, "")
	})

	t.Run("leaves an existing slice untouched", func(t *testing.T) {
		existing := &discoveryv1.EndpointSlice{
			ObjectMeta: metav1.ObjectMeta{
				Name:        testPodName,
				Namespace:   testPodNamespace,
				Labels:      map[string]string{crdnames.LabelTenantID: "fresher-tenant"},
				Annotations: map[string]string{crdnames.AnnotationSandboxID: testNewSandbox},
			},
			AddressType: discoveryv1.AddressTypeIPv6,
			Endpoints:   []discoveryv1.Endpoint{{Addresses: []string{"fd00::2"}}},
		}
		k8s := fakeClient(testPod(), existing)

		created, err := Restore(context.Background(), k8s, testPod(), testEndpoint(""))
		if err != nil || created {
			t.Fatalf("Restore() = (%v, %v), want (false, nil)", created, err)
		}
		got, err := getSlice(t, k8s)
		if err != nil {
			t.Fatalf("get EndpointSlice: %v", err)
		}
		if got.Endpoints[0].Addresses[0] != "fd00::2" || got.Annotations[crdnames.AnnotationSandboxID] != testNewSandbox {
			t.Errorf("existing EndpointSlice was modified: %+v", got)
		}
	})
}

func TestDelete(t *testing.T) {
	sliceFrom := func(sandboxID string) *discoveryv1.EndpointSlice {
		s := &discoveryv1.EndpointSlice{
			ObjectMeta: metav1.ObjectMeta{
				Name:      testPodName,
				Namespace: testPodNamespace,
				Labels:    map[string]string{crdnames.LabelTenantID: crdnames.TenantIdentifier(testVPC, testAttachment)},
			},
			AddressType: discoveryv1.AddressTypeIPv6,
		}
		if sandboxID != "" {
			s.Annotations = map[string]string{crdnames.AnnotationSandboxID: sandboxID}
		}
		return s
	}

	tests := []struct {
		name        string
		existing    *discoveryv1.EndpointSlice
		sandboxID   string
		wantDeleted bool
	}{
		{name: "deletes the slice its own sandbox wrote", existing: sliceFrom(testOldSandbox),
			sandboxID: testOldSandbox, wantDeleted: true},
		{name: "keeps the slice a replacement sandbox wrote", existing: sliceFrom(testNewSandbox),
			sandboxID: testOldSandbox},
		{name: "keeps a slice with no sandbox annotation", existing: sliceFrom(""),
			sandboxID: testOldSandbox},
		{name: "keeps any slice when DEL names no sandbox", existing: sliceFrom(testOldSandbox)},
		{name: "absent slice is not an error", sandboxID: testOldSandbox},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var objs []client.Object
			if tc.existing != nil {
				objs = append(objs, tc.existing)
			}
			k8s := fakeClient(objs...)

			deleted, err := Delete(context.Background(), k8s, testPodNamespace, testPodName, tc.sandboxID)
			if err != nil || deleted != tc.wantDeleted {
				t.Fatalf("Delete() = (%v, %v), want (%v, nil)", deleted, err, tc.wantDeleted)
			}
			_, getErr := getSlice(t, k8s)
			stillThere := getErr == nil
			if tc.existing != nil && stillThere == tc.wantDeleted {
				t.Errorf("slice present after Delete = %v, want %v (get err %v)", stillThere, !tc.wantDeleted, getErr)
			}
		})
	}
}

// TestDeleteLateDelKeepsReplacementSlice is the reboot sequence: the
// replacement sandbox's ADD runs, then the runtime tears down the pod's
// previous sandbox. The replacement's slice must survive that DEL.
func TestDeleteLateDelKeepsReplacementSlice(t *testing.T) {
	k8s := fakeClient(testPod())

	if err := Publish(context.Background(), k8s, testPodNamespace, testPodName, testEndpoint(testNewSandbox)); err != nil {
		t.Fatalf("Publish() = %v, want nil", err)
	}
	if _, err := Delete(context.Background(), k8s, testPodNamespace, testPodName, testOldSandbox); err != nil {
		t.Fatalf("Delete() = %v, want nil", err)
	}

	got, err := getSlice(t, k8s)
	if err != nil {
		t.Fatalf("replacement sandbox's EndpointSlice gone after the previous sandbox's DEL: %v", err)
	}
	checkPublished(t, got, testNewSandbox)
}

// TestDeleteRewrittenBetweenReadAndDelete covers an ADD that rewrites the
// slice after Delete has read it: the precondition fails, and the rewritten
// slice stays.
func TestDeleteRewrittenBetweenReadAndDelete(t *testing.T) {
	base := fakeClient(testPod())
	err := Publish(context.Background(), base, testPodNamespace, testPodName, testEndpoint(testOldSandbox))
	if err != nil {
		t.Fatalf("Publish() = %v, want nil", err)
	}

	k8s := interceptor.NewClient(base.(client.WithWatch), interceptor.Funcs{
		Delete: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
			if err := Publish(ctx, c, testPodNamespace, testPodName, testEndpoint(testNewSandbox)); err != nil {
				t.Fatalf("concurrent Publish() = %v, want nil", err)
			}
			return c.Delete(ctx, obj, opts...)
		},
	})

	deleted, err := Delete(context.Background(), k8s, testPodNamespace, testPodName, testOldSandbox)
	if err != nil || deleted {
		t.Fatalf("Delete() = (%v, %v), want (false, nil)", deleted, err)
	}
	got, err := getSlice(t, base)
	if err != nil {
		t.Fatalf("rewritten EndpointSlice gone: %v", err)
	}
	checkPublished(t, got, testNewSandbox)
}
