// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gc

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	cloudv1alpha1 "go.datum.net/cloud/api/v1alpha1"
)

const (
	testNamespace      = "default"
	testVPCName        = "my-vpc"
	testNADName        = "vpc-abc-def"
	testAttachmentName = "abc-def"
)

var gcTestScheme = func() *runtime.Scheme {
	s := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(s))
	utilruntime.Must(cloudv1alpha1.AddToScheme(s))
	return s
}()

func gcFakeClient(objs ...client.Object) client.Client {
	return fake.NewClientBuilder().WithScheme(gcTestScheme).WithObjects(objs...).Build()
}

func testNAD(name string, labels map[string]string) *unstructured.Unstructured {
	nad := &unstructured.Unstructured{}
	nad.SetGroupVersionKind(nadGVK)
	nad.SetName(name)
	nad.SetNamespace(testNamespace)
	nad.SetLabels(labels)
	return nad
}

func podWithNetworks(name, networksJSON string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: testNamespace,
			Annotations: map[string]string{
				networksAnnotation: networksJSON,
			},
		},
	}
}

func TestCollectOrphanedNADs(t *testing.T) {
	t.Run("unlabeled NAD is never a candidate", func(t *testing.T) {
		nad := testNAD("manual-nad", nil)
		k8s := gcFakeClient(nad)

		orphans, err := CollectOrphanedNADs(context.Background(), k8s)
		if err != nil {
			t.Fatalf("CollectOrphanedNADs() = %v, want nil", err)
		}
		if len(orphans) != 0 {
			t.Errorf("orphans = %v, want none (unlabeled NAD skipped)", orphans)
		}
	})

	t.Run("labeled NAD referenced by a live pod is not orphaned", func(t *testing.T) {
		nad := testNAD(testNADName, map[string]string{labelVPC: testVPCName})
		pod := podWithNetworks("my-pod", `[{"name":"vpc-abc-def","namespace":"default"}]`)
		k8s := gcFakeClient(nad, pod)

		orphans, err := CollectOrphanedNADs(context.Background(), k8s)
		if err != nil {
			t.Fatalf("CollectOrphanedNADs() = %v, want nil", err)
		}
		if len(orphans) != 0 {
			t.Errorf("orphans = %v, want none (referenced by live pod)", orphans)
		}
	})

	t.Run("labeled NAD with no referencing pod is orphaned", func(t *testing.T) {
		nad := testNAD(testNADName, map[string]string{labelVPC: testVPCName})
		unrelatedPod := podWithNetworks("other-pod", `[{"name":"some-other-nad"}]`)
		k8s := gcFakeClient(nad, unrelatedPod)

		orphans, err := CollectOrphanedNADs(context.Background(), k8s)
		if err != nil {
			t.Fatalf("CollectOrphanedNADs() = %v, want nil", err)
		}
		if len(orphans) != 1 || orphans[0].Name != testNADName || orphans[0].Kind != kindNetworkAttachmentDefinition {
			t.Errorf("orphans = %+v, want exactly one %s orphan named %s", orphans, kindNetworkAttachmentDefinition, testNADName)
		}
	})

	t.Run("malformed networks annotation does not block reclaim", func(t *testing.T) {
		nad := testNAD(testNADName, map[string]string{labelVPC: testVPCName})
		brokenPod := podWithNetworks("broken-pod", `not-json`)
		k8s := gcFakeClient(nad, brokenPod)

		orphans, err := CollectOrphanedNADs(context.Background(), k8s)
		if err != nil {
			t.Fatalf("CollectOrphanedNADs() = %v, want nil", err)
		}
		if len(orphans) != 1 {
			t.Errorf("orphans = %v, want one (malformed annotation ignored, not treated as a reference)", orphans)
		}
	})
}

func TestCollectOrphanedVPCAttachments(t *testing.T) {
	const nodeName = "node-1"

	newAttachment := func(name, node, podName string) *cloudv1alpha1.VPCAttachment {
		a := &cloudv1alpha1.VPCAttachment{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: testNamespace},
			Spec: cloudv1alpha1.VPCAttachmentSpec{
				VPC: cloudv1alpha1.VPCRef{Name: testVPCName},
				Interface: cloudv1alpha1.VPCAttachmentInterface{
					Name:      "eth0",
					Addresses: []cloudv1alpha1.IPAddress{"10.0.0.1/32"},
				},
			},
		}
		a.Status = cloudv1alpha1.VPCAttachmentStatus{Node: node, PodName: podName}
		return a
	}

	t.Run("different node is not ours to judge", func(t *testing.T) {
		attachment := newAttachment(testAttachmentName, "other-node", "gone-pod")
		k8s := gcFakeClient(attachment)

		orphans, err := CollectOrphanedVPCAttachments(context.Background(), k8s, nodeName)
		if err != nil {
			t.Fatalf("CollectOrphanedVPCAttachments() = %v, want nil", err)
		}
		if len(orphans) != 0 {
			t.Errorf("orphans = %v, want none (belongs to another node)", orphans)
		}
	})

	t.Run("empty PodName is skipped, not treated as orphaned", func(t *testing.T) {
		attachment := newAttachment(testAttachmentName, nodeName, "")
		k8s := gcFakeClient(attachment)

		orphans, err := CollectOrphanedVPCAttachments(context.Background(), k8s, nodeName)
		if err != nil {
			t.Fatalf("CollectOrphanedVPCAttachments() = %v, want nil", err)
		}
		if len(orphans) != 0 {
			t.Errorf("orphans = %v, want none (empty PodName cannot be judged)", orphans)
		}
	})

	t.Run("pod still exists is not orphaned", func(t *testing.T) {
		attachment := newAttachment(testAttachmentName, nodeName, "my-pod")
		pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "my-pod", Namespace: testNamespace}}
		k8s := gcFakeClient(attachment, pod)

		orphans, err := CollectOrphanedVPCAttachments(context.Background(), k8s, nodeName)
		if err != nil {
			t.Fatalf("CollectOrphanedVPCAttachments() = %v, want nil", err)
		}
		if len(orphans) != 0 {
			t.Errorf("orphans = %v, want none (pod still exists)", orphans)
		}
	})

	t.Run("pod gone is orphaned", func(t *testing.T) {
		attachment := newAttachment(testAttachmentName, nodeName, "gone-pod")
		k8s := gcFakeClient(attachment)

		orphans, err := CollectOrphanedVPCAttachments(context.Background(), k8s, nodeName)
		if err != nil {
			t.Fatalf("CollectOrphanedVPCAttachments() = %v, want nil", err)
		}
		if len(orphans) != 1 || orphans[0].Name != testAttachmentName || orphans[0].Kind != kindVPCAttachment {
			t.Errorf("orphans = %+v, want exactly one %s orphan named %s", orphans, kindVPCAttachment, testAttachmentName)
		}
	})
}

func TestRemoveOrphanedCRDsVPCAttachmentAndNAD(t *testing.T) {
	attachment := &cloudv1alpha1.VPCAttachment{
		ObjectMeta: metav1.ObjectMeta{Name: testAttachmentName, Namespace: testNamespace},
		Spec: cloudv1alpha1.VPCAttachmentSpec{
			VPC: cloudv1alpha1.VPCRef{Name: testVPCName},
			Interface: cloudv1alpha1.VPCAttachmentInterface{
				Name:      "eth0",
				Addresses: []cloudv1alpha1.IPAddress{"10.0.0.1/32"},
			},
		},
	}
	nad := testNAD(testNADName, map[string]string{labelVPC: testVPCName})
	k8s := gcFakeClient(attachment, nad)

	orphans := []OrphanedCRD{
		{Name: testAttachmentName, Namespace: testNamespace, Kind: kindVPCAttachment},
		{Name: testNADName, Namespace: testNamespace, Kind: kindNetworkAttachmentDefinition},
	}
	result := RemoveOrphanedCRDs(context.Background(), k8s, orphans)
	if result.Errors != 0 {
		t.Errorf("result.Errors = %d, want 0", result.Errors)
	}
	if result.OrphanedCRDsRemoved != 2 {
		t.Errorf("result.OrphanedCRDsRemoved = %d, want 2", result.OrphanedCRDsRemoved)
	}

	var gotAttachment cloudv1alpha1.VPCAttachment
	attachmentKey := client.ObjectKey{Name: testAttachmentName, Namespace: testNamespace}
	if err := k8s.Get(context.Background(), attachmentKey, &gotAttachment); err == nil {
		t.Error("expected VPCAttachment to be deleted")
	}
	gotNAD := &unstructured.Unstructured{}
	gotNAD.SetGroupVersionKind(nadGVK)
	key := client.ObjectKey{Name: testNADName, Namespace: testNamespace}
	if err := k8s.Get(context.Background(), key, gotNAD); err == nil {
		t.Error("expected NAD to be deleted")
	}
}
