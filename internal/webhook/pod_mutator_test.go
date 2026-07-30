// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package webhook

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	jsonpatch "github.com/evanphx/json-patch/v5"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	cloudv1alpha1 "go.datum.net/cloud/api/v1alpha1"
)

func newPodMutator(objs ...client.Object) (*PodMutator, client.Client) {
	k8s := webhookFakeClient(objs...)
	return &PodMutator{
		Client:      k8s,
		Decoder:     admission.NewDecoder(NewScheme()),
		NADDefaults: DefaultNADDefaults(),
	}, k8s
}

// admissionRequest builds an admission.Request for pod in testNamespace.
func admissionRequest(t *testing.T, pod *corev1.Pod, dryRun bool) admission.Request {
	t.Helper()
	raw, err := json.Marshal(pod)
	if err != nil {
		t.Fatalf("marshal pod: %v", err)
	}
	return admission.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{
			Namespace: testNamespace,
			DryRun:    &dryRun,
			Object:    runtime.RawExtension{Raw: raw},
		},
	}
}

// testVPCObj builds a VPC named testVPCName in testNamespace with the given
// Status.VPC.
func testVPCObj(statusVPC string) *cloudv1alpha1.VPC {
	return &cloudv1alpha1.VPC{
		ObjectMeta: metav1.ObjectMeta{Name: testVPCName, Namespace: testNamespace},
		Spec:       cloudv1alpha1.VPCSpec{Networks: []cloudv1alpha1.Network{"10.0.0.0/8"}},
		Status:     cloudv1alpha1.VPCStatus{VPC: statusVPC},
	}
}

// applyPatches applies resp's JSON patch operations to the original raw pod
// JSON and unmarshals the result, so tests can assert on the actual patched
// annotations rather than parsing raw patch operations.
func applyPatches(t *testing.T, original []byte, resp admission.Response) *corev1.Pod {
	t.Helper()
	if len(resp.Patches) == 0 {
		var pod corev1.Pod
		if err := json.Unmarshal(original, &pod); err != nil {
			t.Fatalf("unmarshal original pod: %v", err)
		}
		return &pod
	}
	patchJSON, err := json.Marshal(resp.Patches)
	if err != nil {
		t.Fatalf("marshal patches: %v", err)
	}
	patch, err := jsonpatch.DecodePatch(patchJSON)
	if err != nil {
		t.Fatalf("decode patch: %v", err)
	}
	patched, err := patch.Apply(original)
	if err != nil {
		t.Fatalf("apply patch: %v", err)
	}
	var pod corev1.Pod
	if err := json.Unmarshal(patched, &pod); err != nil {
		t.Fatalf("unmarshal patched pod: %v", err)
	}
	return &pod
}

func TestPodMutatorHandle(t *testing.T) {
	basePod := func() *corev1.Pod {
		return &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: testNamespace,
			},
		}
	}

	t.Run("no vpc annotation is a silent no-op", func(t *testing.T) {
		m, _ := newPodMutator()
		resp := m.Handle(context.Background(), admissionRequest(t, basePod(), false))
		if !resp.Allowed {
			t.Fatalf("Allowed = false, want true: %+v", resp.Result)
		}
		if len(resp.Patches) != 0 {
			t.Errorf("Patches = %v, want none", resp.Patches)
		}
	})

	t.Run("reinvocation guard short-circuits", func(t *testing.T) {
		pod := basePod()
		pod.Annotations = map[string]string{annotationVPCAttachmentRef: testNamespace + "/my-vpc-0"}
		m, _ := newPodMutator()

		resp := m.Handle(context.Background(), admissionRequest(t, pod, false))
		if !resp.Allowed {
			t.Fatalf("Allowed = false, want true: %+v", resp.Result)
		}
		if len(resp.Patches) != 0 {
			t.Errorf("Patches = %v, want none (already processed)", resp.Patches)
		}
	})

	t.Run("hostNetwork pod is skipped", func(t *testing.T) {
		pod := basePod()
		pod.Annotations = map[string]string{annotationVPC: testVPCName}
		pod.Spec.HostNetwork = true
		m, _ := newPodMutator()

		resp := m.Handle(context.Background(), admissionRequest(t, pod, false))
		if !resp.Allowed {
			t.Fatalf("Allowed = false, want true: %+v", resp.Result)
		}
		if len(resp.Patches) != 0 {
			t.Errorf("Patches = %v, want none (hostNetwork)", resp.Patches)
		}
	})

	t.Run("missing VPC is denied", func(t *testing.T) {
		pod := basePod()
		pod.Annotations = map[string]string{annotationVPC: "does-not-exist"}
		m, _ := newPodMutator()

		resp := m.Handle(context.Background(), admissionRequest(t, pod, false))
		if resp.Allowed {
			t.Fatal("Allowed = true, want false (VPC missing)")
		}
		if resp.Result.Code != http.StatusForbidden {
			t.Errorf("Result.Code = %d, want %d", resp.Result.Code, http.StatusForbidden)
		}
	})

	t.Run("VPC with no assigned identifier yet is denied", func(t *testing.T) {
		pod := basePod()
		pod.Annotations = map[string]string{annotationVPC: testVPCName}
		vpc := testVPCObj("") // Status.VPC empty
		m, _ := newPodMutator(vpc)

		resp := m.Handle(context.Background(), admissionRequest(t, pod, false))
		if resp.Allowed {
			t.Fatal("Allowed = true, want false (no assigned identifier)")
		}
	})

	t.Run("dry-run never creates real objects", func(t *testing.T) {
		pod := basePod()
		pod.Annotations = map[string]string{annotationVPC: testVPCName}
		vpc := testVPCObj("vpcBase62")
		m, k8s := newPodMutator(vpc)

		resp := m.Handle(context.Background(), admissionRequest(t, pod, true))
		if !resp.Allowed {
			t.Fatalf("Allowed = false, want true: %+v", resp.Result)
		}
		if len(resp.Patches) != 0 {
			t.Errorf("Patches = %v, want none on dry-run", resp.Patches)
		}
		var nadList unstructured.UnstructuredList
		nadList.SetGroupVersionKind(nadGVK)
		if err := k8s.List(context.Background(), &nadList); err != nil {
			t.Fatalf("list NADs: %v", err)
		}
		if len(nadList.Items) != 0 {
			t.Errorf("NADs created on dry-run = %d, want 0", len(nadList.Items))
		}
	})

	t.Run("happy path creates NAD and patches the pod", func(t *testing.T) {
		pod := basePod()
		pod.Annotations = map[string]string{annotationVPC: testVPCName}
		vpc := testVPCObj("vpcBase62")
		m, k8s := newPodMutator(vpc)

		req := admissionRequest(t, pod, false)
		resp := m.Handle(context.Background(), req)
		if !resp.Allowed {
			t.Fatalf("Allowed = false, want true: %+v", resp.Result)
		}
		if len(resp.Patches) == 0 {
			t.Fatal("Patches is empty, want a patch")
		}

		var nadList unstructured.UnstructuredList
		nadList.SetGroupVersionKind(nadGVK)
		if err := k8s.List(context.Background(), &nadList); err != nil {
			t.Fatalf("list NADs: %v", err)
		}
		if len(nadList.Items) != 1 {
			t.Fatalf("NADs created = %d, want 1", len(nadList.Items))
		}
		nadName := nadList.Items[0].GetName()
		if nadName != "vpcBase62-0" {
			t.Errorf("NAD name = %q, want %q", nadName, "vpcBase62-0")
		}

		patched := applyPatches(t, req.Object.Raw, resp)
		wantRef := testNamespace + "/" + nadName
		if patched.Annotations[annotationVPCAttachmentRef] != wantRef {
			t.Errorf("annotationVPCAttachmentRef = %q, want %q",
				patched.Annotations[annotationVPCAttachmentRef], wantRef)
		}
		var elements []networkSelectionElement
		if err := json.Unmarshal([]byte(patched.Annotations[networksAnnotation]), &elements); err != nil {
			t.Fatalf("unmarshal networks annotation: %v", err)
		}
		if len(elements) != 1 || elements[0].Name != nadName {
			t.Errorf("networks annotation = %+v, want one entry naming %q", elements, nadName)
		}
	})

	t.Run("second pod against the same VPC gets a distinct ID", func(t *testing.T) {
		vpc := testVPCObj("vpcBase62")
		m, k8s := newPodMutator(vpc)

		for range 2 {
			pod := basePod()
			pod.Annotations = map[string]string{annotationVPC: testVPCName}
			resp := m.Handle(context.Background(), admissionRequest(t, pod, false))
			if !resp.Allowed {
				t.Fatalf("Allowed = false, want true: %+v", resp.Result)
			}
		}

		var nadList unstructured.UnstructuredList
		nadList.SetGroupVersionKind(nadGVK)
		if err := k8s.List(context.Background(), &nadList); err != nil {
			t.Fatalf("list NADs: %v", err)
		}
		if len(nadList.Items) != 2 {
			t.Fatalf("NADs created = %d, want 2 (distinct IDs)", len(nadList.Items))
		}
		if nadList.Items[0].GetName() == nadList.Items[1].GetName() {
			t.Error("both pods got the same NAD name, want distinct IDs")
		}
	})
}
