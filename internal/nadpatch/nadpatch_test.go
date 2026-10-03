// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package nadpatch

import (
	"context"
	"errors"
	"strings"
	"testing"

	cnitypes "github.com/containernetworking/cni/pkg/types"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

func fakeClient(objs ...client.Object) client.Client {
	return fake.NewClientBuilder().WithScheme(runtime.NewScheme()).WithObjects(objs...).Build()
}

func TestParsePodNamespace(t *testing.T) {
	tests := []struct {
		name     string
		cniArgs  string
		expected string
	}{
		{name: "empty string", cniArgs: "", expected: ""},
		{name: "namespace only", cniArgs: "K8S_POD_NAMESPACE=default", expected: "default"},
		{
			name:     "full multus args",
			cniArgs:  "K8S_POD_NAME=my-pod;K8S_POD_NAMESPACE=galactic-system;K8S_POD_INFRA_CONTAINER_ID=abc123",
			expected: "galactic-system",
		},
		{
			name:     "namespace not present",
			cniArgs:  "K8S_POD_NAME=my-pod;K8S_POD_INFRA_CONTAINER_ID=abc123",
			expected: "",
		},
		{name: "namespace with hyphens", cniArgs: "K8S_POD_NAMESPACE=my-custom-namespace", expected: "my-custom-namespace"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ParsePodNamespace(tc.cniArgs)
			if got != tc.expected {
				t.Errorf("ParsePodNamespace(%q) = %q, want %q", tc.cniArgs, got, tc.expected)
			}
		})
	}
}

func TestParsePodName(t *testing.T) {
	tests := []struct {
		name     string
		cniArgs  string
		expected string
	}{
		{name: "empty string", cniArgs: "", expected: ""},
		{name: "name only", cniArgs: "K8S_POD_NAME=my-pod", expected: "my-pod"},
		{
			name:     "full multus args",
			cniArgs:  "K8S_POD_NAME=my-pod;K8S_POD_NAMESPACE=galactic-system;K8S_POD_INFRA_CONTAINER_ID=abc123",
			expected: "my-pod",
		},
		{
			name:     "name not present",
			cniArgs:  "K8S_POD_NAMESPACE=galactic-system;K8S_POD_INFRA_CONTAINER_ID=abc123",
			expected: "",
		},
		{name: "name with hyphens", cniArgs: "K8S_POD_NAME=my-custom-pod-0", expected: "my-custom-pod-0"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ParsePodName(tc.cniArgs)
			if got != tc.expected {
				t.Errorf("ParsePodName(%q) = %q, want %q", tc.cniArgs, got, tc.expected)
			}
		})
	}
}

func TestAnnotateNAD(t *testing.T) {
	const (
		nadName      = "test-net"
		nadNamespace = "default"
		hostIface    = "vpc-abc-def"
	)

	t.Run("NAD does not exist is a hard failure", func(t *testing.T) {
		k8s := fakeClient()

		err := AnnotateNAD(context.Background(), k8s, nadName, nadNamespace,
			map[string]string{AnnotationHostInterface: hostIface})
		if err == nil {
			t.Fatal("expected error when NAD does not exist, got nil")
		}
		if !apierrors.IsNotFound(err) {
			t.Errorf("expected error to wrap a not-found status, got: %v", err)
		}
	})

	t.Run("NAD exists is annotated successfully", func(t *testing.T) {
		nad := &unstructured.Unstructured{}
		nad.SetGroupVersionKind(nadGVK)
		nad.SetName(nadName)
		nad.SetNamespace(nadNamespace)
		k8s := fakeClient(nad)

		if err := AnnotateNAD(context.Background(), k8s, nadName, nadNamespace,
			map[string]string{AnnotationHostInterface: hostIface}); err != nil {
			t.Fatalf("AnnotateNAD() = %v, want nil", err)
		}

		got := &unstructured.Unstructured{}
		got.SetGroupVersionKind(nadGVK)
		if err := k8s.Get(context.Background(), client.ObjectKey{Name: nadName, Namespace: nadNamespace}, got); err != nil {
			t.Fatalf("get NAD after annotate: %v", err)
		}
		if gotAnnotation := got.GetAnnotations()[AnnotationHostInterface]; gotAnnotation != hostIface {
			t.Errorf("annotation %s = %q, want %q", AnnotationHostInterface, gotAnnotation, hostIface)
		}
	})

	t.Run("host interface and subnet length are written together", func(t *testing.T) {
		// A hypervisor adopting the host device reads both keys. Writing the
		// name without the prefix length leaves it unable to configure the
		// guest, so the pair has to land in one patch.
		const subnetLen = "96"

		nad := &unstructured.Unstructured{}
		nad.SetGroupVersionKind(nadGVK)
		nad.SetName(nadName)
		nad.SetNamespace(nadNamespace)
		k8s := fakeClient(nad)

		if err := AnnotateNAD(context.Background(), k8s, nadName, nadNamespace, map[string]string{
			AnnotationHostInterface: hostIface,
			AnnotationSubnetLen:     subnetLen,
		}); err != nil {
			t.Fatalf("AnnotateNAD() = %v, want nil", err)
		}

		got := &unstructured.Unstructured{}
		got.SetGroupVersionKind(nadGVK)
		if err := k8s.Get(context.Background(), client.ObjectKey{Name: nadName, Namespace: nadNamespace}, got); err != nil {
			t.Fatalf("get NAD after annotate: %v", err)
		}
		if v := got.GetAnnotations()[AnnotationHostInterface]; v != hostIface {
			t.Errorf("annotation %s = %q, want %q", AnnotationHostInterface, v, hostIface)
		}
		if v := got.GetAnnotations()[AnnotationSubnetLen]; v != subnetLen {
			t.Errorf("annotation %s = %q, want %q", AnnotationSubnetLen, v, subnetLen)
		}
	})

	t.Run("pre-existing foreign annotations survive", func(t *testing.T) {
		// A NetworkAttachmentDefinition is authored and owned by the external
		// VPC operator, so it arrives carrying annotations from Multus, the
		// CNI tooling, and whatever applied it. The patch has to leave every
		// one of them in place.
		const (
			resourceNameKey = "k8s.v1.cni.cncf.io/resourceName"
			resourceNameVal = "intel.com/sriov_netdevice"
			lastAppliedKey  = "kubectl.kubernetes.io/last-applied-configuration"
			lastAppliedVal  = `{"apiVersion":"k8s.cni.cncf.io/v1"}`
			tildeKey        = "example.com/odd~key/with~slash"
			tildeVal        = "preserved"
		)

		nad := &unstructured.Unstructured{}
		nad.SetGroupVersionKind(nadGVK)
		nad.SetName(nadName)
		nad.SetNamespace(nadNamespace)
		nad.SetAnnotations(map[string]string{
			resourceNameKey: resourceNameVal,
			lastAppliedKey:  lastAppliedVal,
			tildeKey:        tildeVal,
		})
		k8s := fakeClient(nad)

		if err := AnnotateNAD(context.Background(), k8s, nadName, nadNamespace,
			map[string]string{AnnotationHostInterface: hostIface}); err != nil {
			t.Fatalf("AnnotateNAD() = %v, want nil", err)
		}

		got := &unstructured.Unstructured{}
		got.SetGroupVersionKind(nadGVK)
		if err := k8s.Get(context.Background(), client.ObjectKey{Name: nadName, Namespace: nadNamespace}, got); err != nil {
			t.Fatalf("get NAD after annotate: %v", err)
		}

		want := map[string]string{
			resourceNameKey:         resourceNameVal,
			lastAppliedKey:          lastAppliedVal,
			tildeKey:                tildeVal,
			AnnotationHostInterface: hostIface,
		}
		gotAnnotations := got.GetAnnotations()
		for key, wantValue := range want {
			if gotAnnotations[key] != wantValue {
				t.Errorf("annotation %s = %q, want %q", key, gotAnnotations[key], wantValue)
			}
		}
		if len(gotAnnotations) != len(want) {
			t.Errorf("annotations = %v, want exactly %d entries", gotAnnotations, len(want))
		}
	})

	t.Run("re-annotating an already annotated NAD overwrites only its own key", func(t *testing.T) {
		const foreignKey = "k8s.v1.cni.cncf.io/resourceName"

		nad := &unstructured.Unstructured{}
		nad.SetGroupVersionKind(nadGVK)
		nad.SetName(nadName)
		nad.SetNamespace(nadNamespace)
		nad.SetAnnotations(map[string]string{
			foreignKey:              "intel.com/sriov_netdevice",
			AnnotationHostInterface: "vpc-stale-iface",
		})
		k8s := fakeClient(nad)

		if err := AnnotateNAD(context.Background(), k8s, nadName, nadNamespace,
			map[string]string{AnnotationHostInterface: hostIface}); err != nil {
			t.Fatalf("AnnotateNAD() = %v, want nil", err)
		}

		got := &unstructured.Unstructured{}
		got.SetGroupVersionKind(nadGVK)
		if err := k8s.Get(context.Background(), client.ObjectKey{Name: nadName, Namespace: nadNamespace}, got); err != nil {
			t.Fatalf("get NAD after annotate: %v", err)
		}
		if v := got.GetAnnotations()[AnnotationHostInterface]; v != hostIface {
			t.Errorf("annotation %s = %q, want %q", AnnotationHostInterface, v, hostIface)
		}
		if v := got.GetAnnotations()[foreignKey]; v != "intel.com/sriov_netdevice" {
			t.Errorf("annotation %s = %q, want it preserved", foreignKey, v)
		}
	})

	t.Run("a conflict from the server is surfaced, not swallowed", func(t *testing.T) {
		// A merge patch carries no resourceVersion, so the API server has no
		// precondition to fail and cannot answer this call with a conflict of
		// its own. One can still arrive from an admission webhook, and it
		// means the host interface never reached the definition: report it so
		// the attach fails loudly instead of handing back an interface with no
		// path to its VPC.
		base := fake.NewClientBuilder().WithScheme(runtime.NewScheme()).Build()
		k8s := interceptor.NewClient(base, interceptor.Funcs{
			Patch: func(context.Context, client.WithWatch, client.Object, client.Patch, ...client.PatchOption) error {
				return apierrors.NewConflict(
					schema.GroupResource{Group: nadGVK.Group, Resource: "network-attachment-definitions"},
					nadName, errors.New("rejected by webhook"),
				)
			},
		})

		err := AnnotateNAD(context.Background(), k8s, nadName, nadNamespace,
			map[string]string{AnnotationHostInterface: hostIface})
		if err == nil {
			t.Fatal("expected error when the server reports a conflict, got nil")
		}
		if !apierrors.IsConflict(err) {
			t.Errorf("expected error to wrap a conflict status, got: %v", err)
		}
	})

	t.Run("empty pod namespace is a no-op", func(t *testing.T) {
		k8s := fakeClient()

		if err := AnnotateNAD(context.Background(), k8s, nadName, "",
			map[string]string{AnnotationHostInterface: hostIface}); err != nil {
			t.Fatalf("AnnotateNAD() with empty namespace = %v, want nil", err)
		}
	})
}

func TestVerifyDefinition(t *testing.T) {
	const (
		nadName      = "test-net"
		nadNamespace = "default"
		bgpType      = "galactic-bgp"
	)
	want := Expected{ChainType: bgpType, VPC: "vpc1", VPCAttachment: "att1"}
	completeChain := func(vpc, vpcAttachment string) string {
		return `{"cniVersion":"1.0.0","name":"private","plugins":[` +
			`{"type":"galactic-veth","vpc":"` + vpc + `","vpcattachment":"` + vpcAttachment + `"},` +
			`{"type":"galactic-bgp","vpc":"` + vpc + `","vpcattachment":"` + vpcAttachment + `"}]}`
	}

	nadWithConfig := func(config string) *unstructured.Unstructured {
		nad := &unstructured.Unstructured{}
		nad.SetGroupVersionKind(nadGVK)
		nad.SetName(nadName)
		nad.SetNamespace(nadNamespace)
		_ = unstructured.SetNestedField(nad.Object, config, "spec", "config")
		return nad
	}
	wantCode := func(t *testing.T, err error, code uint) {
		t.Helper()
		var cniErr *cnitypes.Error
		if !errors.As(err, &cniErr) {
			t.Fatalf("error %v is not a CNI error", err)
		}
		if cniErr.Code != code {
			t.Errorf("CNI error code = %d, want %d (%s)", cniErr.Code, code, cniErr.Msg)
		}
	}

	t.Run("NAD does not exist is a hard failure", func(t *testing.T) {
		k8s := fakeClient()

		err := VerifyDefinition(context.Background(), k8s, nadName, nadNamespace, want)
		if err == nil {
			t.Fatal("expected error when NAD does not exist, got nil")
		}
	})

	t.Run("complete chain with matching identifiers passes", func(t *testing.T) {
		k8s := fakeClient(nadWithConfig(completeChain("vpc1", "att1")))

		if err := VerifyDefinition(context.Background(), k8s, nadName, nadNamespace, want); err != nil {
			t.Fatalf("VerifyDefinition() = %v, want nil", err)
		}
	})

	t.Run("plugin stanza without identifiers is not compared", func(t *testing.T) {
		k8s := fakeClient(nadWithConfig(`{"cniVersion":"1.0.0","name":"private","plugins":[` +
			`{"type":"galactic-veth","vpc":"vpc1","vpcattachment":"att1"},` +
			`{"type":"tuning"},` +
			`{"type":"galactic-bgp","vpc":"vpc1","vpcattachment":"att1"}]}`))

		if err := VerifyDefinition(context.Background(), k8s, nadName, nadNamespace, want); err != nil {
			t.Fatalf("VerifyDefinition() = %v, want nil", err)
		}
	})

	t.Run("galactic-bgp missing from spec.config fails", func(t *testing.T) {
		k8s := fakeClient(nadWithConfig(
			`{"cniVersion":"1.0.0","name":"private","plugins":[{"type":"galactic-veth","vpc":"vpc1","vpcattachment":"att1"}]}`))

		err := VerifyDefinition(context.Background(), k8s, nadName, nadNamespace, want)
		if err == nil {
			t.Fatal("expected error when galactic-bgp is missing, got nil")
		}
		if !strings.Contains(err.Error(), bgpType) {
			t.Errorf("error %q does not name the missing plugin type %q", err, bgpType)
		}
		wantCode(t, err, cnitypes.ErrInvalidNetworkConfig)
	})

	t.Run("NAD with no spec.config fails", func(t *testing.T) {
		nad := &unstructured.Unstructured{}
		nad.SetGroupVersionKind(nadGVK)
		nad.SetName(nadName)
		nad.SetNamespace(nadNamespace)
		k8s := fakeClient(nad)

		err := VerifyDefinition(context.Background(), k8s, nadName, nadNamespace, want)
		if err == nil {
			t.Fatal("expected error when spec.config is absent, got nil")
		}
		wantCode(t, err, cnitypes.ErrInvalidNetworkConfig)
	})

	// A workload recreated under the same names: the runtime still holds the
	// previous incarnation's attachment identifier, the operator has since
	// written a new one.
	t.Run("stale attachment identifier asks the runtime to retry", func(t *testing.T) {
		k8s := fakeClient(nadWithConfig(completeChain("vpc1", "att2")))

		err := VerifyDefinition(context.Background(), k8s, nadName, nadNamespace, want)
		if err == nil {
			t.Fatal("expected error when the live definition names another attachment, got nil")
		}
		for _, id := range []string{"att1", "att2"} {
			if !strings.Contains(err.Error(), id) {
				t.Errorf("error %q does not name attachment identifier %q", err, id)
			}
		}
		wantCode(t, err, cnitypes.ErrTryAgainLater)
	})

	t.Run("stale VPC identifier asks the runtime to retry", func(t *testing.T) {
		k8s := fakeClient(nadWithConfig(completeChain("vpc2", "att1")))

		err := VerifyDefinition(context.Background(), k8s, nadName, nadNamespace, want)
		if err == nil {
			t.Fatal("expected error when the live definition names another VPC, got nil")
		}
		wantCode(t, err, cnitypes.ErrTryAgainLater)
	})

	t.Run("mismatch in the BGP stanza alone is caught", func(t *testing.T) {
		k8s := fakeClient(nadWithConfig(`{"cniVersion":"1.0.0","name":"private","plugins":[` +
			`{"type":"galactic-veth","vpc":"vpc1","vpcattachment":"att1"},` +
			`{"type":"galactic-bgp","vpc":"vpc1","vpcattachment":"att2"}]}`))

		err := VerifyDefinition(context.Background(), k8s, nadName, nadNamespace, want)
		if err == nil {
			t.Fatal("expected error when the BGP stanza names another attachment, got nil")
		}
		wantCode(t, err, cnitypes.ErrTryAgainLater)
	})

	t.Run("definition being deleted asks the runtime to retry", func(t *testing.T) {
		nad := nadWithConfig(completeChain("vpc1", "att1"))
		nad.SetFinalizers([]string{"example.com/hold"})
		k8s := fakeClient(nad)
		if err := k8s.Delete(context.Background(), nad); err != nil {
			t.Fatalf("mark NAD deleting: %v", err)
		}

		err := VerifyDefinition(context.Background(), k8s, nadName, nadNamespace, want)
		if err == nil {
			t.Fatal("expected error when the definition is being deleted, got nil")
		}
		wantCode(t, err, cnitypes.ErrTryAgainLater)
	})

	t.Run("empty pod namespace is a no-op, no Get issued", func(t *testing.T) {
		k8s := failingClient{t: t}

		if err := VerifyDefinition(context.Background(), k8s, nadName, "", want); err != nil {
			t.Fatalf("VerifyDefinition() with empty namespace = %v, want nil", err)
		}
	})
}

// failingClient is a client.Client that fails the test if any method is
// called — used to prove VerifyDefinition's empty-namespace short
// circuit never touches the k8s client at all.
type failingClient struct {
	client.Client
	t *testing.T
}

func (f failingClient) Get(context.Context, client.ObjectKey, client.Object, ...client.GetOption) error {
	f.t.Helper()
	f.t.Fatal("Get should not be called when nadNamespace is empty")
	return nil
}
