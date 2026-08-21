// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package nadpatch

import (
	"context"
	"strings"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
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

		err := AnnotateNAD(context.Background(), k8s, nadName, nadNamespace, hostIface)
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

		if err := AnnotateNAD(context.Background(), k8s, nadName, nadNamespace, hostIface); err != nil {
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

	t.Run("empty pod namespace is a no-op", func(t *testing.T) {
		k8s := fakeClient()

		if err := AnnotateNAD(context.Background(), k8s, nadName, "", hostIface); err != nil {
			t.Fatalf("AnnotateNAD() with empty namespace = %v, want nil", err)
		}
	})
}

func TestVerifyChainComplete(t *testing.T) {
	const (
		nadName      = "test-net"
		nadNamespace = "default"
		bgpType      = "galactic-bgp"
	)

	nadWithConfig := func(config string) *unstructured.Unstructured {
		nad := &unstructured.Unstructured{}
		nad.SetGroupVersionKind(nadGVK)
		nad.SetName(nadName)
		nad.SetNamespace(nadNamespace)
		_ = unstructured.SetNestedField(nad.Object, config, "spec", "config")
		return nad
	}

	t.Run("NAD does not exist is a hard failure", func(t *testing.T) {
		k8s := fakeClient()

		err := VerifyChainComplete(context.Background(), k8s, nadName, nadNamespace, bgpType)
		if err == nil {
			t.Fatal("expected error when NAD does not exist, got nil")
		}
	})

	t.Run("complete chain passes", func(t *testing.T) {
		nad := nadWithConfig(
			`{"cniVersion":"1.0.0","name":"private","plugins":[{"type":"galactic-veth"},{"type":"galactic-bgp"}]}`,
		)
		k8s := fakeClient(nad)

		if err := VerifyChainComplete(context.Background(), k8s, nadName, nadNamespace, bgpType); err != nil {
			t.Fatalf("VerifyChainComplete() = %v, want nil", err)
		}
	})

	t.Run("galactic-bgp missing from spec.config fails", func(t *testing.T) {
		nad := nadWithConfig(`{"cniVersion":"1.0.0","name":"private","plugins":[{"type":"galactic-veth"}]}`)
		k8s := fakeClient(nad)

		err := VerifyChainComplete(context.Background(), k8s, nadName, nadNamespace, bgpType)
		if err == nil {
			t.Fatal("expected error when galactic-bgp is missing, got nil")
		}
		if !strings.Contains(err.Error(), bgpType) {
			t.Errorf("error %q does not name the missing plugin type %q", err, bgpType)
		}
	})

	t.Run("NAD with no spec.config fails", func(t *testing.T) {
		nad := &unstructured.Unstructured{}
		nad.SetGroupVersionKind(nadGVK)
		nad.SetName(nadName)
		nad.SetNamespace(nadNamespace)
		k8s := fakeClient(nad)

		if err := VerifyChainComplete(context.Background(), k8s, nadName, nadNamespace, bgpType); err == nil {
			t.Fatal("expected error when spec.config is absent, got nil")
		}
	})

	t.Run("empty pod namespace is a no-op, no Get issued", func(t *testing.T) {
		k8s := failingClient{t: t}

		if err := VerifyChainComplete(context.Background(), k8s, nadName, "", bgpType); err != nil {
			t.Fatalf("VerifyChainComplete() with empty namespace = %v, want nil", err)
		}
	})
}

// failingClient is a client.Client that fails the test if any method is
// called — used to prove VerifyChainComplete's empty-namespace short
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
