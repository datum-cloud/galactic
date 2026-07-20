// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cni

import (
	"context"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestParsePodNamespace(t *testing.T) {
	tests := []struct {
		name     string
		cniArgs  string
		expected string
	}{
		{
			name:     "empty string",
			cniArgs:  "",
			expected: "",
		},
		{
			name:     "namespace only",
			cniArgs:  "K8S_POD_NAMESPACE=default",
			expected: "default",
		},
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
		{
			name:     "namespace with hyphens",
			cniArgs:  "K8S_POD_NAMESPACE=my-custom-namespace",
			expected: "my-custom-namespace",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parsePodNamespace(tc.cniArgs)
			if got != tc.expected {
				t.Errorf("parsePodNamespace(%q) = %q, want %q", tc.cniArgs, got, tc.expected)
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

		err := annotateNAD(context.Background(), k8s, nadName, nadNamespace, hostIface)
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

		if err := annotateNAD(context.Background(), k8s, nadName, nadNamespace, hostIface); err != nil {
			t.Fatalf("annotateNAD() = %v, want nil", err)
		}

		got := &unstructured.Unstructured{}
		got.SetGroupVersionKind(nadGVK)
		if err := k8s.Get(context.Background(), client.ObjectKey{Name: nadName, Namespace: nadNamespace}, got); err != nil {
			t.Fatalf("get NAD after annotate: %v", err)
		}
		if gotAnnotation := got.GetAnnotations()[annotationHostInterface]; gotAnnotation != hostIface {
			t.Errorf("annotation %s = %q, want %q", annotationHostInterface, gotAnnotation, hostIface)
		}
	})

	t.Run("empty pod namespace is a no-op", func(t *testing.T) {
		k8s := fakeClient()

		if err := annotateNAD(context.Background(), k8s, nadName, "", hostIface); err != nil {
			t.Fatalf("annotateNAD() with empty namespace = %v, want nil", err)
		}
	})
}
