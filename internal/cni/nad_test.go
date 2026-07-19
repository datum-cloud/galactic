// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cni

import (
	"testing"
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
