// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package attachment

import (
	"testing"

	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
)

// A provider is never bound in kube-system or kube-node-lease, which the
// provider policy leaves to Kubernetes, even when it lists a ServiceAccount
// there from before EdgeProvider refused one. Its RoleBinding there is then
// withdrawn like any namespace the provider no longer names.
func TestProviderSubjectsLeaveOutSystemNamespaces(t *testing.T) {
	got := providerSubjects([]galacticv1alpha1.ServiceAccountReference{
		{Namespace: "edge", Name: "a"}, {Namespace: "edge", Name: "b"},
		{Namespace: "kube-system", Name: "c"}, {Namespace: "kube-node-lease", Name: "d"},
	})
	if len(got) != 1 || len(got["edge"]) != 2 {
		t.Fatalf("subjects by namespace = %v, want only edge with both of its ServiceAccounts", got)
	}
}
