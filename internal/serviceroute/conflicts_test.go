// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package serviceroute

import (
	"net"
	"testing"

	"k8s.io/apimachinery/pkg/types"

	networkv1alpha1 "go.datum.net/network/api/v1alpha1"
)

func TestTranslatedConflictScopePreservesDistinctAttachments(t *testing.T) {
	_, service, _ := net.ParseCIDR("fd70::10/128")
	_, frontend, _ := net.ParseCIDR("fd53::53/128")
	first := types.NamespacedName{Namespace: "a", Name: "psc-conflict"}
	second := types.NamespacedName{Namespace: "b", Name: "psc-conflict"}
	route := RouteIntent{Attachment: types.NamespacedName{Namespace: "a", Name: "client"}, Kind: RouteIntentLocal,
		Service: service, Frontend: frontend, Ports: []networkv1alpha1.ServiceRouteProtocolPort{{Protocol: "udp", Port: 53}}}
	other := route
	other.Attachment.Namespace = "b"
	intents := map[types.NamespacedName][]RouteIntent{first: {route}, second: {other}}
	translated := map[types.NamespacedName]bool{first: true, second: true}
	if conflicts := ConflictingPolicies(intents, translated); len(conflicts) != 0 {
		t.Fatalf("distinct VPC attachments conflict=%v", conflicts)
	}
	other.Attachment = route.Attachment
	intents[second] = []RouteIntent{other}
	if conflicts := ConflictingPolicies(intents, translated); len(conflicts) != 2 {
		t.Fatalf("duplicate claim did not fail closed=%v", conflicts)
	}
}
