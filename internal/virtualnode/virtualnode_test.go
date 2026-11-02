// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package virtualnode

import (
	"maps"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func node(name string, virtual bool, addrs ...corev1.NodeAddress) corev1.Node {
	n := corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name}}
	if virtual {
		n.Labels = Selector()
	}
	n.Status.Addresses = addrs
	return n
}

func internalIP(addr string) corev1.NodeAddress {
	return corev1.NodeAddress{Type: corev1.NodeInternalIP, Address: addr}
}

func TestHosts(t *testing.T) {
	nodes := []corev1.Node{
		node("host-a", false, internalIP("192.0.2.10"), internalIP("2001:db8::10")),
		node("host-b", false, internalIP("192.0.2.11")),
		node("kraftlet-host-a", true, internalIP("2001:db8::10")),
		node("kraftlet-host-b", true, internalIP("192.0.2.11")),
		// A shared hostname address does not identify the host.
		node("kraftlet-orphan", true, corev1.NodeAddress{Type: corev1.NodeHostName, Address: "host-a"}),
		// Two virtual Nodes sharing an address never map to each other.
		node("kraftlet-x", true, internalIP("192.0.2.99")),
		node("kraftlet-y", true, internalIP("192.0.2.99")),
	}
	want := map[string]string{"kraftlet-host-a": "host-a", "kraftlet-host-b": "host-b"}
	if got := Hosts(nodes); !maps.Equal(got, want) {
		t.Fatalf("Hosts() = %v, want %v", got, want)
	}
}
