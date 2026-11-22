/*
Copyright © 2026 Datum Technology, Inc. All rights reserved.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

package webhook

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	computev1alpha "go.datum.net/compute/api/v1alpha"
	networkingv1alpha "go.datum.net/network-services-operator/api/v1alpha"
)

const (
	testPrimaryInterface   = "eth0"
	testSecondaryInterface = "eth1"
	testNetworkA           = "ns/a"
	testNetworkB           = "ns/b"
	testOtherNetwork       = "ns/other"
)

func TestInstanceOwner(t *testing.T) {
	tests := []struct {
		name  string
		owner metav1.OwnerReference
		want  string
	}{
		{"controlling instance", metav1.OwnerReference{
			APIVersion: "compute.datumapis.com/v1alpha", Kind: instanceKind,
			Name: chainInstance, Controller: ptr.To(true)}, chainInstance},
		{"not controlling", metav1.OwnerReference{
			APIVersion: "compute.datumapis.com/v1alpha", Kind: instanceKind, Name: chainInstance}, ""},
		{"another group's instance", metav1.OwnerReference{
			APIVersion: "example.com/v1", Kind: instanceKind,
			Name: chainInstance, Controller: ptr.To(true)}, ""},
		{"a replicaset", metav1.OwnerReference{
			APIVersion: "apps/v1", Kind: "ReplicaSet",
			Name: "web", Controller: ptr.To(true)}, ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{OwnerReferences: []metav1.OwnerReference{test.owner}}}
			got, found := InstanceOwner(pod)
			if got != test.want || found != (test.want != "") {
				t.Errorf("got (%q, %v), want (%q, %v)", got, found, test.want, test.want != "")
			}
		})
	}
}

func TestInterfaceRefFor(t *testing.T) {
	instance := &computev1alpha.Instance{
		Status: computev1alpha.InstanceStatus{
			NetworkInterfaces: []computev1alpha.InstanceNetworkInterfaceStatus{
				{Name: testPrimaryInterface, NetworkInterfaceRef: &networkingv1alpha.LocalNetworkInterfaceRef{Name: "web-0-eth0"}},
				{Name: testSecondaryInterface},
			},
		},
	}
	if got := interfaceRefFor(instance, testPrimaryInterface); got != "web-0-eth0" {
		t.Errorf("bound interface: got %q, want %q", got, "web-0-eth0")
	}
	if got := interfaceRefFor(instance, testSecondaryInterface); got != "" {
		t.Errorf("unbound interface: got %q, want empty", got)
	}
	if got := interfaceRefFor(instance, "eth9"); got != "" {
		t.Errorf("undeclared interface: got %q, want empty", got)
	}
}

func TestMergeNetworks(t *testing.T) {
	tests := []struct {
		name     string
		existing string
		networks []string
		want     string
	}{
		{"empty", "", []string{testNetworkA}, testNetworkA},
		{"nothing to add", "", nil, ""},
		{"appends in order", "", []string{testNetworkA, testNetworkB}, "ns/a,ns/b"},
		{"preserves what the pod asked for", testOtherNetwork, []string{testNetworkA}, "ns/other,ns/a"},
		{"does not duplicate", testNetworkA, []string{testNetworkA}, testNetworkA},
		{"tolerates whitespace", " ns/other , ", []string{testNetworkA}, "ns/other,ns/a"},
		{"drops the default network", "ns/default,ns/other", []string{testNetworkA}, "ns/other,ns/a"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := mergeNetworks(test.existing, test.networks, "ns/default"); got != test.want {
				t.Errorf("got %q, want %q", got, test.want)
			}
		})
	}
}

func TestInjectNetworks(t *testing.T) {
	tests := []struct {
		name        string
		existing    map[string]string
		networks    []string
		wantDefault string
		wantList    string
		wantListSet bool
	}{
		{"single interface is only the default", map[string]string{},
			[]string{testNetworkA}, testNetworkA, "", false},
		{"additional interfaces exclude the default", map[string]string{},
			[]string{testNetworkA, testNetworkB, "ns/c"}, testNetworkA, "ns/b,ns/c", true},
		{"preserves what the pod asked for", map[string]string{MultusNetworksAnnotation: testOtherNetwork},
			[]string{testNetworkA}, testNetworkA, testOtherNetwork, true},
		{"drops a default the pod already listed", map[string]string{MultusNetworksAnnotation: testNetworkA},
			[]string{testNetworkA, testNetworkB}, testNetworkA, testNetworkB, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			injectNetworks(test.existing, test.networks)
			if got := test.existing[MultusDefaultNetworkAnnotation]; got != test.wantDefault {
				t.Errorf("default network: got %q, want %q", got, test.wantDefault)
			}
			got, set := test.existing[MultusNetworksAnnotation]
			if got != test.wantList || set != test.wantListSet {
				t.Errorf("networks: got (%q, %v), want (%q, %v)", got, set, test.wantList, test.wantListSet)
			}
		})
	}
}
