// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package serviceroute

import (
	"net"
	"reflect"
	"testing"

	"k8s.io/apimachinery/pkg/types"

	api "go.datum.net/galactic/api/network/v1alpha1"
)

// The producer's old and new interfaces, as spreadTestProgrammer names them.
const (
	oldProducerDevice = "producer-a"
	newProducerDevice = "producer-b"
)

// remoteProducerIntent is the producer node's half of a remote path, for the
// producer on device.
func remoteProducerIntent(device string) RouteIntent {
	_, service, _ := net.ParseCIDR("fd00::53/128")
	return RouteIntent{
		Attachment:         types.NamespacedName{Namespace: eligibilityNamespace, Name: spreadConsumerName},
		ProducerAttachment: types.NamespacedName{Namespace: spreadProducerNamespace, Name: "producer"},
		Kind:               RouteIntentRemoteProducer,
		Service:            service,
		ServiceDevice:      device,
		ConsumerSID:        net.ParseIP("fd00:123:456:20::"),
		GrantID:            [16]byte{3},
		Ports:              []api.ServiceRouteProtocolPort{{Protocol: api.NetworkServiceProtocolUDP, Port: 53}},
	}
}

// onlyTarget returns the producer ifindex of the one remote target row.
func onlyTarget(t *testing.T, targets *persistedPolicyTable) (uint32, bool) {
	t.Helper()
	if len(targets.rows) > 1 {
		t.Fatalf("%d remote targets, want at most one", len(targets.rows))
	}
	for _, value := range targets.rows {
		return uint32(reflect.ValueOf(value).FieldByName("ProducerIfindex").Uint()), true
	}
	return 0, false
}

// While a producer's interface is replaced, its old and new interfaces hold
// the same grant. Removing either leaves the target on the other.
func TestRemoteTargetFollowsTheRemainingInterface(t *testing.T) {
	for _, removed := range []string{oldProducerDevice, newProducerDevice} {
		t.Run("remove "+removed, func(t *testing.T) {
			programmer, _, _ := spreadTestProgrammer()
			targets := &persistedPolicyTable{}
			programmer.tables.WithRemoteTargets(targets)
			for _, device := range []string{oldProducerDevice, newProducerDevice} {
				if err := programmer.Apply(remoteProducerIntent(device)); err != nil {
					t.Fatalf("Apply(%s): %v", device, err)
				}
			}
			if err := programmer.Remove(remoteProducerIntent(removed)); err != nil {
				t.Fatalf("Remove(%s): %v", removed, err)
			}
			want := uint32(20)
			if removed == oldProducerDevice {
				want = 21
			}
			if got, ok := onlyTarget(t, targets); !ok || got != want {
				t.Fatalf("target = %d, %t; want %d", got, ok, want)
			}
			remaining := oldProducerDevice
			if removed == oldProducerDevice {
				remaining = newProducerDevice
			}
			if err := programmer.Remove(remoteProducerIntent(remaining)); err != nil {
				t.Fatalf("Remove(%s): %v", remaining, err)
			}
			if _, ok := onlyTarget(t, targets); ok {
				t.Fatal("target survived its last grant")
			}
		})
	}
}
