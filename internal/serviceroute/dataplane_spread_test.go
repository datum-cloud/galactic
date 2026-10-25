//go:build linux

// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package serviceroute

import (
	"errors"
	"fmt"
	"net"
	"reflect"
	"testing"

	"k8s.io/apimachinery/pkg/types"

	api "go.datum.net/galactic/api/network/v1alpha1"
	"go.datum.net/galactic/internal/plumbing/ebpf/serviceroutemap"
)

// spreadTestProgrammer returns a programmer over persisted fakes with a
// producer set map, its route and producer set tables, and the interfaces
// consumer0=10, producer-a=20, producer-b=21 and producer-c=22.
func spreadTestProgrammer() (*EBPFRouteProgrammer, *persistedPolicyTable, *persistedPolicyTable) {
	routes, sets := &persistedPolicyTable{}, &persistedPolicyTable{}
	programmer := testRouteProgrammer(&recordingTable{}, &recordingTable{}, &recordingTable{})
	programmer.tables = serviceroutemap.New(routes, &persistedPolicyTable{}, &persistedPolicyTable{},
		&persistedPolicyTable{},
		&recordingTable{identityTokens: map[uint32]uint64{10: 100, 20: 200, 21: 210, 22: 220}},
		&persistedPolicyTable{}, &persistedPolicyTable{}, &persistedPolicyTable{}).WithProducerSets(sets)
	programmer.mapIDs = mapSetIDs{1, 2, 3, 4, 5, 6, 7, 8, 9}
	programmer.mapIDsValid = true
	programmer.readMapIDsFn = func(string) (mapSetIDs, error) { return programmer.mapIDs, nil }
	programmer.targetIndexFn = func(name string) (uint32, error) {
		switch name {
		case testConsumerDeviceName:
			return 10, nil
		case "producer-a":
			return 20, nil
		case "producer-b":
			return 21, nil
		case "producer-c":
			return 22, nil
		default:
			return 0, fmt.Errorf("unknown interface %q", name)
		}
	}
	return programmer, routes, sets
}

func localSetIntent(producers ...ProducerTarget) RouteIntent {
	_, service, _ := net.ParseCIDR("fd00::53/128")
	return RouteIntent{
		Attachment:     types.NamespacedName{Namespace: eligibilityNamespace, Name: spreadConsumerName},
		Kind:           RouteIntentLocalSet,
		Service:        service,
		ConsumerDevice: testConsumerDeviceName,
		Ports:          []api.ServiceRouteProtocolPort{{Protocol: api.NetworkServiceProtocolUDP, Port: 53}},
		Producers:      producers,
	}
}

func producer(device string, draining bool) ProducerTarget {
	return ProducerTarget{Attachment: types.NamespacedName{Namespace: spreadProducerNamespace, Name: device},
		Device:   device,
		Draining: draining}
}

// onlySet returns the members and eligible member ifindexes of the one row in
// sets.
func onlySet(t *testing.T, sets *persistedPolicyTable) (members, eligible []uint32) {
	t.Helper()
	if len(sets.rows) != 1 {
		t.Fatalf("producer set rows = %d, want 1", len(sets.rows))
	}
	for _, row := range sets.rows {
		value := reflect.ValueOf(row)
		count := int(value.FieldByName("Count").Uint())
		for i := range count {
			members = append(members, uint32(value.FieldByName("Members").Index(i).FieldByName("Ifindex").Uint()))
		}
		for i := range int(value.FieldByName("EligibleCount").Uint()) {
			index := int(value.FieldByName("Eligible").Index(i).Uint())
			eligible = append(eligible, members[index])
		}
	}
	return members, eligible
}

func onlyRouteMode(t *testing.T, routes *persistedPolicyTable) uint64 {
	t.Helper()
	if len(routes.rows) != 1 {
		t.Fatalf("route rows = %d, want 1", len(routes.rows))
	}
	for _, row := range routes.rows {
		return reflect.ValueOf(row).FieldByName("Mode").Uint()
	}
	return 0
}

func TestApplyLocalSetWritesRouteAndProducerSet(t *testing.T) {
	programmer, routes, sets := spreadTestProgrammer()
	intent := localSetIntent(producer("producer-a", false), producer("producer-b", true))
	if err := programmer.Apply(intent); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if mode := onlyRouteMode(t, routes); mode != 3 {
		t.Fatalf("route mode = %d, want LocalSet (3)", mode)
	}
	members, eligible := onlySet(t, sets)
	if !reflect.DeepEqual(members, []uint32{20, 21}) || !reflect.DeepEqual(eligible, []uint32{20}) {
		t.Fatalf("set members=%v eligible=%v, want [20 21] and [20]", members, eligible)
	}
	if err := programmer.Finalize(); err != nil {
		t.Fatalf("Finalize: %v", err)
	}
	if len(routes.rows) != 1 || len(sets.rows) != 1 {
		t.Fatalf("finalize swept live state: routes=%d sets=%d", len(routes.rows), len(sets.rows))
	}
	if err := programmer.Remove(intent); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if len(routes.rows) != 0 || len(sets.rows) != 0 {
		t.Fatalf("remove left routes=%d sets=%d", len(routes.rows), len(sets.rows))
	}
}

// Replacing a LocalSet intent applies the new one before the old one is
// removed, so the route row stays throughout and the newer set wins.
func TestLocalSetReplacementKeepsRouteAndPrefersNewestSet(t *testing.T) {
	programmer, routes, sets := spreadTestProgrammer()
	old := localSetIntent(producer("producer-a", false), producer("producer-b", false))
	next := localSetIntent(producer("producer-a", false), producer("producer-b", true), producer("producer-c", false))
	if intentKey(old) == intentKey(next) {
		t.Fatal("intents with different producer sets share an identity")
	}
	if err := programmer.Apply(old); err != nil {
		t.Fatal(err)
	}
	if err := programmer.Apply(next); err != nil {
		t.Fatalf("Apply replacement alongside the old intent: %v", err)
	}
	if _, eligible := onlySet(t, sets); !reflect.DeepEqual(eligible, []uint32{20, 22}) {
		t.Fatalf("eligible after replacement = %v, want [20 22]", eligible)
	}
	if err := programmer.Remove(old); err != nil {
		t.Fatal(err)
	}
	if onlyRouteMode(t, routes) != 3 {
		t.Fatal("route row lost while replacing its producer set")
	}
	if members, eligible := onlySet(t, sets); !reflect.DeepEqual(members, []uint32{20, 21, 22}) ||
		!reflect.DeepEqual(eligible, []uint32{20, 22}) {
		t.Fatalf("set after removing old intent = %v/%v, want the replacement's", members, eligible)
	}

	// Undoing a replacement, the newer intent removed first, restores the
	// older set.
	if err := programmer.Apply(old); err != nil {
		t.Fatal(err)
	}
	if err := programmer.Remove(old); err != nil {
		t.Fatal(err)
	}
	if _, eligible := onlySet(t, sets); !reflect.DeepEqual(eligible, []uint32{20, 22}) {
		t.Fatalf("eligible after undoing a replacement = %v, want [20 22]", eligible)
	}
}

func TestLocalSetNeedsProducerSetMap(t *testing.T) {
	programmer, _, _ := spreadTestProgrammer()
	programmer.tables.WithProducerSets(nil)
	err := programmer.Apply(localSetIntent(producer("producer-a", false)))
	if !errors.Is(err, ErrProducerSetsUnavailable) {
		t.Fatalf("Apply without a producer set map: %v, want ErrProducerSetsUnavailable", err)
	}
	if err := programmer.Apply(localTestIntentFor(testConsumerDeviceName, "producer-a")); err != nil {
		t.Fatalf("Apply of a single-producer intent without a producer set map: %v", err)
	}
}

func localTestIntentFor(consumer, producer string) RouteIntent {
	intent := localTestIntent()
	intent.ConsumerDevice, intent.ServiceDevice = consumer, producer
	return intent
}

func TestFinalizeSweepsStaleProducerSets(t *testing.T) {
	programmer, _, sets := spreadTestProgrammer()
	stale := localSetIntent(producer("producer-a", false))
	stale.ConsumerDevice = testConsumerDeviceName
	if err := programmer.tables.RegisterProducerSet(99, net.ParseIP("fd00::99"), serviceroutemap.ProtocolUDP, 53,
		[]serviceroutemap.ProducerMember{{Ifindex: 20, Token: 200, Eligible: true}}); err != nil {
		t.Fatal(err)
	}
	if err := programmer.Apply(stale); err != nil {
		t.Fatal(err)
	}
	if len(sets.rows) != 2 {
		t.Fatalf("producer set rows = %d, want 2", len(sets.rows))
	}
	if err := programmer.Finalize(); err != nil {
		t.Fatal(err)
	}
	if members, _ := onlySet(t, sets); !reflect.DeepEqual(members, []uint32{20}) {
		t.Fatalf("set left after sweep = %v", members)
	}
}
