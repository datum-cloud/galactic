//go:build linux

// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package serviceroute

import (
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/vishvananda/netlink"

	"go.datum.net/galactic/internal/plumbing/ebpf/serviceroutemap"
)

// replacementFixture is a Spread programmer whose producer interfaces can
// disappear and come back under a new ifindex, as when a producer pod is
// replaced and its interface is recreated under the same name.
type replacementFixture struct {
	programmer          *EBPFRouteProgrammer
	routes, access, set *persistedPolicyTable
	links               map[string]uint32
}

func newReplacementFixture() *replacementFixture {
	f := &replacementFixture{
		routes: &persistedPolicyTable{}, access: &persistedPolicyTable{}, set: &persistedPolicyTable{},
		links: map[string]uint32{testConsumerDeviceName: 10, "producer-a": 20, "producer-b": 21},
	}
	p := testRouteProgrammer(&recordingTable{}, &recordingTable{}, &recordingTable{})
	p.tables = serviceroutemap.New(f.routes, f.access, &persistedPolicyTable{}, &persistedPolicyTable{},
		&recordingTable{identityTokens: map[uint32]uint64{10: 100, 20: 200, 21: 210, 23: 230}},
		&persistedPolicyTable{}, &persistedPolicyTable{}, &persistedPolicyTable{}).WithProducerSets(f.set)
	p.mapIDs = mapSetIDs{1, 2, 3, 4, 5, 6, 7, 8, 9}
	p.mapIDsValid = true
	p.readMapIDsFn = func(string) (mapSetIDs, error) { return p.mapIDs, nil }
	p.targetIndexFn = func(name string) (uint32, error) {
		if index, ok := f.links[name]; ok {
			return index, nil
		}
		if name == "producer-a" || name == "producer-b" {
			return 0, netlink.LinkNotFoundError{}
		}
		return 0, fmt.Errorf("unknown interface %q", name)
	}
	f.programmer = p
	return f
}

// requireServing fails the test, from every later mutation of the route,
// access and set tables, unless the consumer can still reach producer-b: its
// route, its request markers and a set with producer-b eligible.
func (f *replacementFixture) requireServing(t *testing.T) {
	t.Helper()
	check := func() {
		if len(f.routes.rows) != 1 {
			t.Errorf("route rows = %d mid-repair, want the consumer's route", len(f.routes.rows))
		}
		consumerAccess := 0
		for key := range f.access.rows {
			if reflect.ValueOf(key).FieldByName("IngressIfindex").Uint() == 10 {
				consumerAccess++
			}
		}
		if consumerAccess != 2 {
			t.Errorf("consumer access rows = %d mid-repair, want the marker and the port", consumerAccess)
		}
		if len(f.set.rows) != 1 {
			t.Errorf("producer set rows = %d mid-repair, want 1", len(f.set.rows))
			return
		}
		if _, eligible := onlySet(t, f.set); !containsIfindex(eligible, 21) {
			t.Errorf("eligible = %v mid-repair, want producer-b (21)", eligible)
		}
	}
	for _, table := range []*persistedPolicyTable{f.routes, f.access, f.set} {
		table.afterMutation = check
	}
}

func containsIfindex(indexes []uint32, want uint32) bool {
	for _, index := range indexes {
		if index == want {
			return true
		}
	}
	return false
}

// repair runs the attachment repair the next programmer call starts with.
func (f *replacementFixture) repair(t *testing.T, intent RouteIntent) {
	t.Helper()
	if err := f.programmer.Cleanup(intent); err != nil {
		t.Fatalf("repair: %v", err)
	}
	if f.programmer.generationIncomplete || f.programmer.syncFailures != 0 {
		t.Fatal("repair fell back to a full rebuild")
	}
}

func TestReplacingDrainingProducerInterfaceKeepsServing(t *testing.T) {
	f := newReplacementFixture()
	intent := localSetIntent(producer("producer-a", true), producer("producer-b", false))
	if err := f.programmer.Apply(intent); err != nil {
		t.Fatal(err)
	}
	f.requireServing(t)

	// The old pod stops: its interface is gone.
	delete(f.links, "producer-a")
	f.repair(t, intent)
	if members, eligible := onlySet(t, f.set); !reflect.DeepEqual(members, []uint32{21}) ||
		!reflect.DeepEqual(eligible, []uint32{21}) {
		t.Fatalf("set without producer-a = %v/%v, want [21]/[21]", members, eligible)
	}

	// The replacement pod recreates it under the same name.
	f.links["producer-a"] = 23
	f.repair(t, intent)
	if members, eligible := onlySet(t, f.set); !reflect.DeepEqual(members, []uint32{23, 21}) ||
		!reflect.DeepEqual(eligible, []uint32{21}) {
		t.Fatalf("set with recreated producer-a = %v/%v, want [23 21]/[21]", members, eligible)
	}
	for key := range f.access.rows {
		if reflect.ValueOf(key).FieldByName("IngressIfindex").Uint() == 20 {
			t.Fatal("reply marker of the removed interface remains")
		}
	}
}

func TestRecreatingProducerInterfaceInPlaceKeepsServing(t *testing.T) {
	f := newReplacementFixture()
	intent := localSetIntent(producer("producer-a", true), producer("producer-b", false))
	if err := f.programmer.Apply(intent); err != nil {
		t.Fatal(err)
	}
	f.requireServing(t)
	// The interface comes back before any repair sees it missing.
	f.links["producer-a"] = 23
	f.repair(t, intent)
	if members, _ := onlySet(t, f.set); !reflect.DeepEqual(members, []uint32{23, 21}) {
		t.Fatalf("set members = %v, want [23 21]", members)
	}
	f.routes.afterMutation, f.access.afterMutation, f.set.afterMutation = nil, nil, nil
	if err := f.programmer.Remove(intent); err != nil {
		t.Fatal(err)
	}
	if len(f.routes.rows)+len(f.access.rows)+len(f.set.rows) != 0 {
		t.Fatalf("rows after Remove: routes=%d access=%d sets=%d, want none",
			len(f.routes.rows), len(f.access.rows), len(f.set.rows))
	}
}

func TestApplyLocalSetWithMissingProducerInterface(t *testing.T) {
	f := newReplacementFixture()
	delete(f.links, "producer-a")
	// A draining producer that is gone leaves the others as they are.
	if err := f.programmer.Apply(localSetIntent(producer("producer-a", true), producer("producer-b", false))); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if members, eligible := onlySet(t, f.set); !reflect.DeepEqual(members, []uint32{21}) ||
		!reflect.DeepEqual(eligible, []uint32{21}) {
		t.Fatalf("set = %v/%v, want [21]/[21]", members, eligible)
	}

	// When the only eligible producer is gone, the draining ones serve.
	f = newReplacementFixture()
	delete(f.links, "producer-a")
	if err := f.programmer.Apply(localSetIntent(producer("producer-a", false), producer("producer-b", true))); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if _, eligible := onlySet(t, f.set); !reflect.DeepEqual(eligible, []uint32{21}) {
		t.Fatalf("eligible = %v, want the draining producer-b", eligible)
	}
}

func TestLocalSetWithNoProducerInterfaceIsWithdrawn(t *testing.T) {
	f := newReplacementFixture()
	intent := localSetIntent(producer("producer-a", false), producer("producer-b", false))
	if err := f.programmer.Apply(intent); err != nil {
		t.Fatal(err)
	}
	delete(f.links, "producer-a")
	delete(f.links, "producer-b")
	if err := f.programmer.Apply(localSetIntent(producer("producer-a", true), producer("producer-b", false))); !errors.As(err,
		&netlink.LinkNotFoundError{}) {
		t.Fatalf("Apply with no producer interface = %v, want a missing link error", err)
	}
	f.repair(t, intent)
	if len(f.routes.rows) != 0 || len(f.set.rows) != 0 {
		t.Fatalf("routes=%d sets=%d with every producer gone, want the route withdrawn",
			len(f.routes.rows), len(f.set.rows))
	}
	if len(f.programmer.desiredIntents[intentKey(intent)]) != 1 {
		t.Fatal("lost the intent to restore when a producer returns")
	}
}

func TestReplacingServingProducerInterfaceKeepsServing(t *testing.T) {
	f := newReplacementFixture()
	intent := localSetIntent(producer("producer-a", false), producer("producer-b", false))
	if err := f.programmer.Apply(intent); err != nil {
		t.Fatal(err)
	}
	f.requireServing(t)
	delete(f.links, "producer-a")
	f.repair(t, intent)
	if members, eligible := onlySet(t, f.set); !reflect.DeepEqual(members, []uint32{21}) ||
		!reflect.DeepEqual(eligible, []uint32{21}) {
		t.Fatalf("set without producer-a = %v/%v, want [21]/[21]", members, eligible)
	}
	// The new interface exists before the CNI records its identity.
	f.links["producer-a"] = 24
	f.repair(t, intent)
	if members, _ := onlySet(t, f.set); !reflect.DeepEqual(members, []uint32{21}) {
		t.Fatalf("set with an interface that has no identity = %v, want [21]", members)
	}
	f.links["producer-a"] = 23
	f.repair(t, intent)
	if members, eligible := onlySet(t, f.set); !reflect.DeepEqual(members, []uint32{23, 21}) ||
		!reflect.DeepEqual(eligible, []uint32{23, 21}) {
		t.Fatalf("set with recreated producer-a = %v/%v, want [23 21]/[23 21]", members, eligible)
	}
}
