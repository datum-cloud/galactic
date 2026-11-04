// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package serviceroutemap

import (
	"net"
	"testing"
)

var (
	targetService = net.ParseIP("fd70:100::53")
	targetSID     = net.ParseIP("fd00:123:456:20::")
	targetGrant   = [16]byte{4}
)

func newTargetTables() (*Tables, *memoryTable, *memoryTable) {
	grants := &memoryTable{entries: make(map[any]any)}
	targets := &memoryTable{entries: make(map[any]any)}
	tables := New(&memoryTable{}, &memoryTable{}, &memoryTable{}, grants).WithRemoteTargets(targets)
	return tables, grants, targets
}

func targetFor(t *testing.T, targets *memoryTable) (serviceRemoteTargetValue, bool) {
	t.Helper()
	key, err := remoteGrantKey(0, targetService, ProtocolUDP, 53, targetGrant)
	if err != nil {
		t.Fatal(err)
	}
	value, ok := targets.entries[key].(serviceRemoteTargetValue)
	return value, ok
}

// A grant names its producer interface in the remote target map, under the
// grant's key without the interface, and removing it removes the target.
func TestRemoteGrantNamesItsProducer(t *testing.T) {
	tables, _, targets := newTargetTables()
	if err := tables.RegisterRemoteGrant(12, targetService, targetService, ProtocolUDP, 53, targetGrant,
		targetSID, 7); err != nil {
		t.Fatalf("RegisterRemoteGrant: %v", err)
	}
	if got, ok := targetFor(t, targets); !ok || got.ProducerIfindex != 12 {
		t.Fatalf("target = %+v, %t; want producer ifindex 12", got, ok)
	}
	if err := tables.UnregisterRemoteGrant(12, targetService, ProtocolUDP, 53, targetGrant); err != nil {
		t.Fatalf("UnregisterRemoteGrant: %v", err)
	}
	if _, ok := targetFor(t, targets); ok {
		t.Fatal("target survived its grant")
	}
}

// Removing the grant of a producer's previous interface leaves the target a
// grant for its current interface wrote.
func TestRemoteGrantRemovalKeepsReplacementTarget(t *testing.T) {
	tables, _, targets := newTargetTables()
	for _, ifindex := range []uint32{12, 13} {
		if err := tables.RegisterRemoteGrant(ifindex, targetService, targetService, ProtocolUDP, 53, targetGrant,
			targetSID, uint64(ifindex)); err != nil {
			t.Fatalf("RegisterRemoteGrant(%d): %v", ifindex, err)
		}
	}
	if err := tables.UnregisterRemoteGrant(12, targetService, ProtocolUDP, 53, targetGrant); err != nil {
		t.Fatalf("UnregisterRemoteGrant: %v", err)
	}
	if got, ok := targetFor(t, targets); !ok || got.ProducerIfindex != 13 {
		t.Fatalf("target = %+v, %t; want the replacement's ifindex 13", got, ok)
	}
}

// A sweep keeps a target only while a desired grant names its interface.
func TestSweepPolicyRemovesStaleTargets(t *testing.T) {
	tables, grants, targets := newTargetTables()
	if err := tables.RegisterRemoteGrant(12, targetService, targetService, ProtocolUDP, 53, targetGrant,
		targetSID, 7); err != nil {
		t.Fatalf("RegisterRemoteGrant: %v", err)
	}
	other := [16]byte{5}
	if err := tables.RegisterRemoteGrant(14, targetService, targetService, ProtocolUDP, 53, other,
		targetSID, 7); err != nil {
		t.Fatalf("RegisterRemoteGrant: %v", err)
	}
	if err := tables.SweepPolicy(PolicySnapshot{RemoteGrants: []RemoteGrantIdentity{{
		ProducerIfindex: 12, Address: targetService, Protocol: ProtocolUDP, Port: 53, GrantID: targetGrant,
	}}}); err != nil {
		t.Fatalf("SweepPolicy: %v", err)
	}
	if got, ok := targetFor(t, targets); !ok || got.ProducerIfindex != 12 {
		t.Fatalf("desired target = %+v, %t; want kept", got, ok)
	}
	if len(targets.entries) != 1 || len(grants.entries) != 1 {
		t.Fatalf("after sweep: %d targets, %d grants; want 1 each", len(targets.entries), len(grants.entries))
	}

	// A target naming an undesired interface moves to the desired grant's.
	if err := tables.SweepPolicy(PolicySnapshot{RemoteGrants: []RemoteGrantIdentity{{
		ProducerIfindex: 13, Address: targetService, Protocol: ProtocolUDP, Port: 53, GrantID: targetGrant,
	}}}); err != nil {
		t.Fatalf("SweepPolicy: %v", err)
	}
	if got, ok := targetFor(t, targets); !ok || got.ProducerIfindex != 13 {
		t.Fatalf("target = %+v, %t; want moved to the desired interface 13", got, ok)
	}

	// A desired grant whose target is missing gets one back, and a target
	// with no desired grant goes.
	delete(targets.entries, remoteTargetKey(mustGrantKey(t, 13, targetGrant)))
	if err := tables.SweepPolicy(PolicySnapshot{RemoteGrants: []RemoteGrantIdentity{{
		ProducerIfindex: 13, Address: targetService, Protocol: ProtocolUDP, Port: 53, GrantID: targetGrant,
	}}}); err != nil {
		t.Fatalf("SweepPolicy: %v", err)
	}
	if got, ok := targetFor(t, targets); !ok || got.ProducerIfindex != 13 {
		t.Fatalf("target = %+v, %t; want restored to 13", got, ok)
	}
	if err := tables.SweepPolicy(PolicySnapshot{}); err != nil {
		t.Fatalf("SweepPolicy: %v", err)
	}
	if len(targets.entries) != 0 {
		t.Fatalf("%d targets survived an empty snapshot", len(targets.entries))
	}
}

func mustGrantKey(t *testing.T, ifindex uint32, grant [16]byte) serviceRemoteGrantKey {
	t.Helper()
	key, err := remoteGrantKey(ifindex, targetService, ProtocolUDP, 53, grant)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// SetRemoteTarget points a grant's target at an interface.
func TestSetRemoteTarget(t *testing.T) {
	tables, _, targets := newTargetTables()
	if err := tables.SetRemoteTarget(9, targetService, ProtocolUDP, 53, targetGrant); err != nil {
		t.Fatalf("SetRemoteTarget: %v", err)
	}
	if got, ok := targetFor(t, targets); !ok || got.ProducerIfindex != 9 {
		t.Fatalf("target = %+v, %t; want 9", got, ok)
	}
	if err := New(&memoryTable{}, &memoryTable{}, &memoryTable{}).SetRemoteTarget(
		9, targetService, ProtocolUDP, 53, targetGrant); err != nil {
		t.Fatalf("SetRemoteTarget without the map: %v", err)
	}
}

// A datapath without the map leaves grants working as before.
func TestRemoteGrantWithoutTargetMap(t *testing.T) {
	grants := &memoryTable{entries: make(map[any]any)}
	tables := New(&memoryTable{}, &memoryTable{}, &memoryTable{}, grants)
	if tables.RemoteTargetsAvailable() {
		t.Fatal("RemoteTargetsAvailable = true without the map")
	}
	if err := tables.RegisterRemoteGrant(12, targetService, targetService, ProtocolUDP, 53, targetGrant,
		targetSID, 7); err != nil {
		t.Fatalf("RegisterRemoteGrant: %v", err)
	}
	if err := tables.UnregisterRemoteGrant(12, targetService, ProtocolUDP, 53, targetGrant); err != nil {
		t.Fatalf("UnregisterRemoteGrant: %v", err)
	}
	if err := tables.Clear(); err != nil {
		t.Fatalf("Clear: %v", err)
	}
}
