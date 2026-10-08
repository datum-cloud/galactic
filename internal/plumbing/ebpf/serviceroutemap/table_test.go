// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package serviceroutemap

import (
	"bytes"
	"errors"
	"math/bits"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/cilium/ebpf"

	"go.datum.net/galactic/internal/plumbing/ebpf/usidmap"
)

type fakeTable struct {
	putKey, putValue any
	deleted          any
}

func (f *fakeTable) Put(key, value any) error {
	f.putKey, f.putValue = key, value
	return nil
}

func (*fakeTable) Lookup(any, any) error { return ebpf.ErrKeyNotExist }

func (f *fakeTable) Delete(key any) error {
	f.deleted = key
	return ebpf.ErrKeyNotExist
}

func (*fakeTable) Iterate() usidmap.Iterator {
	return emptyIterator{}
}

type emptyIterator struct{}

func (emptyIterator) Next(any, any) bool { return false }
func (emptyIterator) Err() error         { return nil }

type memoryTable struct {
	entries    map[any]any
	iterateErr error
	deleteErr  error
	deletes    int
	name       string
	deleteLog  *[]string
}

func (t *memoryTable) Put(key, value any) error {
	if t.entries == nil {
		t.entries = make(map[any]any)
	}
	t.entries[key] = value
	return nil
}

func (t *memoryTable) Lookup(key, value any) error {
	stored, ok := t.entries[key]
	if !ok {
		return ebpf.ErrKeyNotExist
	}
	reflect.ValueOf(value).Elem().Set(reflect.ValueOf(stored))
	return nil
}

func (t *memoryTable) Delete(key any) error {
	t.deletes++
	if t.deleteLog != nil {
		*t.deleteLog = append(*t.deleteLog, t.name)
	}
	if t.deleteErr != nil {
		err := t.deleteErr
		t.deleteErr = nil
		return err
	}
	if _, ok := t.entries[key]; !ok {
		return ebpf.ErrKeyNotExist
	}
	delete(t.entries, key)
	return nil
}

func (t *memoryTable) Iterate() usidmap.Iterator {
	keys := make([]any, 0, len(t.entries))
	values := make([]any, 0, len(t.entries))
	for key, value := range t.entries {
		keys = append(keys, key)
		values = append(values, value)
	}
	return &memoryIterator{keys: keys, values: values, err: t.iterateErr}
}

type memoryIterator struct {
	keys, values []any
	index        int
	err          error
}

func (i *memoryIterator) Next(key, value any) bool {
	if i.index == len(i.keys) {
		return false
	}
	reflect.ValueOf(key).Elem().Set(reflect.ValueOf(i.keys[i.index]))
	reflect.ValueOf(value).Elem().Set(reflect.ValueOf(i.values[i.index]))
	i.index++
	return true
}

func (i *memoryIterator) Err() error { return i.err }

func TestTables_RegisterIPv6Route(t *testing.T) {
	routes, access := &fakeTable{}, &fakeTable{}
	reverse := &fakeTable{}
	tables := New(routes, access, reverse)
	address := net.ParseIP("fd20:0:19::53")
	if err := tables.RegisterRoute(42, address, address, ProtocolUDP, 53, 101, 420, 1010); err != nil {
		t.Fatal(err)
	}
	key, ok := routes.putKey.(serviceRouteKey)
	if !ok {
		t.Fatalf("route key type = %T", routes.putKey)
	}
	if key.IngressIfindex != 42 || key.Family != familyIPv6 || key.Protocol != ProtocolUDP ||
		key.Port != bits.ReverseBytes16(53) || !bytes.Equal(key.Address[:], address.To16()) {
		t.Fatalf("route key = %+v", key)
	}
	value, ok := routes.putValue.(serviceRouteValue)
	if !ok || value.TargetIfindex != 101 || value.Mode != routeModeLocal ||
		value.ConsumerToken != 420 || value.ProducerToken != 1010 {
		t.Fatalf("route value = %+v", routes.putValue)
	}
}

func TestTables_RegisterRemoteRoute(t *testing.T) {
	routes := &fakeTable{}
	tables := New(routes, &fakeTable{}, &fakeTable{}, &fakeTable{})
	grant := [16]byte{1, 2, 3}
	if err := tables.RegisterRemoteRoute(42, net.ParseIP("10.0.0.53"), net.ParseIP("10.0.0.53"), grant,
		ProtocolTCP, 443, net.ParseIP("fd00::1234"), 420); err != nil {
		t.Fatal(err)
	}
	value, ok := routes.putValue.(serviceRouteValue)
	if !ok || value.Mode != routeModeRemote || value.GrantID != grant || value.ConsumerToken != 420 ||
		!bytes.Equal(value.TargetSID[:], net.ParseIP("fd00::1234").To16()) {
		t.Fatalf("remote route value = %+v", routes.putValue)
	}
}

func TestTables_RegisterRemoteGrant(t *testing.T) {
	grants := &fakeTable{}
	tables := New(&fakeTable{}, &fakeTable{}, &fakeTable{}, grants)
	grantID := [16]byte{9, 8, 7}
	consumerSID := net.ParseIP("fd00::42")
	if err := tables.RegisterRemoteGrant(101, net.ParseIP("fd20::53"), net.ParseIP("fd20::53"), ProtocolTCP, 443,
		grantID, consumerSID, 1010); err != nil {
		t.Fatal(err)
	}
	key, ok := grants.putKey.(serviceRemoteGrantKey)
	if !ok || key.ProducerIfindex != 101 || key.Protocol != ProtocolTCP || key.Port != bits.ReverseBytes16(443) ||
		key.GrantID != grantID || key.Family != familyIPv6 || !bytes.Equal(key.Address[:], net.ParseIP("fd20::53").To16()) {
		t.Fatalf("remote grant key = %+v", grants.putKey)
	}
	value, ok := grants.putValue.(serviceRemoteGrantValue)
	if !ok || !bytes.Equal(value.ConsumerSID[:], consumerSID.To16()) || value.ProducerToken != 1010 {
		t.Fatalf("remote grant value = %+v", grants.putValue)
	}
	if err := tables.UnregisterRemoteGrant(101, net.ParseIP("fd20::53"), ProtocolTCP, 443, grantID); err != nil {
		t.Fatal(err)
	}
	deleted, ok := grants.deleted.(serviceRemoteGrantKey)
	if !ok || deleted != key {
		t.Fatalf("deleted remote grant key = %+v, want %+v", grants.deleted, key)
	}
}

func TestTables_RegisterAccessUsesNetworkPortOrder(t *testing.T) {
	routes, access := &fakeTable{}, &fakeTable{}
	tables := New(routes, access, &fakeTable{})
	address := net.ParseIP("fd20::53")
	if err := tables.RegisterAccess(42, address, ProtocolUDP, 53, 420, 0); err != nil {
		t.Fatal(err)
	}
	key, ok := access.putKey.(serviceAccessKey)
	if !ok {
		t.Fatalf("access key type = %T", access.putKey)
	}
	if key.IngressIfindex != 42 || key.Family != familyIPv6 || key.Protocol != ProtocolUDP || key.Port != 0x3500 {
		t.Fatalf("access key = %+v", key)
	}
	if !bytes.Equal(key.Address[:], address.To16()) {
		t.Fatalf("address = %x, want %x", key.Address, address.To16())
	}
	value, ok := access.putValue.(serviceAccessValue)
	if !ok || value.AttachmentToken != 420 || value.MarkerDirections != 0 {
		t.Fatalf("access value = %+v", access.putValue)
	}
}

func TestTables_RegisterServiceAddressMarker(t *testing.T) {
	access := &fakeTable{}
	tables := New(&fakeTable{}, access, &fakeTable{})
	address := net.ParseIP("192.0.2.53")
	if err := tables.RegisterAccess(101, address, 0, 0, 1010, MarkerReply); err != nil {
		t.Fatal(err)
	}
	key, ok := access.putKey.(serviceAccessKey)
	if !ok || key.IngressIfindex != 101 || key.Family != familyIPv4 || key.Protocol != 0 || key.Port != 0 ||
		!bytes.Equal(key.Address[:4], address.To4()) {
		t.Fatalf("service address marker = %+v", access.putKey)
	}
	value, ok := access.putValue.(serviceAccessValue)
	if !ok || value.AttachmentToken != 1010 || value.MarkerDirections != MarkerReply {
		t.Fatalf("service marker value = %+v", access.putValue)
	}
}

func TestTables_UnregisterAbsentIsIdempotent(t *testing.T) {
	routes, access := &fakeTable{}, &fakeTable{}
	reverse := &fakeTable{}
	tables := New(routes, access, reverse)
	if err := tables.UnregisterRoute(7, net.ParseIP("192.0.2.53"), ProtocolUDP, 53); err != nil {
		t.Fatal(err)
	}
	if err := tables.UnregisterAccess(7, net.ParseIP("192.0.2.53"), ProtocolTCP, 853); err != nil {
		t.Fatal(err)
	}
	if routes.deleted == nil || access.deleted == nil {
		t.Fatal("expected both map keys to be deleted")
	}
}

func TestRouteKeyRejectsInvalidAddress(t *testing.T) {
	_, err := routeKey(1, nil, ProtocolTCP, 443)
	if err == nil {
		t.Fatal("routeKey(nil) did not return an error")
	}
}

func TestTablesSweepPolicyRemovesOnlyStalePolicyState(t *testing.T) {
	routes, access := &memoryTable{entries: make(map[any]any)}, &memoryTable{entries: make(map[any]any)}
	reverse, grants := &memoryTable{entries: make(map[any]any)}, &memoryTable{entries: make(map[any]any)}
	desiredRoute, _ := routeKey(10, net.ParseIP("10.0.0.53"), ProtocolTCP, 443)
	staleRoute, _ := routeKey(11, net.ParseIP("10.0.0.54"), ProtocolUDP, 53)
	desiredAccess, _ := accessKey(10, net.ParseIP("10.0.0.53"), ProtocolTCP, 443)
	staleAccess, _ := accessKey(11, net.ParseIP("10.0.0.54"), ProtocolUDP, 53)
	desiredGrant, _ := remoteGrantKey(20, net.ParseIP("10.0.0.53"), ProtocolTCP, 443, [16]byte{1})
	staleGrant, _ := remoteGrantKey(21, net.ParseIP("10.0.0.54"), ProtocolUDP, 53, [16]byte{2})
	reverseKey := serviceReverseKey{IngressIfindex: 10, Protocol: ProtocolTCP}
	routes.entries[desiredRoute], routes.entries[staleRoute] = serviceRouteValue{}, serviceRouteValue{}
	access.entries[desiredAccess], access.entries[staleAccess] = serviceAccessValue{}, serviceAccessValue{}
	grants.entries[desiredGrant], grants.entries[staleGrant] = serviceRemoteGrantValue{}, serviceRemoteGrantValue{}
	reverse.entries[reverseKey] = serviceReverseValue{}
	tables := New(routes, access, reverse, grants)

	err := tables.SweepPolicy(PolicySnapshot{
		Routes: []RouteIdentity{{IngressIfindex: 10, Address: net.ParseIP("10.0.0.53"), Protocol: ProtocolTCP, Port: 443}},
		Access: []AccessIdentity{{IngressIfindex: 10, Address: net.ParseIP("10.0.0.53"), Protocol: ProtocolTCP, Port: 443}},
		RemoteGrants: []RemoteGrantIdentity{{
			ProducerIfindex: 20, Address: net.ParseIP("10.0.0.53"), Protocol: ProtocolTCP, Port: 443,
			GrantID: [16]byte{1},
		}},
	})
	if err != nil {
		t.Fatalf("SweepPolicy: %v", err)
	}
	if _, ok := routes.entries[desiredRoute]; !ok {
		t.Fatal("desired route was removed")
	}
	if _, ok := routes.entries[staleRoute]; ok {
		t.Fatal("stale route survived")
	}
	if _, ok := access.entries[desiredAccess]; !ok {
		t.Fatal("desired access entry was removed")
	}
	if _, ok := access.entries[staleAccess]; ok {
		t.Fatal("stale access entry survived")
	}
	if _, ok := grants.entries[desiredGrant]; !ok {
		t.Fatal("desired remote grant was removed")
	}
	if _, ok := grants.entries[staleGrant]; ok {
		t.Fatal("stale remote grant survived")
	}
	if _, ok := reverse.entries[reverseKey]; !ok || reverse.deletes != 0 {
		t.Fatal("reverse state was not preserved")
	}
}

func TestTablesSweepPolicyIterationFailureDoesNotDeleteAnything(t *testing.T) {
	iterationFailure := errors.New("access iteration failed")
	route, _ := routeKey(10, net.ParseIP("10.0.0.53"), ProtocolTCP, 443)
	accessKey, _ := accessKey(10, net.ParseIP("10.0.0.53"), ProtocolTCP, 443)
	routes := &memoryTable{entries: map[any]any{route: serviceRouteValue{}}}
	access := &memoryTable{entries: map[any]any{accessKey: serviceAccessValue{}}, iterateErr: iterationFailure}
	reverse := &memoryTable{entries: make(map[any]any)}
	grants := &memoryTable{entries: make(map[any]any)}

	if err := New(routes, access, reverse, grants).SweepPolicy(PolicySnapshot{}); !errors.Is(err, iterationFailure) {
		t.Fatalf("SweepPolicy error = %v, want %v", err, iterationFailure)
	}
	if routes.deletes+access.deletes+grants.deletes != 0 {
		t.Fatalf("sweep deleted entries before completing iteration: route/access/grant=%d/%d/%d",
			routes.deletes, access.deletes, grants.deletes)
	}
}

func TestTablesSweepPolicyDeleteFailureIsRetryable(t *testing.T) {
	deleteFailure := errors.New("grant deletion failed")
	staleRoute, _ := routeKey(10, net.ParseIP("10.0.0.53"), ProtocolTCP, 443)
	staleAccess, _ := accessKey(10, net.ParseIP("10.0.0.53"), ProtocolTCP, 443)
	staleGrant, _ := remoteGrantKey(20, net.ParseIP("10.0.0.53"), ProtocolTCP, 443, [16]byte{1})
	var deleteLog []string
	routes := &memoryTable{
		entries: map[any]any{staleRoute: serviceRouteValue{}}, name: "route", deleteLog: &deleteLog,
	}
	access := &memoryTable{
		entries: map[any]any{staleAccess: serviceAccessValue{}}, name: "access", deleteLog: &deleteLog,
	}
	reverseKey := serviceReverseKey{IngressIfindex: 10, Protocol: ProtocolTCP}
	reverse := &memoryTable{entries: map[any]any{reverseKey: serviceReverseValue{}}}
	grants := &memoryTable{
		entries: map[any]any{staleGrant: serviceRemoteGrantValue{}}, deleteErr: deleteFailure,
		name: "grant", deleteLog: &deleteLog,
	}
	tables := New(routes, access, reverse, grants)

	if err := tables.SweepPolicy(PolicySnapshot{}); !errors.Is(err, deleteFailure) {
		t.Fatalf("first SweepPolicy error = %v, want %v", err, deleteFailure)
	}
	if _, ok := grants.entries[staleGrant]; !ok {
		t.Fatal("failed grant deletion unexpectedly removed entry")
	}
	if len(routes.entries) != 0 || len(access.entries) != 0 {
		t.Fatalf("independent stale deletions did not continue: routes=%d access=%d",
			len(routes.entries), len(access.entries))
	}
	if got, want := deleteLog, []string{"grant", "access", "route"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("deletion order = %v, want %v", got, want)
	}
	if err := tables.SweepPolicy(PolicySnapshot{}); err != nil {
		t.Fatalf("retry SweepPolicy: %v", err)
	}
	if len(routes.entries) != 0 || len(access.entries) != 0 || len(grants.entries) != 0 {
		t.Fatalf("stale state survived retry: routes=%d access=%d grants=%d",
			len(routes.entries), len(access.entries), len(grants.entries))
	}
	if _, ok := reverse.entries[reverseKey]; !ok || reverse.deletes != 0 {
		t.Fatal("reverse state was not preserved across retry")
	}
}

func TestAuthorizationLeasePinnedReplayAndRenewal(t *testing.T) {
	wall := time.Unix(1800000000, 0)
	monotonic := uint64(10000000000)
	until := wall.Add(10 * time.Second)
	tests := []struct {
		name   string
		remote bool
	}{{"LocalRoute", false}, {"RemoteGrant", true}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			routes, grants := &memoryTable{}, &memoryTable{}
			tables := New(routes, &memoryTable{}, &memoryTable{}, grants)
			clockWall, clockMono := wall, monotonic
			tables.leaseClockFn = func() (time.Time, uint64, error) { return clockWall, clockMono, nil }
			address := net.ParseIP("fd20:70::53")
			register := func(expiry time.Time) error {
				if tt.remote {
					return tables.RegisterRemoteGrant(
						1, address, address, ProtocolTCP, 53, [16]byte{1}, net.ParseIP("fd00:1::1"), 1, expiry,
					)
				}
				return tables.RegisterRoute(1, address, address, ProtocolTCP, 53, 2, 1, 2, expiry)
			}
			deadline := func() uint64 {
				if tt.remote {
					for _, v := range grants.entries {
						return v.(serviceRemoteGrantValue).AuthorizationDeadlineNS
					}
				}
				for _, v := range routes.entries {
					return v.(serviceRouteValue).AuthorizationDeadlineNS
				}
				return 0
			}
			if err := register(until); err != nil {
				t.Fatal(err)
			}
			want := monotonic + uint64(10*time.Second)
			if deadline() != want {
				t.Fatalf("deadline=%d, want %d", deadline(), want)
			}
			// A restarted controller with a backward wall clock must not renew the lease.
			clockWall, clockMono = wall.Add(-time.Second), monotonic+uint64(time.Second)
			if err := register(until); err != nil {
				t.Fatal(err)
			}
			if deadline() != want {
				t.Fatalf("replay extended deadline to %d, want %d", deadline(), want)
			}
			// Expiry remains enforced by the pinned monotonic deadline, even under clock skew.
			clockMono = want
			if err := register(until); err == nil {
				t.Fatal("accepted expired pinned authorization")
			}
			if err := register(until.Add(10 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if deadline() <= want {
				t.Fatal("explicit renewal did not advance deadline")
			}
			if err := register(clockWall.Add(-time.Second)); err == nil {
				t.Fatal("accepted expired absolute authorization")
			}
		})
	}
}
