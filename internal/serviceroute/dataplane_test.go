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

	"github.com/cilium/ebpf"

	"go.datum.net/galactic/internal/plumbing/ebpf/serviceroutemap"
	"go.datum.net/galactic/internal/plumbing/ebpf/usidmap"
	api "go.datum.net/network/api/v1alpha1"
)

type recordingTable struct {
	puts, deletes  int
	putErr         error
	deleteErr      error
	iterateCount   int
	identityTokens map[uint32]uint64
	lastValue      any
}

const (
	testRemoteServiceAddress = "10.0.0.53"
	testConsumerDeviceName   = "consumer0"
	testProducerDeviceName   = "producer0"
)

func (t *recordingTable) Put(_ any, value any) error {
	t.puts++
	t.lastValue = value
	return t.putErr
}

func TestAccessMarkersAggregateDirectionsByKernelKey(t *testing.T) {
	access := &recordingTable{}
	programmer := testRouteProgrammer(&recordingTable{}, access, &recordingTable{})
	request := appliedEntry{access: &accessRef{ingressIfindex: 10, address: "10.0.0.53", attachmentToken: 100,
		markerDirections: serviceroutemap.MarkerRequest}}
	reply := appliedEntry{access: &accessRef{ingressIfindex: 10, address: "10.0.0.53", attachmentToken: 100,
		markerDirections: serviceroutemap.MarkerReply}}
	if err := programmer.acquire(request); err != nil {
		t.Fatal(err)
	}
	if err := programmer.acquire(reply); err != nil {
		t.Fatal(err)
	}
	if got := reflect.ValueOf(access.lastValue).FieldByName("MarkerDirections").Uint(); got != 3 {
		t.Fatalf("aggregated directions = %d, want request|reply", got)
	}
	if err := programmer.release(request); err != nil {
		t.Fatal(err)
	}
	if access.deletes != 0 {
		t.Fatal("shared marker deleted while reply owner remains")
	}
	if got := reflect.ValueOf(access.lastValue).FieldByName("MarkerDirections").Uint(); got != 2 {
		t.Fatalf("directions after request release = %d, want reply", got)
	}
	if err := programmer.release(reply); err != nil {
		t.Fatal(err)
	}
	if access.deletes != 1 {
		t.Fatalf("final marker deletes = %d, want 1", access.deletes)
	}
}

func (t *recordingTable) Lookup(key, value any) error {
	if t.identityTokens != nil {
		ifindex, ok := key.(uint32)
		out, valueOK := value.(*uint64)
		if ok && valueOK {
			token, found := t.identityTokens[ifindex]
			if found {
				*out = token
				return nil
			}
		}
	}
	return ebpf.ErrKeyNotExist
}

func (t *recordingTable) Delete(any) error {
	t.deletes++
	if t.deleteErr != nil {
		err := t.deleteErr
		t.deleteErr = nil
		return err
	}
	return nil
}

func (t *recordingTable) Iterate() usidmap.Iterator {
	return &recordingIterator{remaining: t.iterateCount}
}

type recordingIterator struct{ remaining int }

func (i *recordingIterator) Next(any, any) bool {
	if i.remaining == 0 {
		return false
	}
	i.remaining--
	return true
}
func (*recordingIterator) Err() error { return nil }

func testRouteProgrammer(routes, access, grants *recordingTable) *EBPFRouteProgrammer {
	identities := &recordingTable{identityTokens: map[uint32]uint64{10: 100, 11: 110, 20: 200, 42: 420, 101: 1010}}
	policyState := &recordingTable{}
	return &EBPFRouteProgrammer{
		tables: serviceroutemap.New(
			routes, access, &recordingTable{}, grants, identities, policyState, &recordingTable{},
		),
		routeRefs:        make(map[string]routeState),
		accessRefs:       make(map[accessKey]accessState),
		denyRefs:         make(map[denyKey]denyState),
		grantRefs:        make(map[grantRef]int),
		appliedRefs:      make(map[string][][]appliedEntry),
		desiredIntents:   make(map[string][]RouteIntent),
		pendingRollbacks: make(map[string][]appliedEntry),
	}
}

func localTestIntent() RouteIntent {
	_, service, _ := net.ParseCIDR("10.0.0.53/32")
	return RouteIntent{
		Kind:           RouteIntentLocal,
		Service:        service,
		ConsumerDevice: testConsumerDeviceName,
		ServiceDevice:  testProducerDeviceName,
		Ports: []api.ServiceRouteProtocolPort{{
			Protocol: api.NetworkRuleProtocolTCP,
			Port:     443,
		}},
	}
}

func TestRemoteConsumerEntriesAcquireAndRevokeRouteAndAccess(t *testing.T) {
	routes, access, grants := &recordingTable{}, &recordingTable{}, &recordingTable{}
	programmer := testRouteProgrammer(routes, access, grants)
	accessEntry := appliedEntry{access: &accessRef{
		ingressIfindex: 42, address: testRemoteServiceAddress, protocol: serviceroutemap.ProtocolTCP, port: 443,
	}}
	routeEntry := appliedEntry{route: &routeRef{
		ingressIfindex: 42, address: testRemoteServiceAddress, mode: RouteIntentRemoteConsumer,
		protocol: serviceroutemap.ProtocolTCP, port: 443, grantID: ServiceGrantID{1},
		targetSID: [16]byte{0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2},
	}}

	if err := programmer.acquire(accessEntry); err != nil {
		t.Fatalf("acquire access: %v", err)
	}
	if err := programmer.acquire(routeEntry); err != nil {
		t.Fatalf("acquire route: %v", err)
	}
	if routes.puts != 1 || access.puts != 1 || grants.puts != 0 {
		t.Fatalf("map puts routes/access/grants = %d/%d/%d, want 1/1/0", routes.puts, access.puts, grants.puts)
	}

	if err := programmer.release(routeEntry); err != nil {
		t.Fatalf("release route: %v", err)
	}
	if err := programmer.release(accessEntry); err != nil {
		t.Fatalf("release access: %v", err)
	}
	if routes.deletes != 1 || access.deletes != 1 || len(programmer.routeRefs) != 0 || len(programmer.accessRefs) != 0 {
		t.Fatalf("revocation incomplete: deletes=%d/%d refs=%d/%d",
			routes.deletes, access.deletes, len(programmer.routeRefs), len(programmer.accessRefs))
	}
}

func TestRemoteConsumerRollbackRevokesAcquiredAccess(t *testing.T) {
	routeFailure := errors.New("route map write failed")
	routes, access := &recordingTable{putErr: routeFailure}, &recordingTable{}
	programmer := testRouteProgrammer(routes, access, &recordingTable{})
	accessEntry := appliedEntry{access: &accessRef{
		ingressIfindex: 42, address: testRemoteServiceAddress, protocol: serviceroutemap.ProtocolUDP, port: 53,
	}}
	routeEntry := appliedEntry{route: &routeRef{
		ingressIfindex: 42, address: testRemoteServiceAddress, mode: RouteIntentRemoteConsumer,
		protocol: serviceroutemap.ProtocolUDP, port: 53,
		targetSID: [16]byte{0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2},
	}}

	if err := programmer.acquire(accessEntry); err != nil {
		t.Fatalf("acquire access: %v", err)
	}
	if err := programmer.acquire(routeEntry); !errors.Is(err, routeFailure) {
		t.Fatalf("acquire route error = %v, want %v", err, routeFailure)
	}
	if err := programmer.release(accessEntry); err != nil {
		t.Fatalf("rollback access: %v", err)
	}
	if access.deletes != 1 || len(programmer.accessRefs) != 0 || len(programmer.routeRefs) != 0 {
		t.Fatalf("rollback incomplete: access deletes=%d access refs=%d route refs=%d",
			access.deletes, len(programmer.accessRefs), len(programmer.routeRefs))
	}
}

func TestRemoteProducerGrantRefcountAndRevocationRetry(t *testing.T) {
	revokeFailure := errors.New("grant delete failed")
	grants := &recordingTable{deleteErr: revokeFailure}
	programmer := testRouteProgrammer(&recordingTable{}, &recordingTable{}, grants)
	grant := grantRef{
		producerIfindex: 101, address: "fd20::53", protocol: serviceroutemap.ProtocolTCP, port: 443,
		grantID: ServiceGrantID{9}, consumerSID: [16]byte{0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x42},
	}
	entry := appliedEntry{grant: &grant}

	if err := programmer.acquire(entry); err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	if err := programmer.acquire(entry); err != nil {
		t.Fatalf("second acquire: %v", err)
	}
	if grants.puts != 1 || programmer.grantRefs[grant] != 2 {
		t.Fatalf("grant acquisition puts/count = %d/%d, want 1/2", grants.puts, programmer.grantRefs[grant])
	}
	if err := programmer.release(entry); err != nil {
		t.Fatalf("first release: %v", err)
	}
	if grants.deletes != 0 || programmer.grantRefs[grant] != 1 {
		t.Fatalf("first release deletes/count = %d/%d, want 0/1", grants.deletes, programmer.grantRefs[grant])
	}
	if err := programmer.release(entry); !errors.Is(err, revokeFailure) {
		t.Fatalf("failed revocation error = %v, want %v", err, revokeFailure)
	}
	if programmer.grantRefs[grant] != 1 {
		t.Fatalf("failed revocation dropped grant refcount: %d", programmer.grantRefs[grant])
	}
	if err := programmer.release(entry); err != nil {
		t.Fatalf("retry revocation: %v", err)
	}
	if grants.deletes != 2 {
		t.Fatalf("grant delete attempts = %d, want 2", grants.deletes)
	}
	if _, ok := programmer.grantRefs[grant]; ok {
		t.Fatal("grant remains tracked after successful revocation retry")
	}
}

func TestIPv6BytesRejectsIPv4SID(t *testing.T) {
	if _, err := ipv6Bytes(net.ParseIP("192.0.2.1")); err == nil {
		t.Fatal("ipv6Bytes accepted an IPv4 SID")
	}
}

func TestInitializePreservesPinnedState(t *testing.T) {
	routes := &recordingTable{iterateCount: 1}
	access := &recordingTable{iterateCount: 1}
	reverse := &recordingTable{iterateCount: 1}
	grants := &recordingTable{iterateCount: 1}
	programmer := &EBPFRouteProgrammer{
		openMapSetFn: func(string) (*serviceroutemap.Tables, []*ebpf.Map, [7]ebpf.MapID, error) {
			return serviceroutemap.New(routes, access, reverse, grants,
					&recordingTable{identityTokens: map[uint32]uint64{}}, &recordingTable{}, &recordingTable{}), nil,
				[7]ebpf.MapID{1, 2, 3, 4, 5, 6}, nil
		},
	}

	if err := programmer.Initialize(); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	if routes.deletes+access.deletes+reverse.deletes+grants.deletes != 0 {
		t.Fatalf("Initialize deleted pinned state: routes/access/reverse/grants=%d/%d/%d/%d",
			routes.deletes, access.deletes, reverse.deletes, grants.deletes)
	}
}

func TestInitializeDoesNotDisableFinalizedPolicy(t *testing.T) {
	policyState := &recordingTable{}
	ids := [7]ebpf.MapID{1, 2, 3, 4, 5, 6}
	programmer := &EBPFRouteProgrammer{
		tables: serviceroutemap.New(
			&recordingTable{}, &recordingTable{}, &recordingTable{}, &recordingTable{},
			&recordingTable{identityTokens: map[uint32]uint64{}}, policyState, &recordingTable{},
		),
		mapIDs:           ids,
		mapIDsValid:      true,
		routeRefs:        make(map[string]routeState),
		accessRefs:       make(map[accessKey]accessState),
		denyRefs:         make(map[denyKey]denyState),
		grantRefs:        make(map[grantRef]int),
		appliedRefs:      make(map[string][][]appliedEntry),
		desiredIntents:   make(map[string][]RouteIntent),
		pendingRollbacks: make(map[string][]appliedEntry),
		readMapIDsFn:     func(string) ([7]ebpf.MapID, error) { return ids, nil },
	}
	if err := programmer.Initialize(); err != nil {
		t.Fatalf("first Initialize: %v", err)
	}
	if err := programmer.Finalize(); err != nil {
		t.Fatalf("Finalize: %v", err)
	}
	if err := programmer.Initialize(); err != nil {
		t.Fatalf("periodic Initialize: %v", err)
	}
	if policyState.puts != 2 {
		t.Fatalf("policy-state writes = %d, want disable+enable only", policyState.puts)
	}
}

func TestInitializeRepairsRecreatedInterface(t *testing.T) {
	routes, access, grants := &recordingTable{}, &recordingTable{}, &recordingTable{}
	programmer := testRouteProgrammer(routes, access, grants)
	programmer.mapIDs = [7]ebpf.MapID{1, 2, 3, 4, 5, 6}
	programmer.mapIDsValid = true
	programmer.readMapIDsFn = func(string) ([7]ebpf.MapID, error) { return programmer.mapIDs, nil }
	consumerIndex := uint32(10)
	programmer.targetIndexFn = func(name string) (uint32, error) {
		switch name {
		case testConsumerDeviceName:
			return consumerIndex, nil
		case testProducerDeviceName:
			return 20, nil
		default:
			return 0, fmt.Errorf("unknown interface %q", name)
		}
	}
	intent := localTestIntent()
	if err := programmer.Apply(intent); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	consumerIndex = 11
	if err := programmer.Initialize(); err != nil {
		t.Fatalf("repair Initialize: %v", err)
	}

	sets := programmer.appliedRefs[intentKey(intent)]
	if len(sets) != 1 || sets[0][0].access == nil || sets[0][0].access.ingressIfindex != 11 {
		t.Fatalf("repaired entries = %#v, want consumer ifindex 11", sets)
	}
	if routes.deletes != 0 || routes.puts != 2 {
		t.Fatalf("route deletes/puts = %d/%d, want 0/2 (fake iterator has no persisted rows)", routes.deletes, routes.puts)
	}
	if access.deletes != 0 || access.puts != 6 {
		t.Fatalf("access deletes/puts = %d/%d, want 0/6", access.deletes, access.puts)
	}
}

func TestInitializeRepairsSharedRefsAsCompleteGeneration(t *testing.T) {
	routes, access, grants := &recordingTable{}, &recordingTable{}, &recordingTable{}
	programmer := testRouteProgrammer(routes, access, grants)
	programmer.mapIDs = [7]ebpf.MapID{1, 2, 3, 4, 5, 6}
	programmer.mapIDsValid = true
	programmer.readMapIDsFn = func(string) ([7]ebpf.MapID, error) { return programmer.mapIDs, nil }
	consumerIndex := uint32(10)
	programmer.targetIndexFn = func(name string) (uint32, error) {
		switch name {
		case testConsumerDeviceName:
			return consumerIndex, nil
		case testProducerDeviceName:
			return 20, nil
		default:
			return 0, fmt.Errorf("unknown interface %q", name)
		}
	}
	intent := localTestIntent()
	if err := programmer.Apply(intent); err != nil {
		t.Fatalf("first Apply: %v", err)
	}
	if err := programmer.Apply(intent); err != nil {
		t.Fatalf("duplicate Apply: %v", err)
	}

	consumerIndex = 11
	if err := programmer.Initialize(); err != nil {
		t.Fatalf("repair Initialize: %v", err)
	}

	sets := programmer.appliedRefs[intentKey(intent)]
	if len(sets) != 2 {
		t.Fatalf("repaired applied sets = %d, want 2", len(sets))
	}
	if len(programmer.routeRefs) != 1 {
		t.Fatalf("repaired route keys = %d, want 1", len(programmer.routeRefs))
	}
	for _, state := range programmer.routeRefs {
		if state.count != 2 || state.ref.ingressIfindex != 11 {
			t.Fatalf("repaired shared route = %#v, want count 2 on ifindex 11", state)
		}
	}
	for key, state := range programmer.accessRefs {
		if key.ingressIfindex == 10 {
			t.Fatalf("stale consumer access key survived generation repair: %#v", key)
		}
		if key.ingressIfindex == 11 && accessStateCount(state) != 2 {
			t.Fatalf("shared consumer access refs = %d, want 2", accessStateCount(state))
		}
	}
}

func TestInitializeRetriesIncompleteGenerationRebuild(t *testing.T) {
	routes, access, grants := &recordingTable{}, &recordingTable{}, &recordingTable{}
	programmer := testRouteProgrammer(routes, access, grants)
	programmer.mapIDs = [7]ebpf.MapID{1, 2, 3, 4, 5, 6}
	programmer.mapIDsValid = true
	programmer.readMapIDsFn = func(string) ([7]ebpf.MapID, error) { return programmer.mapIDs, nil }
	consumerIndex := uint32(10)
	programmer.targetIndexFn = func(name string) (uint32, error) {
		if name == testConsumerDeviceName {
			return consumerIndex, nil
		}
		return 20, nil
	}
	intent := localTestIntent()
	if err := programmer.Apply(intent); err != nil {
		t.Fatal(err)
	}
	consumerIndex = 11
	routes.putErr = errors.New("transient rebuild failure")
	if err := programmer.Initialize(); err == nil {
		t.Fatal("Initialize succeeded despite injected rebuild failure")
	}
	if !programmer.generationIncomplete {
		t.Fatal("failed rebuild was not marked incomplete")
	}
	routes.putErr = nil
	if err := programmer.Initialize(); err != nil {
		t.Fatalf("retry Initialize: %v", err)
	}
	if programmer.generationIncomplete {
		t.Fatal("successful retry left generation incomplete")
	}
	if got := len(programmer.appliedRefs[intentKey(intent)]); got != 1 {
		t.Fatalf("rebuilt applied sets = %d, want 1", got)
	}
}

func TestRemoveRetryClearsSyncFailure(t *testing.T) {
	routes := &recordingTable{deleteErr: errors.New("transient delete failure")}
	programmer := testRouteProgrammer(routes, &recordingTable{}, &recordingTable{})
	programmer.mapIDs = [7]ebpf.MapID{1, 2, 3, 4, 5, 6}
	programmer.mapIDsValid = true
	programmer.readMapIDsFn = func(string) ([7]ebpf.MapID, error) { return programmer.mapIDs, nil }
	programmer.targetIndexFn = func(name string) (uint32, error) {
		if name == testConsumerDeviceName {
			return 10, nil
		}
		return 20, nil
	}
	intent := localTestIntent()
	if err := programmer.Apply(intent); err != nil {
		t.Fatal(err)
	}
	if err := programmer.Remove(intent); err == nil {
		t.Fatal("Remove succeeded despite injected delete failure")
	}
	if programmer.syncFailures != 1 {
		t.Fatalf("sync failures = %d, want 1", programmer.syncFailures)
	}
	if err := programmer.Remove(intent); err != nil {
		t.Fatalf("retry Remove: %v", err)
	}
	if programmer.syncFailures != 0 {
		t.Fatalf("sync failures after retry = %d, want 0", programmer.syncFailures)
	}
}

func TestMapReplacementClearsStaleMutationFailure(t *testing.T) {
	routes := &recordingTable{deleteErr: errors.New("transient delete failure")}
	programmer := testRouteProgrammer(routes, &recordingTable{}, &recordingTable{})
	oldIDs := [7]ebpf.MapID{1, 2, 3, 4, 5, 6, 7}
	newIDs := [7]ebpf.MapID{11, 12, 13, 14, 15, 16, 17}
	currentIDs := oldIDs
	programmer.mapIDs = oldIDs
	programmer.mapIDsValid = true
	programmer.readMapIDsFn = func(string) ([7]ebpf.MapID, error) { return currentIDs, nil }
	programmer.targetIndexFn = func(name string) (uint32, error) {
		if name == testConsumerDeviceName {
			return 10, nil
		}
		return 20, nil
	}
	intent := localTestIntent()
	if err := programmer.Apply(intent); err != nil {
		t.Fatal(err)
	}
	if err := programmer.Finalize(); err != nil {
		t.Fatal(err)
	}
	if err := programmer.Remove(intent); err == nil {
		t.Fatal("Remove succeeded despite injected delete failure")
	}
	if programmer.syncFailures != 1 {
		t.Fatalf("sync failures = %d, want 1", programmer.syncFailures)
	}

	newRoutes := &recordingTable{}
	newPolicyState := &recordingTable{}
	currentIDs = newIDs
	programmer.openMapSetFn = func(string) (*serviceroutemap.Tables, []*ebpf.Map, [7]ebpf.MapID, error) {
		return serviceroutemap.New(newRoutes, &recordingTable{}, &recordingTable{}, &recordingTable{},
			&recordingTable{identityTokens: map[uint32]uint64{10: 100, 20: 200}}, newPolicyState,
			&recordingTable{}), nil, newIDs, nil
	}
	if err := programmer.Initialize(); err != nil {
		t.Fatalf("Initialize after map replacement: %v", err)
	}
	if programmer.syncFailures != 0 || len(programmer.failedMutations) != 0 {
		t.Fatalf("stale mutation failures survived replacement: count=%d keys=%d",
			programmer.syncFailures, len(programmer.failedMutations))
	}
	if newRoutes.puts != 1 {
		t.Fatalf("rebuilt route puts = %d, want 1", newRoutes.puts)
	}
	if newPolicyState.puts != 1 {
		t.Fatalf("policy-state writes = %d, want finalized enable", newPolicyState.puts)
	}
}

func TestInitializeReopensAllMapsWhenGrantMapChanges(t *testing.T) {
	oldRoutes, oldAccess, oldGrants := &recordingTable{}, &recordingTable{}, &recordingTable{}
	programmer := testRouteProgrammer(oldRoutes, oldAccess, oldGrants)
	programmer.mapIDs = [7]ebpf.MapID{1, 2, 3, 4, 5, 6}
	programmer.mapIDsValid = true
	currentIDs := programmer.mapIDs
	programmer.readMapIDsFn = func(string) ([7]ebpf.MapID, error) { return currentIDs, nil }
	programmer.targetIndexFn = func(name string) (uint32, error) {
		if name == testConsumerDeviceName {
			return 10, nil
		}
		return 20, nil
	}
	intent := localTestIntent()
	if err := programmer.Apply(intent); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	newRoutes, newAccess, newGrants := &recordingTable{}, &recordingTable{}, &recordingTable{}
	openCalls := 0
	currentIDs[3] = 99
	programmer.openMapSetFn = func(string) (*serviceroutemap.Tables, []*ebpf.Map, [7]ebpf.MapID, error) {
		openCalls++
		return serviceroutemap.New(
			newRoutes, newAccess, &recordingTable{}, newGrants,
			&recordingTable{identityTokens: map[uint32]uint64{10: 100, 20: 200}},
			&recordingTable{}, &recordingTable{},
		), nil, currentIDs, nil
	}
	if err := programmer.Initialize(); err != nil {
		t.Fatalf("Initialize after grant map replacement: %v", err)
	}
	if openCalls != 1 {
		t.Fatalf("map-set open calls = %d, want 1", openCalls)
	}
	if newRoutes.puts != 1 || newAccess.puts != 3 {
		t.Fatalf("rebuilt route/access puts = %d/%d, want 1/3", newRoutes.puts, newAccess.puts)
	}
}

func TestEntriesIncludeConsumerAndProducerFragmentMarkers(t *testing.T) {
	programmer := testRouteProgrammer(&recordingTable{}, &recordingTable{}, &recordingTable{})
	programmer.targetIndexFn = func(name string) (uint32, error) {
		switch name {
		case testConsumerDeviceName:
			return 10, nil
		case testProducerDeviceName:
			return 20, nil
		default:
			return 0, fmt.Errorf("unknown interface %q", name)
		}
	}
	entries, err := programmer.entries(localTestIntent())
	if err != nil {
		t.Fatalf("entries: %v", err)
	}
	var markers []accessRef
	for _, entry := range entries {
		if entry.access != nil && entry.access.protocol == 0 && entry.access.port == 0 {
			markers = append(markers, *entry.access)
		}
	}
	if len(markers) != 2 || markers[0].ingressIfindex != 10 || markers[1].ingressIfindex != 20 {
		t.Fatalf("fragment markers = %#v, want consumer ifindex 10 and producer ifindex 20", markers)
	}

	remoteProducer := localTestIntent()
	remoteProducer.Kind = RouteIntentRemoteProducer
	remoteProducer.ConsumerDevice = ""
	remoteProducer.ConsumerSID = net.ParseIP("fd00::42")
	remoteEntries, err := programmer.entries(remoteProducer)
	if err != nil {
		t.Fatalf("remote producer entries: %v", err)
	}
	if len(remoteEntries) != 3 || remoteEntries[0].access == nil ||
		remoteEntries[0].access.ingressIfindex != 20 || remoteEntries[0].access.protocol != 0 ||
		remoteEntries[0].access.port != 0 || remoteEntries[1].deny == nil || remoteEntries[2].grant == nil {
		t.Fatalf("remote producer entries = %#v, want access marker, deny marker, then grant", remoteEntries)
	}
}
