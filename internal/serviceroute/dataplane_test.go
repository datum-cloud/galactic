//go:build linux

// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package serviceroute

import (
	"errors"
	"net"
	"testing"

	"github.com/cilium/ebpf"

	"go.datum.net/galactic/internal/plumbing/ebpf/serviceroutemap"
	"go.datum.net/galactic/internal/plumbing/ebpf/usidmap"
)

type recordingTable struct {
	puts, deletes int
	putErr        error
	deleteErr     error
}

const testRemoteServiceAddress = "10.0.0.53"

func (t *recordingTable) Put(any, any) error {
	t.puts++
	return t.putErr
}

func (*recordingTable) Lookup(any, any) error { return ebpf.ErrKeyNotExist }

func (t *recordingTable) Delete(any) error {
	t.deletes++
	if t.deleteErr != nil {
		err := t.deleteErr
		t.deleteErr = nil
		return err
	}
	return nil
}

func (*recordingTable) Iterate() usidmap.Iterator { return emptyRecordingIterator{} }

type emptyRecordingIterator struct{}

func (emptyRecordingIterator) Next(any, any) bool { return false }
func (emptyRecordingIterator) Err() error         { return nil }

func testRouteProgrammer(routes, access, grants *recordingTable) *EBPFRouteProgrammer {
	return &EBPFRouteProgrammer{
		tables:           serviceroutemap.New(routes, access, &recordingTable{}, grants),
		routeRefs:        make(map[string]routeState),
		accessRefs:       make(map[accessRef]int),
		grantRefs:        make(map[grantRef]int),
		appliedRefs:      make(map[string][][]appliedEntry),
		desiredRefs:      make(map[string][][]appliedEntry),
		pendingRollbacks: make(map[string][]appliedEntry),
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
