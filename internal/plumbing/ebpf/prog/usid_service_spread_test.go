// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package prog

import (
	"errors"
	"math/bits"
	"net/netip"
	"testing"

	"github.com/cilium/ebpf"
)

// Producer set members of the LocalSet tests. Program.Test runs every packet
// on ifindex 1, so the consumer and the first producer share it and a reply
// can only be tested from that producer; the second producer is a fake
// interface whose reverse rows and flow pins show where requests went.
const (
	spreadConsumerToken  = uint64(1)
	spreadLocalProducer  = uint32(1)
	spreadRemoteProducer = uint32(50)
	spreadOtherToken     = uint64(50)
	spreadServicePort    = uint16(53)
	spreadClientPort     = uint16(40000)
)

var (
	spreadService  = netip.MustParseAddr("fd20:70::100")
	spreadConsumer = netip.MustParseAddr("fd20:70::2")
)

func spreadRouteKey(protocol uint8) UsidServiceRouteKey {
	return UsidServiceRouteKey{
		IngressIfindex: 1, Family: egressRouteFamilyINET6, Protocol: protocol,
		Port: bits.ReverseBytes16(spreadServicePort), Addr: spreadService.As16(),
	}
}

// setUpLocalSet installs a LocalSet route for protocol from the consumer on
// ifindex 1 to both producers, with eligible naming the members that take new
// flows.
func setUpLocalSet(t *testing.T, objs *UsidObjects, protocol uint8, eligible ...uint32) {
	t.Helper()
	setServiceIdentity(t, objs, spreadConsumerToken)
	if err := objs.AttachmentIdentityTable.Put(spreadRemoteProducer, spreadOtherToken); err != nil {
		t.Fatal(err)
	}
	if err := objs.ServiceRouteTable.Put(spreadRouteKey(protocol), UsidServiceRouteValue{
		Mode: 3, ConsumerToken: spreadConsumerToken, BackendAddr: spreadService.As16(),
	}); err != nil {
		t.Fatalf("populate LocalSet route: %v", err)
	}
	if err := objs.ServiceAccessTable.Put(UsidServiceAccessKey{
		IngressIfindex: 1, Family: egressRouteFamilyINET6, Protocol: protocol,
		Port: bits.ReverseBytes16(spreadServicePort), Addr: spreadService.As16(),
	}, UsidServiceAccessValue{AttachmentToken: spreadConsumerToken}); err != nil {
		t.Fatalf("populate service access: %v", err)
	}
	putProducerSet(t, objs, protocol, []uint32{spreadLocalProducer, spreadRemoteProducer}, eligible)
}

func putProducerSet(t *testing.T, objs *UsidObjects, protocol uint8, members, eligible []uint32) {
	t.Helper()
	tokens := map[uint32]uint64{spreadLocalProducer: spreadConsumerToken, spreadRemoteProducer: spreadOtherToken}
	var set UsidServiceProducerSetValue
	set.Count = uint32(len(members))
	for i, ifindex := range members {
		set.Members[i].Ifindex = ifindex
		set.Members[i].Token = tokens[ifindex]
		for _, e := range eligible {
			if e == ifindex {
				set.Eligible[set.EligibleCount] = uint8(i)
				set.EligibleCount++
			}
		}
	}
	if err := objs.ServiceProducerSetTable.Put(spreadRouteKey(protocol), set); err != nil {
		t.Fatalf("populate producer set: %v", err)
	}
}

func spreadPacket(t *testing.T, protocol uint8, src, dst netip.Addr, srcPort, dstPort uint16) []byte {
	t.Helper()
	pkt := buildPlainV6PacketWithL4Ports(t, src, dst, srcPort, dstPort)
	pkt[ethHeaderLen+6] = protocol
	return pkt
}

// reachedProducer reports whether a UDP request from consumer port
// spreadClientPort left a reverse row on producer.
func reachedProducer(t *testing.T, objs *UsidObjects, producer uint32) bool {
	t.Helper()
	var value UsidServiceReverseValue
	err := objs.ServiceReverseTable.Lookup(UsidServiceReverseKey{
		IngressIfindex: producer, Family: egressRouteFamilyINET6, Protocol: 17,
		SourcePort: bits.ReverseBytes16(spreadServicePort), DestPort: bits.ReverseBytes16(spreadClientPort),
		SourceAddr: spreadService.As16(), DestAddr: spreadConsumer.As16(),
	}, &value)
	if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatal(err)
	}
	return err == nil
}

func clearReverse(t *testing.T, objs *UsidObjects) {
	t.Helper()
	var key UsidServiceReverseKey
	var value UsidServiceReverseValue
	var keys []UsidServiceReverseKey
	iterator := objs.ServiceReverseTable.Iterate()
	for iterator.Next(&key, &value) {
		keys = append(keys, key)
	}
	for _, k := range keys {
		_ = objs.ServiceReverseTable.Delete(k)
	}
}

func sendRequest(t *testing.T, objs *UsidObjects, protocol uint8, srcPort uint16) {
	t.Helper()
	pkt := spreadPacket(t, protocol, spreadConsumer, spreadService, srcPort, spreadServicePort)
	if ret, _, err := objs.UsidServiceEgress.Test(pkt); err != nil || ret != tcActRedirect {
		t.Fatalf("request from port %d: verdict=%d err=%v, want TC_ACT_REDIRECT", srcPort, ret, err)
	}
}

// Requests of one UDP socket spread across every eligible producer.
func TestUsidServiceEgress_LocalSetSpreadsUDPRequests(t *testing.T) {
	requireRoot(t)
	objs := loadObjects(t)
	const udp = uint8(17)
	setUpLocalSet(t, objs, udp, spreadLocalProducer, spreadRemoteProducer)

	for range 64 {
		sendRequest(t, objs, udp, spreadClientPort)
	}
	if !reachedProducer(t, objs, spreadLocalProducer) ||
		!reachedProducer(t, objs, spreadRemoteProducer) {
		t.Fatal("64 requests from one UDP socket did not reach both producers")
	}

	// A draining producer gets no new request.
	putProducerSet(t, objs, udp, []uint32{spreadLocalProducer, spreadRemoteProducer}, []uint32{spreadRemoteProducer})
	clearReverse(t, objs)
	for range 63 {
		sendRequest(t, objs, udp, spreadClientPort)
	}
	if reachedProducer(t, objs, spreadLocalProducer) {
		t.Fatal("a draining producer received a new request")
	}
	if !reachedProducer(t, objs, spreadRemoteProducer) {
		t.Fatal("the eligible producer received no request")
	}
}

// A TCP connection stays with the producer that took its first packet, even
// once that producer drains; new connections avoid a draining producer; and
// a connection moves only when its producer leaves the set.
func TestUsidServiceEgress_LocalSetPinsTCPFlows(t *testing.T) {
	requireRoot(t)
	objs := loadObjects(t)
	const tcp = uint8(6)
	setUpLocalSet(t, objs, tcp, spreadLocalProducer, spreadRemoteProducer)

	pinned := func(srcPort uint16) uint32 {
		t.Helper()
		var pin UsidServiceFlowValue
		if err := objs.ServiceFlowTable.Lookup(UsidServiceReverseKey{
			IngressIfindex: 1, Family: egressRouteFamilyINET6, Protocol: tcp,
			SourcePort: bits.ReverseBytes16(srcPort), DestPort: bits.ReverseBytes16(spreadServicePort),
			SourceAddr: spreadConsumer.As16(), DestAddr: spreadService.As16(),
		}, &pin); err != nil {
			t.Fatalf("flow pin for port %d: %v", srcPort, err)
		}
		return pin.ProducerIfindex
	}

	// Find a connection on each producer.
	byProducer := map[uint32]uint16{}
	for port := uint16(41000); port < 41064 && len(byProducer) < 2; port++ {
		sendRequest(t, objs, tcp, port)
		byProducer[pinned(port)] = port
	}
	if len(byProducer) != 2 {
		t.Fatalf("64 TCP connections all went to one producer: %v", byProducer)
	}
	for port, producer := range map[uint16]uint32{
		byProducer[spreadLocalProducer]: spreadLocalProducer, byProducer[spreadRemoteProducer]: spreadRemoteProducer,
	} {
		for range 16 {
			sendRequest(t, objs, tcp, port)
			if got := pinned(port); got != producer {
				t.Fatalf("connection from port %d moved from producer %d to %d", port, producer, got)
			}
		}
	}

	// Drain the local producer: its connection stays, and its replies pass.
	putProducerSet(t, objs, tcp, []uint32{spreadLocalProducer, spreadRemoteProducer}, []uint32{spreadRemoteProducer})
	drained := byProducer[spreadLocalProducer]
	sendRequest(t, objs, tcp, drained)
	if got := pinned(drained); got != spreadLocalProducer {
		t.Fatalf("draining producer lost its connection to %d", got)
	}
	reply := spreadPacket(t, tcp, spreadService, spreadConsumer, spreadServicePort, drained)
	if ret, _, err := objs.UsidServiceEgress.Test(reply); err != nil || ret != tcActRedirect {
		t.Fatalf("reply from a draining producer: verdict=%d err=%v, want TC_ACT_REDIRECT", ret, err)
	}
	for port := uint16(42000); port < 42032; port++ {
		sendRequest(t, objs, tcp, port)
		if got := pinned(port); got != spreadRemoteProducer {
			t.Fatalf("new connection from port %d went to draining producer %d", port, got)
		}
	}

	// Remove the local producer: only its connection moves, and its replies
	// stop.
	putProducerSet(t, objs, tcp, []uint32{spreadRemoteProducer}, []uint32{spreadRemoteProducer})
	if ret, _, err := objs.UsidServiceEgress.Test(reply); err != nil || ret != tcActShot {
		t.Fatalf("reply from a removed producer: verdict=%d err=%v, want TC_ACT_SHOT", ret, err)
	}
	sendRequest(t, objs, tcp, drained)
	if got := pinned(drained); got != spreadRemoteProducer {
		t.Fatalf("connection of a removed producer went to %d, want %d", got, spreadRemoteProducer)
	}
	other := byProducer[spreadRemoteProducer]
	sendRequest(t, objs, tcp, other)
	if got := pinned(other); got != spreadRemoteProducer {
		t.Fatalf("connection of a remaining producer moved to %d", got)
	}
}

// A LocalSet route fails closed without a producer set, with no eligible
// producer, or when the chosen producer's interface was replaced.
func TestUsidServiceEgress_LocalSetFailsClosed(t *testing.T) {
	requireRoot(t)
	objs := loadObjects(t)
	const udp = uint8(17)
	setUpLocalSet(t, objs, udp, spreadRemoteProducer)
	pkt := spreadPacket(t, udp, spreadConsumer, spreadService, 43000, spreadServicePort)

	if err := objs.AttachmentIdentityTable.Put(spreadRemoteProducer, spreadOtherToken+1); err != nil {
		t.Fatal(err)
	}
	if ret, _, err := objs.UsidServiceEgress.Test(pkt); err != nil || ret != tcActShot {
		t.Fatalf("request to a replaced producer interface: verdict=%d err=%v, want TC_ACT_SHOT", ret, err)
	}
	if err := objs.AttachmentIdentityTable.Put(spreadRemoteProducer, spreadOtherToken); err != nil {
		t.Fatal(err)
	}

	// A TCP flow is never pinned to a member with a stale identity, so its
	// retry after the set is repaired can go elsewhere.
	const tcp = uint8(6)
	setUpLocalSet(t, objs, tcp, spreadRemoteProducer)
	if err := objs.AttachmentIdentityTable.Put(spreadRemoteProducer, spreadOtherToken+1); err != nil {
		t.Fatal(err)
	}
	syn := spreadPacket(t, tcp, spreadConsumer, spreadService, 43001, spreadServicePort)
	if ret, _, err := objs.UsidServiceEgress.Test(syn); err != nil || ret != tcActShot {
		t.Fatalf("TCP request to a replaced producer interface: verdict=%d err=%v, want TC_ACT_SHOT", ret, err)
	}
	var pin UsidServiceFlowValue
	if err := objs.ServiceFlowTable.Lookup(UsidServiceReverseKey{
		IngressIfindex: 1, Family: egressRouteFamilyINET6, Protocol: tcp,
		SourcePort: bits.ReverseBytes16(43001), DestPort: bits.ReverseBytes16(spreadServicePort),
		SourceAddr: spreadConsumer.As16(), DestAddr: spreadService.As16(),
	}, &pin); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("flow pin to a replaced producer interface: %+v err=%v, want none", pin, err)
	}
	if err := objs.AttachmentIdentityTable.Put(spreadRemoteProducer, spreadOtherToken); err != nil {
		t.Fatal(err)
	}
	putProducerSet(t, objs, udp, []uint32{spreadLocalProducer, spreadRemoteProducer}, nil)
	if ret, _, err := objs.UsidServiceEgress.Test(pkt); err != nil || ret != tcActShot {
		t.Fatalf("request with no eligible producer: verdict=%d err=%v, want TC_ACT_SHOT", ret, err)
	}
	if err := objs.ServiceProducerSetTable.Delete(spreadRouteKey(udp)); err != nil {
		t.Fatal(err)
	}
	if ret, _, err := objs.UsidServiceEgress.Test(pkt); err != nil || ret != tcActShot {
		t.Fatalf("request with no producer set: verdict=%d err=%v, want TC_ACT_SHOT", ret, err)
	}
}

// A TCP connection whose flow pin is lost keeps its producer while that
// producer stays in the set, and a producer joining takes only the pin-less
// connections it gains.
func TestUsidServiceEgress_LocalSetKeepsTCPFlowsWithoutPins(t *testing.T) {
	requireRoot(t)
	objs := loadObjects(t)
	const (
		tcp          = uint8(6)
		joinedMember = uint32(51)
		joinedToken  = uint64(51)
		firstPort    = uint16(44000)
		connections  = 64
	)
	setUpLocalSet(t, objs, tcp, spreadLocalProducer, spreadRemoteProducer)
	pinKey := func(port uint16) UsidServiceReverseKey {
		return UsidServiceReverseKey{
			IngressIfindex: 1, Family: egressRouteFamilyINET6, Protocol: tcp,
			SourcePort: bits.ReverseBytes16(port), DestPort: bits.ReverseBytes16(spreadServicePort),
			SourceAddr: spreadConsumer.As16(), DestAddr: spreadService.As16(),
		}
	}
	pinned := func(port uint16) uint32 {
		t.Helper()
		var pin UsidServiceFlowValue
		if err := objs.ServiceFlowTable.Lookup(pinKey(port), &pin); err != nil {
			t.Fatalf("flow pin for port %d: %v", port, err)
		}
		return pin.ProducerIfindex
	}
	dropPins := func() {
		t.Helper()
		for port := firstPort; port < firstPort+connections; port++ {
			if err := objs.ServiceFlowTable.Delete(pinKey(port)); err != nil {
				t.Fatalf("evict pin for port %d: %v", port, err)
			}
		}
	}
	// A third member joins the set, eligible for new flows.
	join := func() {
		t.Helper()
		if err := objs.AttachmentIdentityTable.Put(joinedMember, joinedToken); err != nil {
			t.Fatal(err)
		}
		var set UsidServiceProducerSetValue
		set.Count, set.EligibleCount = 3, 3
		for i, member := range []struct {
			ifindex uint32
			token   uint64
		}{{spreadLocalProducer, spreadConsumerToken}, {spreadRemoteProducer, spreadOtherToken}, {joinedMember, joinedToken}} {
			set.Members[i].Ifindex, set.Members[i].Token = member.ifindex, member.token
			set.Eligible[i] = uint8(i)
		}
		if err := objs.ServiceProducerSetTable.Put(spreadRouteKey(tcp), set); err != nil {
			t.Fatalf("populate producer set: %v", err)
		}
	}

	before := map[uint16]uint32{}
	for port := firstPort; port < firstPort+connections; port++ {
		sendRequest(t, objs, tcp, port)
		before[port] = pinned(port)
	}

	// The pins are evicted, but each connection's reverse row still names its
	// producer.
	join()
	dropPins()
	for port, producer := range before {
		sendRequest(t, objs, tcp, port)
		if got := pinned(port); got != producer {
			t.Fatalf("connection from port %d lost its pin and moved from producer %d to %d", port, producer, got)
		}
	}

	// With no flow state left at all, a connection is placed by its hash: it
	// stays where it was or moves to the producer that joined.
	setUpLocalSet(t, objs, tcp, spreadLocalProducer, spreadRemoteProducer)
	dropPins()
	clearReverse(t, objs)
	for port := firstPort; port < firstPort+connections; port++ {
		sendRequest(t, objs, tcp, port)
		before[port] = pinned(port)
	}
	join()
	dropPins()
	clearReverse(t, objs)
	gained := 0
	for port, producer := range before {
		sendRequest(t, objs, tcp, port)
		switch got := pinned(port); got {
		case producer:
		case joinedMember:
			gained++
		default:
			t.Fatalf("connection from port %d moved from producer %d to %d, not to the one that joined",
				port, producer, got)
		}
	}
	if gained == 0 {
		t.Fatalf("the producer that joined gained none of %d connections", connections)
	}

	// With no flow state, the producer that joined leaving moves only its
	// own connections.
	for port := firstPort; port < firstPort+connections; port++ {
		before[port] = pinned(port)
	}
	setUpLocalSet(t, objs, tcp, spreadLocalProducer, spreadRemoteProducer)
	dropPins()
	clearReverse(t, objs)
	for port, producer := range before {
		sendRequest(t, objs, tcp, port)
		if got := pinned(port); producer != joinedMember && got != producer {
			t.Fatalf("connection from port %d moved from producer %d to %d when another left", port, producer, got)
		}
	}
}

func spreadFlowKey(port uint16) UsidServiceReverseKey {
	return UsidServiceReverseKey{
		IngressIfindex: 1, Family: egressRouteFamilyINET6, Protocol: 6,
		SourcePort: bits.ReverseBytes16(port), DestPort: bits.ReverseBytes16(spreadServicePort),
		SourceAddr: spreadConsumer.As16(), DestAddr: spreadService.As16(),
	}
}

// spreadPinned returns the producer the TCP flow from port is pinned to, or 0
// when it has no pin.
func spreadPinned(t *testing.T, objs *UsidObjects, port uint16) uint32 {
	t.Helper()
	var pin UsidServiceFlowValue
	err := objs.ServiceFlowTable.Lookup(spreadFlowKey(port), &pin)
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		return 0
	}
	if err != nil {
		t.Fatal(err)
	}
	return pin.ProducerIfindex
}

// Without its pin, a TCP connection keeps a draining producer through its
// reverse row, but an opening SYN on the same tuple, or a producer whose
// interface was replaced, does not.
func TestUsidServiceEgress_LocalSetReverseRowFallback(t *testing.T) {
	requireRoot(t)
	objs := loadObjects(t)
	const tcp = uint8(6)
	setUpLocalSet(t, objs, tcp, spreadLocalProducer, spreadRemoteProducer)
	port := uint16(0)
	for p := uint16(45000); p < 45064; p++ {
		sendRequest(t, objs, tcp, p)
		if spreadPinned(t, objs, p) == spreadRemoteProducer {
			port = p
			break
		}
	}
	if port == 0 {
		t.Fatal("64 TCP connections all went to producer 1")
	}
	members := []uint32{spreadLocalProducer, spreadRemoteProducer}
	putProducerSet(t, objs, tcp, members, []uint32{spreadLocalProducer})
	evict := func() {
		t.Helper()
		if err := objs.ServiceFlowTable.Delete(spreadFlowKey(port)); err != nil {
			t.Fatal(err)
		}
	}

	evict()
	sendRequest(t, objs, tcp, port)
	if got := spreadPinned(t, objs, port); got != spreadRemoteProducer {
		t.Fatalf("connection lost its pin and left draining producer %d for %d", spreadRemoteProducer, got)
	}

	evict()
	syn := spreadPacket(t, tcp, spreadConsumer, spreadService, port, spreadServicePort)
	syn[ethHeaderLen+ip6HeaderLen+13] = 0x02
	if ret, _, err := objs.UsidServiceEgress.Test(syn); err != nil || ret != tcActRedirect {
		t.Fatalf("SYN on a reused tuple: verdict=%d err=%v, want TC_ACT_REDIRECT", ret, err)
	}
	if got := spreadPinned(t, objs, port); got != spreadLocalProducer {
		t.Fatalf("SYN on a reused tuple went to %d, want eligible producer %d", got, spreadLocalProducer)
	}

	// Put the flow back on the producer, drain it, then replace its interface.
	evict()
	clearReverse(t, objs)
	putProducerSet(t, objs, tcp, members, []uint32{spreadRemoteProducer})
	sendRequest(t, objs, tcp, port)
	if got := spreadPinned(t, objs, port); got != spreadRemoteProducer {
		t.Fatalf("connection pinned to %d, want %d", got, spreadRemoteProducer)
	}
	putProducerSet(t, objs, tcp, members, []uint32{spreadLocalProducer})
	evict()
	if err := objs.AttachmentIdentityTable.Put(spreadRemoteProducer, spreadOtherToken+1); err != nil {
		t.Fatal(err)
	}
	sendRequest(t, objs, tcp, port)
	if got := spreadPinned(t, objs, port); got != spreadLocalProducer {
		t.Fatalf("connection of a replaced producer interface went to %d, want %d", got, spreadLocalProducer)
	}
}
