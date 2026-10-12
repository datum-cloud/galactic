// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package prog

import (
	"math/bits"
	"net/netip"
	"testing"

	"github.com/cilium/ebpf"

	"go.datum.net/galactic/internal/plumbing/ebpf/uformat"
)

// putVRFTraffic creates key's zeroed vrf_traffic_counters row, as userspace
// does when it registers the vrf_table row.
func putVRFTraffic(t *testing.T, objs *UsidObjects, key uint64) {
	t.Helper()
	n, err := ebpf.PossibleCPU()
	if err != nil {
		t.Fatalf("PossibleCPU: %v", err)
	}
	if err := objs.VrfTrafficCounters.Put(key, make([]UsidVrfTrafficValue, n)); err != nil {
		t.Fatalf("populate vrf_traffic_counters: %v", err)
	}
}

// vrfTraffic returns key's vrf_traffic_counters row summed across CPUs.
func vrfTraffic(t *testing.T, objs *UsidObjects, key uint64) UsidVrfTrafficValue {
	t.Helper()
	var perCPU []UsidVrfTrafficValue
	if err := objs.VrfTrafficCounters.Lookup(key, &perCPU); err != nil {
		t.Fatalf("look up vrf_traffic_counters: %v", err)
	}
	var sum UsidVrfTrafficValue
	for _, v := range perCPU {
		sum.Ingress.Packets += v.Ingress.Packets
		sum.Ingress.Bytes += v.Ingress.Bytes
		sum.Ingress.DroppedPackets += v.Ingress.DroppedPackets
		sum.Egress.Packets += v.Egress.Packets
		sum.Egress.Bytes += v.Egress.Bytes
		sum.Egress.DroppedPackets += v.Egress.DroppedPackets
	}
	return sum
}

func assertVRFTraffic(t *testing.T, objs *UsidObjects, key uint64, want UsidVrfTrafficValue, label string) {
	t.Helper()
	if got := vrfTraffic(t, objs, key); got != want {
		t.Errorf("%s: vrf_traffic_counters = %+v, want %+v", label, got, want)
	}
}

func direction(packets, bytes, drops uint64) UsidVrfDirectionCounter {
	return UsidVrfDirectionCounter{Packets: packets, Bytes: bytes, DroppedPackets: drops}
}

func vrfKeyOf(t *testing.T, block uint64, argument uint16) uint64 {
	t.Helper()
	key, err := uformat.NewVRFKey(block, argument)
	if err != nil {
		t.Fatalf("NewVRFKey: %v", err)
	}
	return uint64(key)
}

// redirectLabInnerLen is the tenant packet redirectLab.send builds toward an
// IPv4 destination: a 20-byte header and a 64-byte payload.
const redirectLabInnerLen = 20 + 64

// A decapsulated packet counts once as inbound, at its tenant length, for
// both a veth and a tap attachment.
func TestUsidIngress_VRFTrafficCountsDelivery(t *testing.T) {
	lab := newRedirectLab(t)
	lab.registerTap(t)
	lab.registerVeth(t)
	key := baseUSID.vrfKey()
	putVRFTraffic(t, lab.objs, key)

	lab.assertVethDelivers(t, "veth", true)
	assertVRFTraffic(t, lab.objs, key,
		UsidVrfTrafficValue{Ingress: direction(1, redirectLabInnerLen, 0)}, "after one veth delivery")

	lab.assertTapDelivers(t, "tap")
	assertVRFTraffic(t, lab.objs, key,
		UsidVrfTrafficValue{Ingress: direction(2, 2*redirectLabInnerLen, 0)}, "after a tap delivery")
}

// A packet dropped after its VRF was resolved counts as an inbound drop, not
// as forwarded.
func TestUsidIngress_VRFTrafficCountsClaimedDrop(t *testing.T) {
	requireRoot(t)
	objs := loadObjects(t)

	usid := testUSID{block: baseUSID.block, nodeID: baseUSID.nodeID, function: uformat.FunctionEndDT46, argument: 0x125}
	if err := objs.LocatorTable.Put(usid.locatorKey(t), UsidLocatorValue{Generation: 1}); err != nil {
		t.Fatalf("populate locator_table: %v", err)
	}
	if err := objs.FunctionTable.Put(usid.functionKey(t), UsidFunctionValue{Behavior: 1}); err != nil {
		t.Fatalf("populate function_table: %v", err)
	}
	if err := objs.VrfTable.Put(usid.vrfKey(), UsidVrfValue{VrfTableId: 0x2C2C2C}); err != nil {
		t.Fatalf("populate vrf_table: %v", err)
	}
	putVRFTraffic(t, objs, usid.vrfKey())

	pkt := buildPacketWithInner(t, usid.addr(t), netip.MustParseAddr("2001:db8::1"), innerUnknownVersion)
	if ret, _, err := objs.UsidIngress.Test(pkt); err != nil || ret != tcActShot {
		t.Fatalf("verdict = %d, err = %v; want TC_ACT_SHOT", ret, err)
	}
	assertVRFTraffic(t, objs, usid.vrfKey(), UsidVrfTrafficValue{Ingress: direction(0, 0, 1)}, "after a claimed drop")
}

// An unregistered row counts nothing and does not change the verdict.
func TestUsidIngress_VRFTrafficMissingRowCountsNothing(t *testing.T) {
	requireRoot(t)
	objs := loadObjects(t)

	usid := testUSID{block: baseUSID.block, nodeID: baseUSID.nodeID, function: uformat.FunctionEndDT46, argument: 0x125}
	if err := objs.LocatorTable.Put(usid.locatorKey(t), UsidLocatorValue{Generation: 1}); err != nil {
		t.Fatalf("populate locator_table: %v", err)
	}
	if err := objs.FunctionTable.Put(usid.functionKey(t), UsidFunctionValue{Behavior: 1}); err != nil {
		t.Fatalf("populate function_table: %v", err)
	}
	if err := objs.VrfTable.Put(usid.vrfKey(), UsidVrfValue{VrfTableId: 0x2C2C2C}); err != nil {
		t.Fatalf("populate vrf_table: %v", err)
	}

	pkt := buildPacketWithInner(t, usid.addr(t), netip.MustParseAddr("2001:db8::1"), innerUnknownVersion)
	if ret, _, err := objs.UsidIngress.Test(pkt); err != nil || ret != tcActShot {
		t.Fatalf("verdict = %d, err = %v; want TC_ACT_SHOT", ret, err)
	}
	var perCPU []UsidVrfTrafficValue
	if err := objs.VrfTrafficCounters.Lookup(usid.vrfKey(), &perCPU); err == nil {
		t.Error("the datapath created a vrf_traffic_counters row; only userspace may")
	}
}

// An encapsulated packet counts once as outbound, at its tenant length, not
// the encapsulated length.
func TestUsidEgress_VRFTrafficCountsEncapsulation(t *testing.T) {
	objs := egressClampFixture(t)
	key := vrfKeyOf(t, 0x123456, 0x210)
	putVRFTraffic(t, objs, key)

	runEgressExpect(t, objs, v6Packet(mssPodV6, mssRemoteV6, ipProtoUDP, 200), tcActRedirect)
	assertVRFTraffic(t, objs, key, UsidVrfTrafficValue{Egress: direction(1, 200, 0)}, "after an IPv6 packet")

	runEgressExpect(t, objs, v4Packet(ipProtoUDP, nil, true, 120), tcActRedirect)
	assertVRFTraffic(t, objs, key, UsidVrfTrafficValue{Egress: direction(2, 320, 0)}, "after an IPv4 packet")
}

// A packet the PMTU check drops counts as an outbound drop.
func TestUsidEgress_VRFTrafficCountsClaimedDrop(t *testing.T) {
	objs := pmtuFixture(t)
	key := vrfKeyOf(t, 0x123456, 0x210)
	putVRFTraffic(t, objs, key)

	runEgressExpect(t, objs, v4Packet(ipProtoUDP, nil, false, 1500), tcActShot)
	assertVRFTraffic(t, objs, key, UsidVrfTrafficValue{Egress: direction(0, 0, 1)}, "after a claimed drop")
}

// Traffic between two attachments on one node never reaches usid_ingress.
// The sender's usid_egress hands it to the kernel through the receiver's local
// pass-through entry, and both attachments share the VPC's VRF row, so it
// counts once in each direction there. Traffic to the sender's own gateway is
// for the host, not another attachment, and counts in neither.
func TestUsidEgress_VRFTrafficSameNodeCountsOncePerDirection(t *testing.T) {
	const (
		block    = 0xABCDEF
		argument = 0x100
		tableID  = 7
	)
	peer6 := netip.MustParseAddr("fd20:70::2")
	peer4 := netip.MustParseAddr("172.21.1.6")

	for _, tt := range []struct {
		name    string
		pkt     []byte
		counted bool
	}{
		{name: "IPv6 peer", pkt: v6Packet(mssPodV6, peer6, ipProtoUDP, 100), counted: true},
		{name: "IPv4 peer", pkt: withEth(0x0800, ip4TCP(mssPodV4, peer4, nil, 0, l4Datagram(ipProtoUDP, 72))), counted: true},
		{name: "IPv6 own gateway", pkt: v6Packet(mssPodV6, pmtuGW6, ipProtoUDP, 100)},
		{name: "IPv4 own gateway", pkt: withEth(0x0800, ip4TCP(mssPodV4, pmtuGW4, nil, 0, l4Datagram(ipProtoUDP, 72)))},
	} {
		t.Run(tt.name, func(t *testing.T) {
			requireRoot(t)
			objs := loadObjects(t)
			setUpEgressRouteAttachment(t, objs, block, argument, tableID)
			setUpNodeSIDBase(t, objs, netip.MustParseAddr("2001:db8:ff01:1:e000::"), argument)
			if err := objs.TenantGwTable.Put(uint32(1), UsidTenantGwValue{Gw6: pmtuGW6.As16(), Gw4: pmtuGW4.As4()}); err != nil {
				t.Fatalf("populate tenant_gw_table: %v", err)
			}
			for _, k := range []UsidEgressRouteKey{
				egressRouteKey(tableID, egressRouteFamilyINET6, peer6, 128),
				egressRouteKey(tableID, egressRouteFamilyINET6, pmtuGW6, 128),
				egressRouteKey(tableID, egressRouteFamilyINET4, peer4, 32),
				egressRouteKey(tableID, egressRouteFamilyINET4, pmtuGW4, 32),
			} {
				if err := objs.EgressRouteTable.Put(k, UsidEgressRouteValue{}); err != nil {
					t.Fatalf("populate pass-through route: %v", err)
				}
			}
			key := vrfKeyOf(t, block, argument)
			putVRFTraffic(t, objs, key)

			if ret, _, err := objs.UsidEgress.Test(tt.pkt); err != nil || ret != tcActUnspec {
				t.Fatalf("verdict = %d, err = %v; want TC_ACT_UNSPEC", ret, err)
			}
			var want UsidVrfTrafficValue
			if tt.counted {
				l3 := uint64(len(tt.pkt) - ethHeaderLen)
				want = UsidVrfTrafficValue{Ingress: direction(1, l3, 0), Egress: direction(1, l3, 0)}
			}
			assertVRFTraffic(t, objs, key, want, tt.name)
		})
	}
}

// A service packet delivered straight to another attachment on this node
// counts as outbound for the sender's VRF and inbound for the receiver's. In
// this fixture both are the attachment on ifindex 1.
func TestUsidServiceEgress_VRFTrafficCountsLocalDelivery(t *testing.T) {
	requireRoot(t)
	objs := loadObjects(t)

	const (
		tableID     = uint32(7)
		loopback    = uint32(1)
		servicePort = uint16(8443)
	)
	setUpEgressRouteAttachment(t, objs, 0xABCDEF, 0x100, tableID)
	setServiceIdentity(t, objs, 1)
	key := vrfKeyOf(t, 0xABCDEF, 0x100)
	putVRFTraffic(t, objs, key)

	service := netip.MustParseAddr("fd20:70::100")
	frontend := netip.MustParseAddr("fd53::53")
	if err := objs.ServiceRouteTable.Put(
		serviceRouteKey(frontend),
		UsidServiceRouteValue{
			TargetIfindex: loopback, Mode: 1, ConsumerToken: 1, ProducerToken: 1, BackendAddr: service.As16(),
		},
	); err != nil {
		t.Fatalf("populate service_route_table: %v", err)
	}
	if err := objs.ServiceAccessTable.Put(UsidServiceAccessKey{
		IngressIfindex: loopback,
		Family:         egressRouteFamilyINET6,
		Protocol:       6,
		Port:           bits.ReverseBytes16(servicePort),
		Addr:           frontend.As16(),
	}, UsidServiceAccessValue{AttachmentToken: 1}); err != nil {
		t.Fatalf("populate service_access_table: %v", err)
	}

	pkt := buildPlainV6PacketWithL4Ports(t, netip.MustParseAddr("fd20:70::2"), frontend, 49152, servicePort)
	if ret, _, err := objs.UsidServiceEgress.Test(pkt); err != nil || ret != tcActRedirect {
		t.Fatalf("verdict = %d, err = %v; want TC_ACT_REDIRECT", ret, err)
	}
	l3 := uint64(len(pkt) - ethHeaderLen)
	assertVRFTraffic(t, objs, key,
		UsidVrfTrafficValue{Ingress: direction(1, l3, 0), Egress: direction(1, l3, 0)}, "after one local delivery")
}
