// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package edgeprog

import (
	"net/netip"
	"testing"
)

// returnStatsRows reads every vip_return_stats_table row.
func returnStatsRows(t *testing.T, objs *EdgedsrObjects) map[EdgedsrVipKey]EdgedsrVipStatsValue {
	t.Helper()
	rows := make(map[EdgedsrVipKey]EdgedsrVipStatsValue)
	var (
		key   EdgedsrVipKey
		value EdgedsrVipStatsValue
	)
	it := objs.VipReturnStatsTable.Iterate()
	for it.Next(&key, &value) {
		rows[key] = value
	}
	if err := it.Err(); err != nil {
		t.Fatalf("iterate vip_return_stats_table: %v", err)
	}
	return rows
}

// putListener registers a vip_table row for proto/port on vip. edge_return
// reads only whether the row exists, so its backends do not matter.
func putListener(t *testing.T, objs *EdgedsrObjects, proto uint8, port uint16, vip netip.Addr) {
	t.Helper()
	value := EdgedsrVipValue{BackendCount: 1, Generation: 1}
	if err := objs.VipTable.Put(vipKey(proto, port, vip), value); err != nil {
		t.Fatalf("populate vip_table: %v", err)
	}
}

func claimReturnAddr(t *testing.T, objs *EdgedsrObjects, vip netip.Addr) {
	t.Helper()
	if err := objs.VipAddrTable.Put(vipAddrKey(vip), EdgedsrVipAddrValue{Generation: 1}); err != nil {
		t.Fatalf("populate vip_addr_table: %v", err)
	}
}

func wantReturnRows(t *testing.T, objs *EdgedsrObjects, want map[EdgedsrVipKey]uint64) {
	t.Helper()
	rows := returnStatsRows(t, objs)
	if len(rows) != len(want) {
		t.Errorf("vip_return_stats_table has %d rows, want %d: %+v", len(rows), len(want), rows)
	}
	for key, packets := range want {
		if got := rows[key].Packets; got != packets {
			t.Errorf("row {proto %d, port %d}: packets = %d, want %d",
				key.Proto, bswap16(key.Port), got, packets)
		}
	}
}

// TestEdgeReturn_CountsRepliesPerListener covers #1377: two listeners sharing
// one address get separate reply counters, and a reply matching no listener,
// or carrying no ports, counts under port 0 of its protocol. The rows still
// sum to every reply the address sourced.
func TestEdgeReturn_CountsRepliesPerListener(t *testing.T) {
	requireRoot(t)
	objs := loadObjects(t)

	vip := netip.MustParseAddr("2001:db8:6060::1")
	client := netip.MustParseAddr("2001:db8:1:40::2")
	claimReturnAddr(t, objs, vip)
	putListener(t, objs, ipprotoTCP, 80, vip)
	putListener(t, objs, ipprotoTCP, 443, vip)

	reply := func(sport uint16) []byte {
		pkt := buildL4Packet(t, ipprotoTCP, client, vip, sport, 44450, nil)
		pkt[ethLen+7] = 64
		return pkt
	}
	icmp := reply(80)
	icmp[ethLen+6] = 58 // ICMPv6: no ports to key on
	// Any other protocol shares protocol 0, so arbitrary protocols cannot
	// each take a row.
	gre, sctp := reply(80), reply(80)
	gre[ethLen+6], sctp[ethLen+6] = 47, 132

	for _, pkt := range [][]byte{reply(80), reply(443), reply(443), reply(8080), icmp, gre, sctp} {
		runReturn(t, objs, pkt)
	}
	wantReturnRows(t, objs, map[EdgedsrVipKey]uint64{
		vipKey(ipprotoTCP, 80, vip):  1,
		vipKey(ipprotoTCP, 443, vip): 2,
		vipKey(ipprotoTCP, 0, vip):   1,
		vipKey(58, 0, vip):           1,
		vipKey(0, 0, vip):            2,
	})
}

// TestEdgeReturn_CountsUDPRangeUnderStartPort covers a reply from inside a
// UDP port range: it counts under the range's start port, the key the forward
// counters use.
func TestEdgeReturn_CountsUDPRangeUnderStartPort(t *testing.T) {
	requireRoot(t)
	objs := loadObjects(t)

	vip := netip.MustParseAddr("2001:db8::100")
	client := netip.MustParseAddr("2001:db8:ffff::1")
	claimReturnAddr(t, objs, vip)
	if err := objs.VipRangeBackends.Put(vipKey(ipprotoUDP, 10000, vip),
		EdgedsrVipValue{BackendCount: 1, Generation: 7}); err != nil {
		t.Fatal(err)
	}
	ranges := EdgedsrVipRangeValue{Count: 1}
	ranges.Ranges[0] = EdgedsrVipRange{Start: 10000, End: 10127, Generation: 7}
	if err := objs.VipRangeTable.Put(vipKey(ipprotoUDP, 0, vip), ranges); err != nil {
		t.Fatal(err)
	}

	for _, sport := range []uint16{10000, 10064, 10127, 10128} {
		pkt := buildL4Packet(t, ipprotoUDP, client, vip, sport, 5000, []byte("media"))
		pkt[ethLen+7] = 64
		runReturn(t, objs, pkt)
	}
	wantReturnRows(t, objs, map[EdgedsrVipKey]uint64{
		vipKey(ipprotoUDP, 10000, vip): 3,
		vipKey(ipprotoUDP, 0, vip):     1,
	})
}

// TestEdgeReturn_IPv4CountsPerListener is the IPv4 twin: a reply from a
// listener's port counts under it, a first fragment included, and a later
// fragment, which carries no ports, counts under port 0.
func TestEdgeReturn_IPv4CountsPerListener(t *testing.T) {
	requireRoot(t)
	objs := loadObjects(t)
	claimReturnAddr(t, objs, testVIP4)
	putIPv4VIP(t, objs, ipprotoTCP, 443, testVIP4, testUSID)

	first := buildIPv4Packet(t, ipprotoTCP, testClient4, testVIP4, 443, 41000, []byte("reply"),
		ip4Opts{fragOff: 0x2000}) // MF set, offset 0: ports present
	later := buildIPv4Packet(t, ipprotoTCP, testClient4, testVIP4, 443, 41000, []byte("reply"),
		ip4Opts{fragOff: 0x0001})
	whole := buildIPv4Packet(t, ipprotoTCP, testClient4, testVIP4, 443, 41000, []byte("reply"),
		ip4Opts{fragOff: ipDF})
	for _, pkt := range [][]byte{first, later, whole} {
		runReturn(t, objs, pkt)
	}
	wantReturnRows(t, objs, map[EdgedsrVipKey]uint64{
		vipKey(ipprotoTCP, 443, testVIP4): 2,
		vipKey(ipprotoTCP, 0, testVIP4):   1,
	})
}
