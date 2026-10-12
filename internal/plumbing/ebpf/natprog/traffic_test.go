// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package natprog

import (
	"encoding/binary"
	"testing"
)

// trafficSnapshot reads every nat_traffic slot summed across CPUs.
func trafficSnapshot(t *testing.T, objs *NatObjects) [TrafficSlots]NatNatTrafficCounter {
	t.Helper()
	var totals [TrafficSlots]NatNatTrafficCounter
	for slot := range TrafficSlots {
		var perCPU []NatNatTrafficCounter
		if err := objs.NatTraffic.Lookup(slot, &perCPU); err != nil {
			t.Fatalf("lookup nat_traffic[%d]: %v", slot, err)
		}
		for _, v := range perCPU {
			totals[slot].Packets += v.Packets
			totals[slot].Bytes += v.Bytes
		}
	}
	return totals
}

// assertTranslatedDelta checks that one program run, which returned ret and
// left out on the wire, moved nat_traffic by exactly what that verdict means:
// one packet of the translated packet's length in the family and direction's
// slot for the action ret names, and nothing anywhere else. A dropped packet
// moves nothing. A return packet carries the SRv6 outer header, which the
// counter leaves out.
func assertTranslatedDelta(t *testing.T, objs *NatObjects, before [TrafficSlots]NatNatTrafficCounter,
	family, direction, ret uint32, out []byte,
) {
	t.Helper()
	want := before
	switch ret {
	case xdpTx, xdpRedirect:
		action := TrafficActionRedirect
		if ret == xdpTx {
			action = TrafficActionTX
		}
		headers := ethLen
		if direction == TrafficDirectionReturn {
			headers += ip6Len
		}
		slot := TrafficSlot(family, direction, action)
		want[slot].Packets++
		want[slot].Bytes += uint64(len(out) - headers) //nolint:gosec // a frame is far smaller than 2^63
	}
	if got := trafficSnapshot(t, objs); got != want {
		t.Errorf("nat_traffic after verdict %d = %+v, want %+v", ret, got, want)
	}
}

// assertNoTranslatedDelta checks a run counted nothing as translated.
func assertNoTranslatedDelta(t *testing.T, objs *NatObjects, before [TrafficSlots]NatNatTrafficCounter) {
	t.Helper()
	if got := trafficSnapshot(t, objs); got != before {
		t.Errorf("nat_traffic = %+v, want unchanged %+v", got, before)
	}
}

// TestNatTraffic_CountsEachLegOnce drives a session through both legs of each
// family over routes the FIB lookup resolves, so every translated packet leaves
// the datapath: each leg counts one packet of its translated length in its own
// slot, and a reply too big for the fabric, answered by the shard's own error
// instead, counts nothing.
func TestNatTraffic_CountsEachLegOnce(t *testing.T) {
	t.Run("nat66", func(t *testing.T) {
		f := newNAT66Fixture(t)
		narrowFabric(t, f.backendUSID, f.peer)

		before := trafficSnapshot(t, f.objs)
		ret, out := f.run(t, buildEncappedUDPPacket(t, sidWithArgument(f.shardSID, 0x123), f.backendUSID,
			f.backend, f.peer, []byte("out")))
		requireLeft(t, ret)
		assertTranslatedDelta(t, f.objs, before, TrafficFamilyNAT66, TrafficDirectionOutbound, ret, out)
		masqPort := binary.BigEndian.Uint16(out[ethLen+ip6Len:])

		before = trafficSnapshot(t, f.objs)
		ret, out = f.run(t, buildUDPPacket(t, f.shardPub, f.peer, encappedDstPort, masqPort, []byte("reply")))
		requireLeft(t, ret)
		assertTranslatedDelta(t, f.objs, before, TrafficFamilyNAT66, TrafficDirectionReturn, ret, out)

		before = trafficSnapshot(t, f.objs)
		f.run(t, buildUDPPacket(t, f.shardPub, f.peer, encappedDstPort, masqPort, make([]byte, bigPayload)))
		assertNoTranslatedDelta(t, f.objs, before)
	})
	t.Run("nat64", func(t *testing.T) {
		f := newNAT64Fixture(t, 0)
		narrowFabric(t, f.backendUSID, f.peer4)

		before := trafficSnapshot(t, f.objs)
		ret, out := f.run(t, buildEncappedUDPPacket(t, sidWithArgument(f.shardSID, 0x123), f.backendUSID,
			f.backend, f.synth, []byte("out")))
		requireLeft(t, ret)
		assertTranslatedDelta(t, f.objs, before, TrafficFamilyNAT64, TrafficDirectionOutbound, ret, out)
		masqPort := binary.BigEndian.Uint16(out[ethLen+ip4Len:])

		before = trafficSnapshot(t, f.objs)
		ret, out = f.run(t, buildIPv4UDPPacket(t, f.shardPub4, f.peer4, encappedDstPort, masqPort, []byte("reply")))
		requireLeft(t, ret)
		assertTranslatedDelta(t, f.objs, before, TrafficFamilyNAT64, TrafficDirectionReturn, ret, out)

		before = trafficSnapshot(t, f.objs)
		f.run(t, buildIPv4UDPPacket(t, f.shardPub4, f.peer4, encappedDstPort, masqPort, make([]byte, bigPayload)))
		assertNoTranslatedDelta(t, f.objs, before)
	})
}

// requireLeft fails unless ret hands the packet to the wire.
func requireLeft(t *testing.T, ret uint32) {
	t.Helper()
	if ret != xdpTx && ret != xdpRedirect {
		t.Fatalf("verdict = %d, want XDP_TX (%d) or XDP_REDIRECT (%d) over the test's routes", ret, xdpTx, xdpRedirect)
	}
}
