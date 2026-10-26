// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package edgeprog

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"strconv"
	"testing"
	"time"
)

func TestEdgeUDPRangeCoverageAndGeneration(t *testing.T) {
	requireRoot(t)
	objs := loadObjects(t)
	vip := netip.MustParseAddr("2001:db8::100")
	client := netip.MustParseAddr("2001:db8:ffff::1")
	value := EdgedsrVipValue{BackendCount: 1, Affinity: 0, Generation: 7}
	value.Backends[0] = EdgedsrBackend{Addr: netip.MustParseAddr("fd00::1").As16(),
		Port: bswap16(10000),
		Usid: netip.MustParseAddr("fc00:1:2::a1b2").As16()}
	if err := objs.VipRangeBackends.Put(vipKey(17, 10000, vip), value); err != nil {
		t.Fatal(err)
	}
	ranges := EdgedsrVipRangeValue{Count: 1}
	ranges.Ranges[0] = EdgedsrVipRange{Start: 10000, End: 10127, Generation: 7}
	if err := objs.VipRangeTable.Put(vipKey(17, 0, vip), ranges); err != nil {
		t.Fatal(err)
	}
	if err := objs.VipOwnedTable.Put(EdgedsrVipAddrKey{Vip: vip.As16()},
		EdgedsrVipOwnedValue{Generation: 1, ExpiresAtNs: ^uint64(0)}); err != nil {
		t.Fatal(err)
	}
	if err := objs.EncapConfigTable.Put(uint32(0),
		EdgedsrEncapConfig{EncapSrc: netip.MustParseAddr("fc00:0:2::1").As16()}); err != nil {
		t.Fatal(err)
	}
	for _, port := range []uint16{9999, 10000, 10064, 10127, 10128} {
		pkt := buildL4Packet(t, 17, vip, client, 5000, port, []byte("media payload"))
		ret, out, err := objs.EdgeLb.Test(pkt)
		if err != nil {
			t.Fatal(err)
		}
		if port >= 10000 && port <= 10127 {
			if len(out) != len(pkt)+40 || !bytes.Equal(out[54:], pkt[14:]) {
				t.Fatalf("port %d not forwarded intact", port)
			}
		} else if ret != xdpDrop || len(out) != len(pkt) {
			t.Fatalf("outside port %d was exposed", port)
		}
	}
	assertOwnedVIPRevocation(t, objs, vip, client)
	// Stale legacy exact rows overlapping owned ranges must fail closed.
	if err := objs.VipTable.Put(vipKey(17, 10064, vip), value); err != nil {
		t.Fatal(err)
	}
	if ret,
		_,
		err := objs.EdgeLb.Test(buildL4Packet(t,
		17,
		vip,
		client,
		5000,
		10064,
		nil)); err != nil || ret != xdpDrop {
		t.Fatalf("stale exact overlap forwarded: %d %v", ret, err)
	}
	if err := objs.VipTable.Delete(vipKey(17, 10064, vip)); err != nil {
		t.Fatal(err)
	}
	// A reader of the retired classifier must not pair it with a replacement row.
	value.Generation = 8
	if err := objs.VipRangeBackends.Put(vipKey(17, 10000, vip), value); err != nil {
		t.Fatal(err)
	}
	for _, port := range []uint16{10000, 10064} {
		pkt := buildL4Packet(t, 17, vip, client, 5000, port, nil)
		ret, out, err := objs.EdgeLb.Test(pkt)
		if err != nil {
			t.Fatal(err)
		}
		if ret != xdpDrop || len(out) != len(pkt) {
			t.Fatalf("stale generation forwarded port %d", port)
		}
	}
	ranges.Ranges[0] = EdgedsrVipRange{Start: 10000, End: 10031, Generation: 8}
	if err := objs.VipRangeTable.Put(vipKey(17, 0, vip), ranges); err != nil {
		t.Fatal(err)
	}
	pkt := buildL4Packet(t, 17, vip, client, 5000, 10064, nil)
	ret, out, err := objs.EdgeLb.Test(pkt)
	if err != nil {
		t.Fatal(err)
	}
	if ret != xdpDrop || len(out) != len(pkt) {
		t.Fatal("shrunk coverage still exposed")
	}
}

func assertOwnedVIPRevocation(t *testing.T, objs *EdgedsrObjects, vip, client netip.Addr) {
	t.Helper()
	// Convergence blocks even a valid old row until the controller acknowledges cleanup.
	ownedKey := EdgedsrVipAddrKey{Vip: vip.As16()}
	if err := objs.VipOwnedTable.Put(ownedKey, EdgedsrVipOwnedValue{Blocked: 1}); err != nil {
		t.Fatal(err)
	}
	if ret,
		_,
		err := objs.EdgeLb.Test(buildL4Packet(t,
		17,
		vip,
		client,
		5000,
		10064,
		nil)); err != nil || ret != xdpDrop {
		t.Fatalf("blocked VIP forwarded: %d %v", ret, err)
	}
	if err := objs.VipOwnedTable.Put(ownedKey, EdgedsrVipOwnedValue{ExpiresAtNs: ^uint64(0)}); err != nil {
		t.Fatal(err)
	}
	// A stopped reconciler cannot keep a formerly valid socket serving indefinitely.
	if err := objs.VipOwnedTable.Put(ownedKey, EdgedsrVipOwnedValue{ExpiresAtNs: 1}); err != nil {
		t.Fatal(err)
	}
	if ret, _, err := objs.EdgeLb.Test(buildL4Packet(t, 17, vip, client, 5000, 10064, nil)); err != nil || ret != xdpDrop {
		t.Fatalf("expired VIP forwarded: %d %v", ret, err)
	}
	if err := objs.VipOwnedTable.Put(ownedKey, EdgedsrVipOwnedValue{ExpiresAtNs: ^uint64(0)}); err != nil {
		t.Fatal(err)
	}
}

func TestOwnedVIPRejectsParserBypass(t *testing.T) {
	requireRoot(t)
	objs := loadObjects(t)
	vip := netip.MustParseAddr("2001:db8::100")
	client := netip.MustParseAddr("2001:db8:ffff::1")
	if err := objs.VipOwnedTable.Put(EdgedsrVipAddrKey{Vip: vip.As16()},
		EdgedsrVipOwnedValue{Generation: 1, ExpiresAtNs: ^uint64(0)}); err != nil {
		t.Fatal(err)
	}
	for _, proto := range []uint8{6, 17, 0, 43, 44, 60, 59} {
		pkt := buildL4Packet(t, 17, vip, client, 5000, 10000, nil)
		pkt[20] = proto
		ret, _, err := objs.EdgeLb.Test(pkt)
		if err != nil {
			t.Fatal(err)
		}
		if ret != xdpDrop {
			t.Fatalf("protocol %d bypassed owned guard", proto)
		}
	}
	pkt := buildL4Packet(t, 17, vip, client, 5000, 10000, nil)
	pkt[20] = 58
	ret, _, err := objs.EdgeLb.Test(pkt)
	if err != nil {
		t.Fatal(err)
	}
	if ret != xdpPass {
		t.Fatal("ICMPv6 control packet blocked")
	}
}

// TestUDPRangeLookupMicrobench records kernel test-run cost, not NIC throughput.
func TestUDPRangeLookupMicrobench(t *testing.T) {
	requireRoot(t)
	objs := loadObjects(t)
	vip := netip.MustParseAddr("2001:db8::100")
	client := netip.MustParseAddr("2001:db8:ffff::1")
	// An empty group deliberately drops, leaving the packet unchanged between
	// BPF_PROG_TEST_RUN repetitions. This measures lookup plus the drop path.
	value := EdgedsrVipValue{Generation: 1}
	value.Backends[0] = EdgedsrBackend{Addr: netip.MustParseAddr("fd00::1").As16(),
		Port: bswap16(10000),
		Usid: netip.MustParseAddr("fc00:1:2::a1b2").As16()}
	if err := objs.EncapConfigTable.Put(uint32(0),
		EdgedsrEncapConfig{EncapSrc: netip.MustParseAddr("fc00:0:2::1").As16()}); err != nil {
		t.Fatal(err)
	}
	if err := objs.VipOwnedTable.Put(EdgedsrVipAddrKey{Vip: vip.As16()},
		EdgedsrVipOwnedValue{ExpiresAtNs: ^uint64(0)}); err != nil {
		t.Fatal(err)
	}
	t.Logf("map value bytes: classifier=%d backend_group=%d", binary.Size(EdgedsrVipRangeValue{}), binary.Size(value))
	for _, count := range []int{0, 1, 16, 50} {
		t.Run(strconv.Itoa(count), func(t *testing.T) {
			if count == 0 {
				if err := objs.VipTable.Put(vipKey(17, 10000, vip), value); err != nil {
					t.Fatal(err)
				}
			} else {
				if count == 1 {
					if err := objs.VipTable.Delete(vipKey(17, 10000, vip)); err != nil {
						t.Fatal(err)
					}
				}
				ranges := EdgedsrVipRangeValue{Count: uint32(count)}
				if count == 50 {
					ranges.Count = 1
				}
				for i := range ranges.Count {
					start := uint16(10000 + i*100)
					ranges.Ranges[i] = EdgedsrVipRange{Start: start, End: start + 63, Generation: 1}
					if count == 50 {
						ranges.Ranges[i].End = 60000
					}
					if err := objs.VipRangeBackends.Put(vipKey(17, start, vip), value); err != nil {
						t.Fatal(err)
					}
				}
				if err := objs.VipRangeTable.Put(vipKey(17, 0, vip), ranges); err != nil {
					t.Fatal(err)
				}
			}
			port := uint16(10000)
			if count == 16 {
				port = 11563
			}
			if count == 50 {
				port = 60000
			}
			packet := buildL4Packet(t, 17, vip, client, 5000, port, make([]byte, 128))
			for run := range 5 {
				ret, duration, err := objs.EdgeLb.Benchmark(packet, 100000, nil)
				if err != nil {
					t.Fatal(err)
				}
				if ret != xdpDrop {
					t.Fatalf("benchmark packet mutated or bypassed lookup: %d", ret)
				}
				t.Logf("sample=%d ns/lookup-and-drop=%d", run, duration.Nanoseconds())
			}
		})
	}
}

// TestRangeMapCapacityAndUpdateMicrobench measures bounded map occupancy and
// synchronous syscall update cost at the backend map limit, not traffic capacity.
func TestRangeMapCapacityAndUpdateMicrobench(t *testing.T) {
	requireRoot(t)
	objs := loadObjects(t)
	value := EdgedsrVipValue{Generation: 1}
	var firstVIP netip.Addr
	for group := range 256 {
		raw := netip.MustParseAddr("2001:db8::").As16()
		binary.BigEndian.PutUint16(raw[14:], uint16(group+1))
		vip := netip.AddrFrom16(raw)
		if group == 0 {
			firstVIP = vip
		}
		snapshot := EdgedsrVipRangeValue{Count: 16, Generation: 1}
		for i := range 16 {
			start := uint16(10000 + i*64)
			snapshot.Ranges[i] = EdgedsrVipRange{Start: start, End: start + 63, Generation: 1}
			if err := objs.VipRangeBackends.Put(vipKey(17, start, vip), value); err != nil {
				t.Fatalf("backend row %d: %v", group*16+i, err)
			}
		}
		if err := objs.VipRangeTable.Put(vipKey(17, 0, vip), snapshot); err != nil {
			t.Fatal(err)
		}
	}
	if err := objs.VipRangeBackends.Put(vipKey(17, 30000, firstVIP), value); err == nil {
		t.Fatal("backend map accepted row 4097")
	}
	var snapshot EdgedsrVipRangeValue
	if err := objs.VipRangeTable.Lookup(vipKey(17, 0, firstVIP), &snapshot); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	const updates = 5000
	for i := range updates {
		// Replacement uses existing keys; no second backend row or staged table.
		snapshot.Generation = uint64(i + 2)
		if err := objs.VipRangeTable.Put(vipKey(17, 0, firstVIP), snapshot); err != nil {
			t.Fatal(err)
		}
		if err := objs.VipRangeBackends.Put(vipKey(17, 10000, firstVIP), value); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("4096 groups,256 classifiers,1024 covered ports/address; "+
		"classifier+backend replacement mean=%dns (%d updates); "+
		"value payload bytes=%d (excludes map allocation/metadata)",
		time.Since(started).Nanoseconds()/updates,
		updates,
		4096*binary.Size(value)+256*binary.Size(snapshot))
}
