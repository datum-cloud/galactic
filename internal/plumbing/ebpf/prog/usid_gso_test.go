// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package prog

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"

	"go.datum.net/galactic/internal/plumbing/ebpf/uformat"
)

const (
	gsoTestTableID  = 100
	gsoTestRouteMTU = 1450
	tcpHeaderLen    = 20
	ip4HeaderLen    = 20

	// virtio_net_hdr values from the kernel UAPI.
	virtioNetHdrLen       = 10
	virtioNetHdrNeedsCsum = 1
	virtioNetHdrGSONone   = 0
	virtioNetHdrGSOTCPv4  = 1
	virtioNetHdrGSOTCPv6  = 4
)

var (
	gsoTestInner6Src = netip.MustParseAddr("2001:db8:100::1")
	gsoTestInner6Dst = netip.MustParseAddr("2001:db8:200::2")
	gsoTestInner4Src = netip.MustParseAddr("192.0.2.1")
	gsoTestInner4Dst = netip.MustParseAddr("198.51.100.2")
)

// TestUsidIngress_FIBLookupJudgesMergedPacketsPerSegment checks that a packet
// the NIC merged with GRO is held to the route MTU one segment at a time, while
// a single packet is still held to it whole.
//
// BPF_PROG_TEST_RUN can set a context's gso_size but not its gso_type, and the
// kernel refuses to strip a header from a GSO packet that isn't marked TCP. A
// tap with a virtio-net header is the closest stand-in for a merged packet the
// kernel builds: it delivers a TCP GSO packet through the attached program the
// same way the uplink does.
func TestUsidIngress_FIBLookupJudgesMergedPacketsPerSegment(t *testing.T) {
	requireRoot(t)

	tests := []struct {
		name         string
		innerV4      bool
		gso          bool
		segL3Len     int
		wantFragDrop uint64
		wantForward  bool
	}{
		{"IPv6SinglePacketFits", false, false, gsoTestRouteMTU, 0, true},
		{"IPv6SinglePacketTooBig", false, false, gsoTestRouteMTU + 1, 1, false},
		{"IPv6MergedSegmentsFit", false, true, gsoTestRouteMTU, 0, true},
		{"IPv6MergedSegmentsTooBig", false, true, gsoTestRouteMTU + 1, 1, false},
		{"IPv4SinglePacketFits", true, false, gsoTestRouteMTU, 0, true},
		{"IPv4SinglePacketTooBig", true, false, gsoTestRouteMTU + 1, 1, false},
		{"IPv4MergedSegmentsFit", true, true, gsoTestRouteMTU, 0, true},
		{"IPv4MergedSegmentsTooBig", true, true, gsoTestRouteMTU + 1, 1, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			objs := loadObjects(t)
			usid := testUSID{block: baseUSID.block, nodeID: baseUSID.nodeID, function: uformat.FunctionEndDT46, argument: 0x321}
			populateGSOTestTables(t, objs, usid)

			netNS, err := ns.TempNetNS()
			if err != nil {
				t.Fatalf("create test netns: %v", err)
			}
			t.Cleanup(func() { _ = netNS.Close() })

			err = netNS.Do(func(_ ns.NetNS) error {
				return runGSOTestCase(t, objs, usid, tt.innerV4, tt.gso, tt.segL3Len, tt.wantForward)
			})
			if err != nil {
				t.Fatal(err)
			}

			if got := sumPerCPU(t, objs.DropReasons, DropReasonFibFragNeeded); got != tt.wantFragDrop {
				t.Errorf("drop_reasons[fib_frag_needed] = %d, want %d", got, tt.wantFragDrop)
			}
			var vrfVal UsidVrfValue
			if err := objs.VrfTable.Lookup(usid.vrfKey(), &vrfVal); err != nil {
				t.Fatalf("lookup vrf_table entry: %v", err)
			}
			if vrfVal.Packets != 1 {
				t.Errorf("vrf_table packets = %d, want 1 (the packet must reach the program's VRF match)", vrfVal.Packets)
			}
		})
	}
}

func populateGSOTestTables(t *testing.T, objs *UsidObjects, usid testUSID) {
	t.Helper()
	if err := objs.LocatorTable.Put(usid.locatorKey(t), UsidLocatorValue{Generation: 1}); err != nil {
		t.Fatalf("populate locator_table: %v", err)
	}
	if err := objs.FunctionTable.Put(usid.functionKey(t), UsidFunctionValue{Behavior: 1}); err != nil {
		t.Fatalf("populate function_table: %v", err)
	}
	// A dummy device has no namespace-crossing peer, so it needs the plain
	// redirect a tap attachment gets.
	vrfVal := UsidVrfValue{VrfTableId: gsoTestTableID, EgressKind: 1}
	if err := objs.VrfTable.Put(usid.vrfKey(), vrfVal); err != nil {
		t.Fatalf("populate vrf_table: %v", err)
	}
}

// runGSOTestCase runs inside a fresh netns: it builds a tap for the program to
// receive on and a dummy route target whose MTU is the route MTU, writes one
// tunneled frame, and checks whether the target transmitted the decapsulated
// packet.
func runGSOTestCase(t *testing.T, objs *UsidObjects, usid testUSID, innerV4, gso bool, segL3Len int,
	wantForward bool) error {
	tap := &netlink.Tuntap{
		LinkAttrs:  netlink.LinkAttrs{Name: "usidgso0"},
		Mode:       netlink.TUNTAP_MODE_TAP,
		Flags:      netlink.TUNTAP_NO_PI | netlink.TUNTAP_VNET_HDR,
		Queues:     1,
		NonPersist: true,
	}
	if err := netlink.LinkAdd(tap); err != nil {
		return fmt.Errorf("add tap: %w", err)
	}
	tapFile := tap.Fds[0]
	defer tapFile.Close() //nolint:errcheck // best-effort cleanup

	dst := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "usidgsodst0", MTU: gsoTestRouteMTU}}
	if err := netlink.LinkAdd(dst); err != nil {
		return fmt.Errorf("add dummy: %w", err)
	}
	// Without a link-local address the target sends no neighbor discovery or
	// MLD traffic of its own, which would otherwise land in its transmit count.
	if err := netlink.LinkSetIP6AddrGenMode(dst, nl.IN6_ADDR_GEN_MODE_NONE); err != nil {
		return fmt.Errorf("disable address generation on dummy: %w", err)
	}
	for _, l := range []netlink.Link{tap, dst} {
		if err := netlink.LinkSetUp(l); err != nil {
			return fmt.Errorf("set %s up: %w", l.Attrs().Name, err)
		}
	}
	tapLink, err := netlink.LinkByName(tap.Name)
	if err != nil {
		return fmt.Errorf("look up tap: %w", err)
	}
	dstLink, err := netlink.LinkByName(dst.Name)
	if err != nil {
		return fmt.Errorf("look up dummy: %w", err)
	}

	if err := installGSOTestRoutes(dstLink); err != nil {
		return err
	}
	// The FIB lookup refuses to forward for an ingress device with forwarding
	// off, which is every device in a fresh netns.
	for _, path := range []string{"/proc/sys/net/ipv6/conf/all/forwarding", "/proc/sys/net/ipv4/ip_forward"} {
		if err := os.WriteFile(path, []byte("1"), 0o644); err != nil {
			return fmt.Errorf("enable forwarding via %s: %w", path, err)
		}
	}

	tcx, err := link.AttachTCX(link.TCXOptions{
		Interface: tapLink.Attrs().Index,
		Program:   objs.UsidIngress,
		Attach:    ebpf.AttachTCXIngress,
	})
	if err != nil {
		return fmt.Errorf("attach usid_ingress to tap: %w", err)
	}
	defer tcx.Close() //nolint:errcheck // best-effort cleanup

	before, err := dummyTxStats(dst.Name)
	if err != nil {
		return err
	}
	frame := buildGSOTestFrame(t, tapLink.Attrs().HardwareAddr, usid.addr(t), innerV4, gso, segL3Len)
	if _, err := tapFile.Write(frame); err != nil {
		return fmt.Errorf("write frame to tap: %w", err)
	}

	// The dummy does not segment, so a forwarded merged packet counts as one
	// transmit of the whole decapsulated frame.
	var wantPkts, wantBytes uint64
	if wantForward {
		wantPkts, wantBytes = 1, uint64(len(frame)-virtioNetHdrLen-ip6HeaderLen)
	}
	// Transmit happens in the write's own context, so a short poll only absorbs
	// stats propagation.
	var gotPkts, gotBytes uint64
	for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		after, err := dummyTxStats(dst.Name)
		if err != nil {
			return err
		}
		gotPkts, gotBytes = after.TxPackets-before.TxPackets, after.TxBytes-before.TxBytes
		if wantForward && gotPkts >= wantPkts {
			break
		}
	}
	if gotPkts != wantPkts || gotBytes != wantBytes {
		t.Errorf("route target transmitted %d packets, %d bytes; want %d packets, %d bytes",
			gotPkts, gotBytes, wantPkts, wantBytes)
	}
	return nil
}

func dummyTxStats(name string) (*netlink.LinkStatistics, error) {
	l, err := netlink.LinkByName(name)
	if err != nil {
		return nil, fmt.Errorf("read %s stats: %w", name, err)
	}
	return l.Attrs().Statistics, nil
}

func installGSOTestRoutes(dstLink netlink.Link) error {
	for _, inner := range []netip.Addr{gsoTestInner6Dst, gsoTestInner4Dst} {
		bits := 64
		if inner.Is4() {
			bits = 24
		}
		prefix := netip.PrefixFrom(inner, bits).Masked()
		route := &netlink.Route{
			LinkIndex: dstLink.Attrs().Index,
			Dst:       &net.IPNet{IP: prefix.Addr().AsSlice(), Mask: net.CIDRMask(bits, inner.BitLen())},
			Table:     gsoTestTableID,
			Scope:     netlink.SCOPE_LINK,
		}
		if err := netlink.RouteAdd(route); err != nil {
			return fmt.Errorf("add route %s: %w", prefix, err)
		}
		neigh := &netlink.Neigh{
			LinkIndex:    dstLink.Attrs().Index,
			State:        netlink.NUD_PERMANENT,
			IP:           inner.AsSlice(),
			HardwareAddr: net.HardwareAddr{0x02, 0, 0, 0, 0, 0x02},
		}
		if err := netlink.NeighAdd(neigh); err != nil {
			return fmt.Errorf("add neighbor %s: %w", inner, err)
		}
	}
	return nil
}

// buildGSOTestFrame returns a virtio-net header followed by an Ethernet frame
// carrying an inner TCP packet in an outer IPv6 header addressed to outerDst.
// Each inner segment's L3 length is segL3Len. A GSO frame carries three such
// segments merged into one packet; otherwise the frame is a single segment.
func buildGSOTestFrame(t *testing.T, dstMAC net.HardwareAddr, outerDst netip.Addr, innerV4, gso bool,
	segL3Len int) []byte {
	t.Helper()

	innerHdrLen, nextHdr, gsoType := ip6HeaderLen, byte(41), byte(virtioNetHdrGSOTCPv6)
	if innerV4 {
		innerHdrLen, nextHdr, gsoType = ip4HeaderLen, 4, virtioNetHdrGSOTCPv4
	}
	segPayload := segL3Len - innerHdrLen - tcpHeaderLen
	payload := segPayload
	if gso {
		payload = 3 * segPayload
	}
	innerLen := innerHdrLen + tcpHeaderLen + payload

	frame := make([]byte, virtioNetHdrLen+ethHeaderLen+ip6HeaderLen+innerLen)
	vnet := frame[:virtioNetHdrLen]
	if gso {
		csumStart := ethHeaderLen + ip6HeaderLen + innerHdrLen
		vnet[0] = virtioNetHdrNeedsCsum
		vnet[1] = gsoType
		binary.NativeEndian.PutUint16(vnet[2:], uint16(csumStart+tcpHeaderLen))
		binary.NativeEndian.PutUint16(vnet[4:], uint16(segPayload))
		binary.NativeEndian.PutUint16(vnet[6:], uint16(csumStart))
		binary.NativeEndian.PutUint16(vnet[8:], 16)
	} else {
		vnet[1] = virtioNetHdrGSONone
	}

	eth := frame[virtioNetHdrLen:]
	copy(eth[0:6], dstMAC)
	copy(eth[6:12], []byte{0x02, 0, 0, 0, 0, 0x01})
	binary.BigEndian.PutUint16(eth[12:], 0x86DD)

	outer := eth[ethHeaderLen:]
	outer[0] = 0x60
	binary.BigEndian.PutUint16(outer[4:], uint16(innerLen))
	outer[6] = nextHdr
	outer[7] = 64
	src := netip.MustParseAddr("2001:db8::1").As16()
	dst := outerDst.As16()
	copy(outer[8:24], src[:])
	copy(outer[24:40], dst[:])

	inner := outer[ip6HeaderLen:]
	if innerV4 {
		inner[0] = 0x45
		binary.BigEndian.PutUint16(inner[2:], uint16(innerLen))
		binary.BigEndian.PutUint16(inner[6:], 0x4000) // DF
		inner[8] = 64
		inner[9] = 6
		s4, d4 := gsoTestInner4Src.As4(), gsoTestInner4Dst.As4()
		copy(inner[12:16], s4[:])
		copy(inner[16:20], d4[:])
		binary.BigEndian.PutUint16(inner[10:], ipv4HeaderChecksum(inner[:ip4HeaderLen]))
	} else {
		inner[0] = 0x60
		binary.BigEndian.PutUint16(inner[4:], uint16(tcpHeaderLen+payload))
		inner[6] = 6
		inner[7] = 64
		s6, d6 := gsoTestInner6Src.As16(), gsoTestInner6Dst.As16()
		copy(inner[8:24], s6[:])
		copy(inner[24:40], d6[:])
	}

	tcp := inner[innerHdrLen:]
	binary.BigEndian.PutUint16(tcp[0:], 443)
	binary.BigEndian.PutUint16(tcp[2:], 40000)
	binary.BigEndian.PutUint32(tcp[4:], 1)
	binary.BigEndian.PutUint32(tcp[8:], 1)
	tcp[12] = tcpHeaderLen / 4 << 4
	tcp[13] = 0x10 // ACK
	binary.BigEndian.PutUint16(tcp[14:], 65535)
	return frame
}

func ipv4HeaderChecksum(hdr []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(hdr); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(hdr[i:]))
	}
	for sum > 0xFFFF {
		sum = sum>>16 + sum&0xFFFF
	}
	return ^uint16(sum)
}
