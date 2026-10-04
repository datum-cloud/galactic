// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package prog

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"go.datum.net/galactic/internal/plumbing/ebpf/uformat"
)

// These tests run send_too_big against a real kernel, through a tap whose
// "guest" hands over its packets with the checksum still to be finished, as a
// guest with checksum offload does. That is the state a pod's or a guest's
// UDP and TCP packets usually reach usid_egress in, and the one
// BPF_PROG_TEST_RUN cannot produce.
//
// The tap uses a virtio_net_hdr, so what the kernel does with the checksum on
// the way back out is visible: with offload on, the header says where it left
// the checksum to be finished; with offload off, the kernel finishes it itself
// before the frame is read.

const (
	virtioNetHdrFNeedsCsum        = 1
	pmtuTapName                   = "pmtut0"
	pmtuTapTableID         uint32 = 31
	pmtuTapArgument        uint16 = 0x231
	pmtuTapBlock           uint64 = 0x123456
)

// The tap offload flags from the kernel UAPI. TUN_F_CSUM lets the tap hand
// checksums to the reader to finish instead of finishing them in the kernel.
// TUN_F_TSO4 and TUN_F_TSO6 let it hand over TCP packets still to be
// segmented, so GSO state that survives to the tap shows in the header read.
const (
	tunOffloadCsum = 0x01
	tunOffloadTSO4 = 0x02
	tunOffloadTSO6 = 0x04
)

// newPMTUTap creates a tap with a virtio_net_hdr in a private network
// namespace, attaches usid_egress to it the way CNI ADD does to a tenant's
// host-side interface, and registers it as a tenant attachment whose default
// routes encapsulate. offloads is the TUN_F_* set the tap accepts.
func newPMTUTap(t *testing.T, offloads uint) (*UsidObjects, int) {
	t.Helper()
	requireRoot(t)
	if _, err := os.Stat("/dev/net/tun"); err != nil {
		t.Skipf("test requires /dev/net/tun: %v", err)
	}

	runtime.LockOSThread()
	origNS := openThreadNetns(t)
	t.Cleanup(func() {
		if err := unix.Setns(origNS, unix.CLONE_NEWNET); err != nil {
			t.Errorf("restore original network namespace: %v", err)
			return
		}
		_ = unix.Close(origNS)
		runtime.UnlockOSThread()
	})
	if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
		t.Fatalf("unshare network namespace: %v", err)
	}

	objs := loadObjects(t)

	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("open /dev/net/tun: %v", err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	ifr, err := unix.NewIfreq(pmtuTapName)
	if err != nil {
		t.Fatalf("ifreq: %v", err)
	}
	ifr.SetUint16(unix.IFF_TAP | unix.IFF_NO_PI | unix.IFF_VNET_HDR)
	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
		t.Fatalf("create tap: %v", err)
	}
	if err := unix.IoctlSetInt(fd, unix.TUNSETOFFLOAD, int(offloads)); err != nil {
		t.Fatalf("set tap offload to %#x: %v", offloads, err)
	}
	link := setLinkUp(t, pmtuTapName)
	attachIngress(t, link, objs.UsidEgress)

	gw := UsidTenantGwValue{Gw6: pmtuGW6.As16(), Gw4: pmtuGW4.As4()}
	registerPMTUAttachment(t, objs, uint32(link.Attrs().Index), gw)
	return objs, fd
}

// registerPMTUAttachment writes what CNI ADD writes for the attachment on
// ifindex, with gw as its gateways, plus default routes in both families that
// encapsulate and the 1500-byte fabric's limit.
func registerPMTUAttachment(t *testing.T, objs *UsidObjects, ifindex uint32, gw UsidTenantGwValue) {
	t.Helper()
	attachment := UsidIfindexVrfValue{Block: pmtuTapBlock, Argument: pmtuTapArgument}
	if err := objs.IfindexVrfTable.Put(ifindex, attachment); err != nil {
		t.Fatalf("populate ifindex_vrf_table: %v", err)
	}
	vrfKey, err := uformat.NewVRFKey(pmtuTapBlock, pmtuTapArgument)
	if err != nil {
		t.Fatalf("NewVRFKey: %v", err)
	}
	if err := objs.VrfTable.Put(uint64(vrfKey), UsidVrfValue{VrfTableId: pmtuTapTableID}); err != nil {
		t.Fatalf("populate vrf_table: %v", err)
	}
	for _, k := range []UsidEgressRouteKey{
		egressRouteKey(pmtuTapTableID, egressRouteFamilyINET6, netip.IPv6Unspecified(), 0),
		egressRouteKey(pmtuTapTableID, egressRouteFamilyINET4, netip.IPv4Unspecified(), 0),
	} {
		if err := objs.EgressRouteTable.Put(k, UsidEgressRouteValue{
			Sid: netip.MustParseAddr("2001:db8:ff01:2002:e231::").As16(), LinkIfindex: 1,
		}); err != nil {
			t.Fatalf("populate egress_route_table: %v", err)
		}
	}
	setUpNodeSIDBase(t, objs, netip.MustParseAddr("2001:db8:ff01:1:e000::"), pmtuTapArgument)
	setEncapMTU(t, objs, testEncapMTU)
	if err := objs.TenantGwTable.Put(ifindex, gw); err != nil {
		t.Fatalf("populate tenant_gw_table: %v", err)
	}
}

// writeGuestFrame hands frame to the host as the guest would, with its
// transport checksum left for the host to finish: csum_start at the transport
// header, csum_offset at the checksum field.
func writeGuestFrame(t *testing.T, fd int, frame []byte, l4Off, csumOff int) {
	t.Helper()
	writeGuestGSOFrame(t, fd, frame, l4Off, csumOff, virtioNetHdrGSONone, 0, 0)
}

// writeGuestGSOFrame is writeGuestFrame for a packet the host must still
// segment: gsoType and gsoSize as the virtio_net_hdr carries them, and hdrLen
// the length of the headers every segment repeats.
func writeGuestGSOFrame(t *testing.T, fd int, frame []byte, l4Off, csumOff int, gsoType byte, hdrLen, gsoSize int) {
	t.Helper()
	hdr := make([]byte, virtioNetHdrLen)
	hdr[0] = virtioNetHdrFNeedsCsum
	hdr[1] = gsoType
	binary.LittleEndian.PutUint16(hdr[2:4], uint16(hdrLen))
	binary.LittleEndian.PutUint16(hdr[4:6], uint16(gsoSize))
	binary.LittleEndian.PutUint16(hdr[6:8], uint16(l4Off))
	binary.LittleEndian.PutUint16(hdr[8:10], uint16(csumOff))
	if _, err := unix.Write(fd, append(hdr, frame...)); err != nil {
		t.Fatalf("write guest frame: %v", err)
	}
}

// readHostFrame returns the next frame of the given ethertype the host sends
// the guest, with its virtio_net_hdr, skipping unrelated traffic such as
// router solicitations.
func readHostFrame(t *testing.T, fd int, etherType uint16) (hdr, frame []byte) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	buf := make([]byte, 65536)
	for time.Now().Before(deadline) {
		fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		n, err := unix.Poll(fds, int(time.Until(deadline).Milliseconds())+1)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			t.Fatalf("poll tap: %v", err)
		}
		if n == 0 {
			break
		}
		n, err = unix.Read(fd, buf)
		if err != nil {
			t.Fatalf("read tap: %v", err)
		}
		if n < virtioNetHdrLen+ethHeaderLen {
			continue
		}
		frame := buf[virtioNetHdrLen:n]
		if binary.BigEndian.Uint16(frame[12:14]) != etherType {
			continue
		}
		if etherType == 0x86DD && (len(frame) < ethHeaderLen+ip6HeaderLen+1 ||
			frame[ethHeaderLen+6] != ipProtoICMPv6 || frame[ethHeaderLen+ip6HeaderLen] != 2) {
			continue // ICMPv6 other than Packet Too Big, such as a router solicitation
		}
		return append([]byte(nil), buf[:virtioNetHdrLen]...), append([]byte(nil), frame...)
	}
	t.Fatal("no error came back to the guest")
	return nil, nil
}

// TestPMTU_TapWithoutOffloadFinishesChecksumHarmlessly is the case the error's
// layout exists for. The guest's packet arrives with its checksum still to be
// finished, the tap cannot take a partial checksum, so the kernel finishes it
// on the way out, writing into the error. The error must arrive intact.
func TestPMTU_TapWithoutOffloadFinishesChecksumHarmlessly(t *testing.T) {
	for _, tt := range []struct {
		name  string
		v4    bool
		proto byte
	}{
		{"IPv6 UDP", false, ipProtoUDP},
		{"IPv6 TCP", false, ipProtoTCP},
		{"IPv4 UDP", true, ipProtoUDP},
		{"IPv4 TCP", true, ipProtoTCP},
	} {
		t.Run(tt.name, func(t *testing.T) {
			objs, fd := newPMTUTap(t, 0)
			pkt, l4Off := tapTestPacket(tt.v4, tt.proto)
			writeGuestFrame(t, fd, pkt, l4Off, partialCsumOffset(tt.proto))

			hdr, frame := readHostFrame(t, fd, binary.BigEndian.Uint16(pkt[12:14]))
			if hdr[0]&virtioNetHdrFNeedsCsum != 0 {
				t.Fatalf("virtio_net_hdr flags = %#x: the kernel left the checksum partial, so this test "+
					"did not exercise finishing it", hdr[0])
			}
			assertErrorFrame(t, frame, pkt, tt.v4, tt.proto)
			assertPMTUStats(t, objs, map[uint32]uint64{sentStat(tt.v4): 1})
		})
	}
}

// TestPMTU_TapWithOffloadReportsPredictedChecksumSpot checks the assumption
// the layout rests on, against the kernel: the checksum spot it leaves for the
// guest to finish is exactly where send_too_big placed its slot word.
func TestPMTU_TapWithOffloadReportsPredictedChecksumSpot(t *testing.T) {
	for _, tt := range []struct {
		name  string
		v4    bool
		proto byte
	}{
		{"IPv6 UDP", false, ipProtoUDP},
		{"IPv4 TCP", true, ipProtoTCP},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, fd := newPMTUTap(t, tunOffloadCsum)
			pkt, l4Off := tapTestPacket(tt.v4, tt.proto)
			writeGuestFrame(t, fd, pkt, l4Off, partialCsumOffset(tt.proto))

			hdr, frame := readHostFrame(t, fd, binary.BigEndian.Uint16(pkt[12:14]))
			if hdr[0]&virtioNetHdrFNeedsCsum == 0 {
				t.Fatalf("virtio_net_hdr flags = %#x, want the checksum left partial", hdr[0])
			}
			errIPHdrLen := ip6HeaderLen
			if tt.v4 {
				errIPHdrLen = 20
			}
			wantStart, wantOffset := partialChecksumSpot(errIPHdrLen, l4Off-ethHeaderLen, tt.proto)
			gotStart := int(binary.LittleEndian.Uint16(hdr[6:8]))
			gotOffset := int(binary.LittleEndian.Uint16(hdr[8:10]))
			if gotStart != wantStart || gotOffset != wantOffset {
				t.Errorf("kernel's checksum spot = start %d offset %d, want start %d offset %d",
					gotStart, gotOffset, wantStart, wantOffset)
			}
			// The guest finishes it, as it would on receipt. The error must
			// survive that too.
			assertErrorFrame(t, finishPartialChecksum(frame, gotStart, gotOffset), pkt, tt.v4, tt.proto)
		})
	}
}

// TestPMTU_TapGSOErrorCarriesNoGSOState covers a guest handing over a TCP
// packet still to be segmented, whose segments are each too big for the
// fabric. The error is rewritten from that packet, and must reach the guest as
// one plain ICMP packet: no GSO type or segment size left over from the TCP
// packet it replaced, which would make the guest try to segment an ICMP
// message as TCP.
func TestPMTU_TapGSOErrorCarriesNoGSOState(t *testing.T) {
	for _, tt := range []struct {
		name    string
		v4      bool
		gsoType byte
	}{
		{"IPv6", false, virtioNetHdrGSOTCPv6},
		{"IPv4", true, virtioNetHdrGSOTCPv4},
	} {
		t.Run(tt.name, func(t *testing.T) {
			objs, fd := newPMTUTap(t, tunOffloadCsum|tunOffloadTSO4|tunOffloadTSO6)

			// Two 1440-byte segments. Each makes a 1500-byte packet over IPv6
			// and a 1480-byte one over IPv4, both past the 1460 limit.
			const segPayload = 1440
			ipHdr := ip6HeaderLen
			if tt.v4 {
				ipHdr = 20
			}
			l3Len := ipHdr + 20 + 2*segPayload
			var pkt []byte
			if tt.v4 {
				pkt = v4Packet(ipProtoTCP, nil, true, l3Len)
			} else {
				pkt = v6Packet(mssPodV6, mssRemoteV6, ipProtoTCP, l3Len)
			}
			l4Off := ethHeaderLen + ipHdr
			writeGuestGSOFrame(t, fd, pkt, l4Off, 16, tt.gsoType, l4Off+20, segPayload)

			hdr, frame := readHostFrame(t, fd, binary.BigEndian.Uint16(pkt[12:14]))
			if hdr[1] != virtioNetHdrGSONone || binary.LittleEndian.Uint16(hdr[4:6]) != 0 {
				t.Errorf("error reached the guest with GSO type %d, segment size %d; want none",
					hdr[1], binary.LittleEndian.Uint16(hdr[4:6]))
			}
			if hdr[0]&virtioNetHdrFNeedsCsum != 0 {
				frame = finishPartialChecksum(frame, int(binary.LittleEndian.Uint16(hdr[6:8])),
					int(binary.LittleEndian.Uint16(hdr[8:10])))
			}
			assertErrorFrame(t, frame, pkt, tt.v4, ipProtoTCP)
			assertPMTUStats(t, objs, map[uint32]uint64{sentStat(tt.v4): 1})
		})
	}
}

// TestPMTU_TapGSOSegmentsThatFitAreEncapsulated is the control for the test
// above: the same merged packet with 1400-byte segments, each a 1460-byte
// IPv6 packet, gets no error, although the merged packet is far over the
// limit. It also proves the tap really hands the program a GSO packet.
func TestPMTU_TapGSOSegmentsThatFitAreEncapsulated(t *testing.T) {
	objs, fd := newPMTUTap(t, tunOffloadCsum|tunOffloadTSO4|tunOffloadTSO6)
	const segPayload = 1400
	pkt := v6Packet(mssPodV6, mssRemoteV6, ipProtoTCP, ip6HeaderLen+20+2*segPayload)
	l4Off := ethHeaderLen + ip6HeaderLen
	writeGuestGSOFrame(t, fd, pkt, l4Off, 16, virtioNetHdrGSOTCPv6, l4Off+20, segPayload)

	time.Sleep(200 * time.Millisecond)
	assertPMTUStats(t, objs, nil)
	// DROP_REASON_TRACE_REDIRECT_OK, a trace slot with no Go constant:
	// usid_egress reached its final redirect toward the fabric.
	const traceRedirectOK = 22
	if got := sumPerCPU(t, objs.DropReasons, traceRedirectOK); got != 1 {
		t.Errorf("drop_reasons[trace_redirect_ok] = %d, want 1: the packet should have been encapsulated", got)
	}
}

func tapTestPacket(v4 bool, proto byte) (pkt []byte, l4Off int) {
	if v4 {
		return v4Packet(proto, nil, true, 1500), ethHeaderLen + 20
	}
	return v6Packet(mssPodV6, mssRemoteV6, proto, 1500), ethHeaderLen + ip6HeaderLen
}

func partialCsumOffset(proto byte) int {
	if proto == ipProtoTCP {
		return 16
	}
	return 6
}

func sentStat(v4 bool) uint32 {
	if v4 {
		return PMTUStatFragNeededSentIPv4
	}
	return PMTUStatTooBigSentIPv6
}

func assertErrorFrame(t *testing.T, frame, pkt []byte, v4 bool, proto byte) {
	t.Helper()
	if v4 {
		assertFragNeeded4(t, frame, pkt, proto)
		assertQuote(t, frame, 20, pkt[ethHeaderLen:])
		return
	}
	assertTooBig6(t, frame, pkt, mssPodV6, proto)
	assertQuote(t, frame, ip6HeaderLen, pkt[ethHeaderLen:])
}

// TestPMTU_VethPodLearnsPathMTU is the issue's report end to end: a pod sends
// a packet too big for the fabric, and its own kernel accepts the error and
// lowers the route's MTU, so the next packet fits.
func TestPMTU_VethPodLearnsPathMTU(t *testing.T) {
	objs, podNS := newPMTUVethPod(t)

	// An ICMPv6 echo request's checksum is computed in software, so this
	// error's own checksum is checked by the pod's kernel rather than trusted.
	setNetns(t, podNS)
	sock, err := unix.Socket(unix.AF_INET6, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.IPPROTO_ICMPV6)
	if err != nil {
		t.Fatalf("open ICMPv6 socket: %v", err)
	}
	t.Cleanup(func() { _ = unix.Close(sock) })
	if err := unix.SetsockoptInt(sock, unix.IPPROTO_IPV6, unix.IPV6_MTU_DISCOVER, unix.IPV6_PMTUDISC_DO); err != nil {
		t.Fatalf("set IPV6_MTU_DISCOVER: %v", err)
	}
	echo := make([]byte, 1500-ip6HeaderLen)
	echo[0] = 128
	dst := &unix.SockaddrInet6{Addr: mssRemoteV6.As16()}
	if err := unix.Sendto(sock, echo, 0, dst); err != nil {
		t.Fatalf("send oversized echo request: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	var mtu int
	for time.Now().Before(deadline) {
		routes, err := netlink.RouteGet(mssRemoteV6.AsSlice())
		if err != nil {
			t.Fatalf("route get %v: %v", mssRemoteV6, err)
		}
		if len(routes) > 0 && routes[0].MTU != 0 {
			mtu = routes[0].MTU
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if mtu != testEncapMTU {
		t.Fatalf("pod's route MTU toward %v = %d, want %d learned from the Packet Too Big", mssRemoteV6, mtu, testEncapMTU)
	}

	// The next send at the old size now fails locally instead of vanishing.
	if err := unix.Sendto(sock, echo, 0, dst); !errors.Is(err, unix.EMSGSIZE) {
		t.Errorf("second 1500-byte send = %v, want EMSGSIZE now that the path MTU is known", err)
	}
	assertPMTUStats(t, objs, map[uint32]uint64{PMTUStatTooBigSentIPv6: 1})
}

// newPMTUVethPod builds a pod: a veth whose peer sits in its own namespace with
// an address and a default route through the gateway, and whose host side
// carries usid_egress, registered as a tenant attachment. It returns the
// loaded objects and the pod's namespace, with the calling thread in the host
// namespace.
func newPMTUVethPod(t *testing.T) (*UsidObjects, int) {
	t.Helper()
	requireRoot(t)

	runtime.LockOSThread()
	origNS := openThreadNetns(t)
	t.Cleanup(func() {
		if err := unix.Setns(origNS, unix.CLONE_NEWNET); err != nil {
			t.Errorf("restore original network namespace: %v", err)
			return
		}
		_ = unix.Close(origNS)
		runtime.UnlockOSThread()
	})
	if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
		t.Fatalf("unshare host namespace: %v", err)
	}
	hostNS := openThreadNetns(t)
	t.Cleanup(func() { _ = unix.Close(hostNS) })
	if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
		t.Fatalf("unshare pod namespace: %v", err)
	}
	podNS := openThreadNetns(t)
	t.Cleanup(func() { _ = unix.Close(podNS) })
	setNetns(t, hostNS)

	objs := loadObjects(t)

	veth := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "pmtuh0"}, PeerName: "pmtup0"}
	if err := netlink.LinkAdd(veth); err != nil {
		t.Fatalf("add veth pair: %v", err)
	}
	peer, err := netlink.LinkByName("pmtup0")
	if err != nil {
		t.Fatalf("look up veth peer: %v", err)
	}
	if err := netlink.LinkSetNsFd(peer, podNS); err != nil {
		t.Fatalf("move veth peer into the pod: %v", err)
	}
	host := setLinkUp(t, "pmtuh0")
	attachIngress(t, host, objs.UsidEgress)

	setNetns(t, podNS)
	if err := os.WriteFile("/proc/sys/net/ipv6/conf/pmtup0/accept_dad", []byte("0"), 0o644); err != nil {
		t.Fatalf("disable DAD: %v", err)
	}
	pod := setLinkUp(t, "pmtup0")
	addr, err := netlink.ParseAddr(mssPodV6.String() + "/64")
	if err != nil {
		t.Fatalf("parse pod address: %v", err)
	}
	addr.Flags = unix.IFA_F_NODAD
	if err := netlink.AddrAdd(pod, addr); err != nil {
		t.Fatalf("add pod address: %v", err)
	}
	if err := netlink.NeighAdd(&netlink.Neigh{
		LinkIndex: pod.Attrs().Index, Family: netlink.FAMILY_V6, State: netlink.NUD_PERMANENT,
		IP: pmtuGW6.AsSlice(), HardwareAddr: host.Attrs().HardwareAddr,
	}); err != nil {
		t.Fatalf("add gateway neighbor: %v", err)
	}
	if err := netlink.RouteAdd(&netlink.Route{LinkIndex: pod.Attrs().Index, Gw: pmtuGW6.AsSlice()}); err != nil {
		t.Fatalf("add pod default route: %v", err)
	}
	setNetns(t, hostNS)

	registerPMTUAttachment(t, objs, uint32(host.Attrs().Index), UsidTenantGwValue{Gw6: pmtuGW6.As16()})
	return objs, podNS
}
