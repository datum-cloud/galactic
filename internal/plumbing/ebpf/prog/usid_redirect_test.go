// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package prog

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// These tests drive real frames through usid_ingress into real tap and veth
// devices, because BPF_PROG_TEST_RUN reports TC_ACT_REDIRECT for either helper
// and never performs the redirect, so it cannot show which one delivers.

const (
	egressKindVeth uint32 = 0
	egressKindTap  uint32 = 1

	redirectLabTableID = 100

	// deliveryWait bounds how long a frame that should arrive may take.
	// quietWait bounds the check that a frame did not appear somewhere; the
	// redirect runs synchronously in softirq, so it is short.
	deliveryWait = 2 * time.Second
	quietWait    = 300 * time.Millisecond
)

var (
	tapInnerDst  = net.IPv4(10, 0, 1, 10).To4()
	vethInnerDst = net.IPv4(10, 0, 2, 10).To4()
	tapGuestMAC  = net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x01, 0x10}
)

// redirectLab is one private network namespace holding a tap standing in for
// the fabric uplink, with usid_ingress attached, plus one tap attachment and
// one veth attachment whose peer sits in a second namespace. Both attachments
// belong to the same VPC, that is, the same vrf_table entry.
type redirectLab struct {
	objs *UsidObjects

	labNS  int
	peerNS int

	uplinkFd  int
	uplinkMAC net.HardwareAddr

	tapIfindex uint32
	tapFd      int

	vethIfindex uint32
	// vethHostCapture sees frames transmitted on the host-side end, which only
	// plain bpf_redirect produces. vethPeerCapture sees frames arriving on the
	// peer inside its own namespace, which both helpers produce.
	vethHostCapture int
	vethPeerCapture int
}

func newRedirectLab(t *testing.T) *redirectLab {
	t.Helper()
	requireRoot(t)
	if _, err := os.Stat("/dev/net/tun"); err != nil {
		t.Skipf("test requires /dev/net/tun: %v", err)
	}

	// Netlink calls, tap creation, and sysctl writes all act on the calling
	// thread's namespace, so this goroutine stays pinned to one thread for the
	// whole test. If the thread cannot be moved back it is left locked, which
	// makes the runtime discard it rather than reuse it.
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
		t.Fatalf("unshare lab network namespace: %v", err)
	}
	labNS := openThreadNetns(t)
	t.Cleanup(func() { _ = unix.Close(labNS) })
	if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
		t.Fatalf("unshare peer network namespace: %v", err)
	}
	peerNS := openThreadNetns(t)
	t.Cleanup(func() { _ = unix.Close(peerNS) })
	setNetns(t, labNS)

	lab := &redirectLab{objs: loadObjects(t), labNS: labNS, peerNS: peerNS}

	var uplink netlink.Link
	lab.uplinkFd, uplink = openTap(t, "up0")
	lab.uplinkMAC = uplink.Attrs().HardwareAddr

	var tapLink netlink.Link
	lab.tapFd, tapLink = openTap(t, "dt0")
	lab.tapIfindex = uint32(tapLink.Attrs().Index)

	if err := netlink.LinkAdd(&netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "dv0"}, PeerName: "dv1"}); err != nil {
		t.Fatalf("add veth pair: %v", err)
	}
	peer, err := netlink.LinkByName("dv1")
	if err != nil {
		t.Fatalf("look up veth peer: %v", err)
	}
	if err := netlink.LinkSetNsFd(peer, peerNS); err != nil {
		t.Fatalf("move veth peer into its namespace: %v", err)
	}
	setNetns(t, peerNS)
	peer = setLinkUp(t, "dv1")
	lab.vethPeerCapture = openCapture(t, peer.Attrs().Index)
	setNetns(t, labNS)
	vethHost := setLinkUp(t, "dv0")
	lab.vethIfindex = uint32(vethHost.Attrs().Index)
	lab.vethHostCapture = openCapture(t, vethHost.Attrs().Index)

	// bpf_fib_lookup refuses to resolve a route for a packet whose ingress
	// device does not forward.
	for _, path := range []string{
		"/proc/sys/net/ipv4/conf/all/forwarding",
		"/proc/sys/net/ipv4/conf/up0/forwarding",
		"/proc/sys/net/ipv6/conf/all/forwarding",
		"/proc/sys/net/ipv6/conf/up0/forwarding",
	} {
		if err := os.WriteFile(path, []byte("1"), 0o644); err != nil {
			t.Fatalf("enable forwarding via %s: %v", path, err)
		}
	}

	addHostRoute(t, tapLink, tapInnerDst, tapGuestMAC)
	addHostRoute(t, vethHost, vethInnerDst, peer.Attrs().HardwareAddr)
	attachIngress(t, uplink, lab.objs.UsidIngress)

	if err := lab.objs.LocatorTable.Put(baseUSID.locatorKey(t), UsidLocatorValue{Generation: 1}); err != nil {
		t.Fatalf("populate locator_table: %v", err)
	}
	if err := lab.objs.FunctionTable.Put(baseUSID.functionKey(t), UsidFunctionValue{Behavior: 1}); err != nil {
		t.Fatalf("populate function_table: %v", err)
	}
	return lab
}

// registerAttachment writes what CNI ADD writes for one attachment. vrf_table's
// entry is shared by the whole VPC, so it keeps only the last writer's kind.
func (lab *redirectLab) registerAttachment(t *testing.T, ifindex, kind uint32) {
	t.Helper()
	value := UsidVrfValue{VrfTableId: redirectLabTableID, EgressKind: kind}
	if err := lab.objs.VrfTable.Put(baseUSID.vrfKey(), value); err != nil {
		t.Fatalf("populate vrf_table: %v", err)
	}
	lab.putEgressKind(t, ifindex, kind)
}

func (lab *redirectLab) putEgressKind(t *testing.T, ifindex, kind uint32) {
	t.Helper()
	if err := lab.objs.IfindexEgressKindTable.Put(ifindex, kind); err != nil {
		t.Fatalf("populate ifindex_egress_kind_table[%d]: %v", ifindex, err)
	}
}

func (lab *redirectLab) deleteEgressKind(t *testing.T, ifindex uint32) {
	t.Helper()
	if err := lab.objs.IfindexEgressKindTable.Delete(ifindex); err != nil {
		t.Fatalf("delete ifindex_egress_kind_table[%d]: %v", ifindex, err)
	}
}

func (lab *redirectLab) registerTap(t *testing.T) {
	lab.registerAttachment(t, lab.tapIfindex, egressKindTap)
}
func (lab *redirectLab) registerVeth(t *testing.T) {
	lab.registerAttachment(t, lab.vethIfindex, egressKindVeth)
}

// assertTapDelivers sends one encapsulated frame toward the tap attachment and
// requires it to come out of the tap.
func (lab *redirectLab) assertTapDelivers(t *testing.T, label string) {
	t.Helper()
	marker := lab.send(t, tapInnerDst, label)
	if !awaitMarker(t, lab.tapFd, marker, deliveryWait, readTap) {
		t.Errorf("%s: frame for the tap attachment never reached the tap", label)
	}
}

// assertVethDelivers sends one encapsulated frame toward the veth attachment,
// requires it to arrive in the peer's namespace, and checks which helper
// carried it there: bpf_redirect_peer never transmits on the host-side end.
func (lab *redirectLab) assertVethDelivers(t *testing.T, label string, wantPeerRedirect bool) {
	t.Helper()
	lab.assertVethDeliversTo(t, vethInnerDst, label, wantPeerRedirect)
}

// assertVethDeliversTo is assertVethDelivers for any inner destination routed
// to the veth attachment, of either family.
func (lab *redirectLab) assertVethDeliversTo(t *testing.T, innerDst net.IP, label string, wantPeerRedirect bool) {
	t.Helper()
	marker := lab.send(t, innerDst, label)
	if !awaitMarker(t, lab.vethPeerCapture, marker, deliveryWait, readCapture(false)) {
		t.Errorf("%s: frame for the veth attachment never reached the peer namespace", label)
		return
	}
	sawHostTransmit := awaitMarker(t, lab.vethHostCapture, marker, quietWait, readCapture(true))
	switch {
	case wantPeerRedirect && sawHostTransmit:
		t.Errorf("%s: frame was transmitted on the host-side veth, want bpf_redirect_peer", label)
	case !wantPeerRedirect && !sawHostTransmit:
		t.Errorf("%s: frame was not transmitted on the host-side veth, want plain bpf_redirect", label)
	}
}

// A VPC with a tap and a veth attachment on one node delivers to both whichever
// registers last. Before the per-interface map, the last veth registration
// switched the whole VPC to bpf_redirect_peer and black-holed the tap.
func TestUsidIngress_MixedEgressKindsInOneVPCDeliverInEitherOrder(t *testing.T) {
	for _, tt := range []struct {
		name     string
		tapFirst bool
	}{
		{name: "tap then veth", tapFirst: true},
		{name: "veth then tap", tapFirst: false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			lab := newRedirectLab(t)
			if tt.tapFirst {
				lab.registerTap(t)
				lab.registerVeth(t)
			} else {
				lab.registerVeth(t)
				lab.registerTap(t)
			}
			lab.assertTapDelivers(t, "tap")
			lab.assertVethDelivers(t, "veth", true)
		})
	}
}

// An attachment registered before ifindex_egress_kind_table existed has no
// entry. Its traffic takes plain bpf_redirect, which still reaches a veth's
// peer namespace, whatever kind vrf_table holds.
func TestUsidIngress_MissingEgressKindFallsBackToPlainRedirect(t *testing.T) {
	lab := newRedirectLab(t)
	// EGRESS_KIND_VETH is the vrf_table value that used to black-hole taps.
	value := UsidVrfValue{VrfTableId: redirectLabTableID, EgressKind: egressKindVeth}
	if err := lab.objs.VrfTable.Put(baseUSID.vrfKey(), value); err != nil {
		t.Fatalf("populate vrf_table: %v", err)
	}
	lab.assertTapDelivers(t, "tap without entry")
	lab.assertVethDelivers(t, "veth without entry", false)
}

// Removing one attachment's entry, as its DEL does, leaves the other's
// redirect choice untouched.
func TestUsidIngress_RemovingOneEgressKindLeavesSiblingIntact(t *testing.T) {
	t.Run("remove tap", func(t *testing.T) {
		lab := newRedirectLab(t)
		lab.registerTap(t)
		lab.registerVeth(t)
		lab.deleteEgressKind(t, lab.tapIfindex)
		lab.assertVethDelivers(t, "veth after tap removal", true)
	})
	t.Run("remove veth", func(t *testing.T) {
		lab := newRedirectLab(t)
		lab.registerVeth(t)
		lab.registerTap(t)
		lab.deleteEgressKind(t, lab.vethIfindex)
		var kind uint32
		if err := lab.objs.IfindexEgressKindTable.Lookup(lab.tapIfindex, &kind); err != nil {
			t.Fatalf("look up tap's ifindex_egress_kind_table entry after veth removal: %v", err)
		}
		if kind != egressKindTap {
			t.Errorf("tap's egress kind after veth removal = %d, want %d", kind, egressKindTap)
		}
		lab.assertTapDelivers(t, "tap after veth removal")
	})
}

// The kernel garbage-collects a STALE neighbor entry nothing has used, and the
// redirect never makes the kernel resolve one. A lookup that finds the route
// but no neighbor must hand the packet to the kernel to resolve, rather than
// drop every packet to the attachment until it sends its own solicitation, and
// the entry that resolution creates must put the next packet back on the
// bpf_redirect_peer fast path.
func TestUsidIngress_MissingNeighborResolvesInsteadOfDropping(t *testing.T) {
	for _, tt := range []struct {
		name     string
		hostAddr string
		peerAddr string
	}{
		{name: "inner IPv4", hostAddr: "10.0.3.1/24", peerAddr: "10.0.3.10/24"},
		{name: "inner IPv6", hostAddr: "fd00:3::1/64", peerAddr: "fd00:3::10/64"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			lab := newRedirectLab(t)
			lab.registerVeth(t)
			dst := lab.addUnresolvedVethHost(t, tt.hostAddr, tt.peerAddr)

			lab.assertVethDeliversTo(t, dst, "unresolved", false)
			if got := sumPerCPU(t, lab.objs.DropReasons, DropReasonFibNoNeigh); got != 0 {
				t.Errorf("drop_reasons[fib_no_neigh] = %d, want 0: the fallback must take the packet", got)
			}
			if !neighborValid(t, lab.vethIfindex, dst) {
				t.Fatalf("no valid neighbor entry for %s after the first frame, want one resolved by the kernel", dst)
			}
			lab.assertVethDeliversTo(t, dst, "resolved", true)
		})
	}
}

// A tap is the attachment this matters most for: CNI ADD primes a permanent
// neighbor entry for a veth's pod, but a tap's guest has no link in the host
// namespace to read a MAC from, so its entry is only ever learned dynamically
// and is always eligible for garbage collection. The kernel solicits the guest
// through the tap, and this test answers as the guest would.
func TestUsidIngress_MissingTapNeighborResolvesInsteadOfDropping(t *testing.T) {
	guestMAC := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x04, 0x10}
	for _, tt := range []struct {
		name     string
		hostAddr string
		guest    string
	}{
		{name: "inner IPv4", hostAddr: "10.0.4.1/24", guest: "10.0.4.10"},
		{name: "inner IPv6", hostAddr: "fd00:4::1/64", guest: "fd00:4::10"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			lab := newRedirectLab(t)
			lab.registerTap(t)
			addLinkAddr(t, "dt0", tt.hostAddr)
			dst := net.ParseIP(tt.guest)
			if dst.To4() == nil {
				awaitLinkLocal(t, lab.tapIfindex)
			}
			routeUnresolved(t, lab.tapIfindex, dst)

			marker := lab.send(t, dst, "unresolved")
			if !lab.awaitTapMarkerAnswering(t, marker, dst, guestMAC) {
				t.Fatalf("frame for the tap attachment never reached the tap")
			}
			if got := sumPerCPU(t, lab.objs.DropReasons, DropReasonFibNoNeigh); got != 0 {
				t.Errorf("drop_reasons[fib_no_neigh] = %d, want 0: the fallback must take the packet", got)
			}
			if !neighborValid(t, lab.tapIfindex, dst) {
				t.Fatalf("no valid neighbor entry for %s after the first frame, want one resolved by the kernel", dst)
			}
			marker = lab.send(t, dst, "resolved")
			if !awaitMarker(t, lab.tapFd, marker, deliveryWait, readTap) {
				t.Errorf("frame for the resolved tap attachment never reached the tap")
			}
		})
	}
}

// awaitTapMarkerAnswering reads frames from the tap until one carries marker,
// answering any ARP request or Neighbor Solicitation for guest with guestMAC
// on the way, as the guest behind the tap would.
func (lab *redirectLab) awaitTapMarkerAnswering(
	t *testing.T, marker []byte, guest net.IP, guestMAC net.HardwareAddr,
) bool {
	t.Helper()
	deadline := time.Now().Add(deliveryWait)
	buf := make([]byte, 65536)
	for time.Now().Before(deadline) {
		fds := []unix.PollFd{{Fd: int32(lab.tapFd), Events: unix.POLLIN}}
		ready, err := unix.Poll(fds, int(time.Until(deadline).Milliseconds())+1)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			t.Fatalf("poll tap: %v", err)
		}
		if ready == 0 {
			return false
		}
		n, err := unix.Read(lab.tapFd, buf)
		if err != nil {
			t.Fatalf("read tap: %v", err)
		}
		frame := buf[:n]
		if bytes.Contains(frame, marker) {
			return true
		}
		if reply := resolutionReply(frame, guest, guestMAC); reply != nil {
			if _, err := unix.Write(lab.tapFd, reply); err != nil {
				t.Fatalf("write resolution reply into tap: %v", err)
			}
		}
	}
	return false
}

// resolutionReply returns the ARP reply or Neighbor Advertisement answering
// frame for guest, or nil if frame is not a request for guest.
func resolutionReply(frame []byte, guest net.IP, guestMAC net.HardwareAddr) []byte {
	if len(frame) < ethHeaderLen {
		return nil
	}
	requester := frame[6:12]
	switch binary.BigEndian.Uint16(frame[12:14]) {
	case unix.ETH_P_ARP:
		arp := frame[ethHeaderLen:]
		if len(arp) < 28 || binary.BigEndian.Uint16(arp[6:8]) != 1 || !net.IP(arp[24:28]).Equal(guest) {
			return nil
		}
		reply := make([]byte, 0, ethHeaderLen+28)
		reply = append(reply, requester...)
		reply = append(reply, guestMAC...)
		reply = append(reply, 0x08, 0x06)
		reply = append(reply, 0x00, 0x01, 0x08, 0x00, 6, 4, 0x00, 0x02) // Ethernet, IPv4, reply
		reply = append(reply, guestMAC...)
		reply = append(reply, guest.To4()...)
		reply = append(reply, arp[8:14]...)  // requester's hardware address
		reply = append(reply, arp[14:18]...) // requester's protocol address
		return reply
	case unix.ETH_P_IPV6:
		ip6 := frame[ethHeaderLen:]
		const nsLen = 24 // type, code, checksum, reserved, target
		if len(ip6) < ip6HeaderLen+nsLen || ip6[6] != ipProtoICMPv6 || ip6[ip6HeaderLen] != 135 ||
			!net.IP(ip6[ip6HeaderLen+8:ip6HeaderLen+24]).Equal(guest) {
			return nil
		}
		src, _ := netip.AddrFromSlice(guest.To16())
		dst, _ := netip.AddrFromSlice(ip6[8:24])
		na := make([]byte, 0, 32)
		na = append(na, 136, 0, 0, 0, 0x60, 0, 0, 0) // Neighbor Advertisement, solicited and override
		na = append(na, guest.To16()...)
		na = append(na, 2, 1) // target link-layer address option, 8 bytes
		na = append(na, guestMAC...)
		sum := onesComplementSum(0, src.AsSlice())
		sum = onesComplementSum(sum, dst.AsSlice())
		sum += uint32(len(na)) + ipProtoICMPv6
		binary.BigEndian.PutUint16(na[2:4], ^fold(onesComplementSum(sum, na)))

		reply := make([]byte, 0, ethHeaderLen+ip6HeaderLen+len(na))
		reply = append(reply, requester...)
		reply = append(reply, guestMAC...)
		reply = append(reply, 0x86, 0xDD)
		reply = append(reply, 0x60, 0, 0, 0, 0, byte(len(na)), ipProtoICMPv6, 255)
		reply = append(reply, src.AsSlice()...)
		reply = append(reply, dst.AsSlice()...)
		return append(reply, na...)
	}
	return nil
}

// addUnresolvedVethHost addresses both ends of the veth and routes the peer's
// address to the host-side end in the lab's VRF table, with no neighbor entry,
// which is what the kernel leaves behind once it garbage-collects one. The
// host-side address gives the kernel a source for its solicitation, and the
// peer's lets the peer answer it. It returns the peer's address.
func (lab *redirectLab) addUnresolvedVethHost(t *testing.T, hostCIDR, peerCIDR string) net.IP {
	t.Helper()
	setNetns(t, lab.peerNS)
	dst := addLinkAddr(t, "dv1", peerCIDR)
	setNetns(t, lab.labNS)
	addLinkAddr(t, "dv0", hostCIDR)
	if dst.To4() == nil {
		awaitLinkLocal(t, lab.vethIfindex)
	}
	routeUnresolved(t, lab.vethIfindex, dst)
	return dst
}

// addLinkAddr assigns cidr to the named link in the current namespace and
// returns its address.
func addLinkAddr(t *testing.T, name, cidr string) net.IP {
	t.Helper()
	link, err := netlink.LinkByName(name)
	if err != nil {
		t.Fatalf("look up %s: %v", name, err)
	}
	addr, err := netlink.ParseAddr(cidr)
	if err != nil {
		t.Fatalf("parse %s: %v", cidr, err)
	}
	// Skip duplicate address detection, so the address can send and answer
	// solicitations at once rather than after it.
	addr.Flags = unix.IFA_F_NODAD
	if err := netlink.AddrAdd(link, addr); err != nil {
		t.Fatalf("address %s with %s: %v", name, cidr, err)
	}
	return addr.IP
}

// routeUnresolved routes dst to ifindex in the lab's VRF table, with no
// neighbor entry for it.
func routeUnresolved(t *testing.T, ifindex uint32, dst net.IP) {
	t.Helper()
	bits := 128
	if dst.To4() != nil {
		bits = 32
	}
	route := &netlink.Route{
		LinkIndex: int(ifindex),
		Dst:       &net.IPNet{IP: dst, Mask: net.CIDRMask(bits, bits)},
		Table:     redirectLabTableID,
		Scope:     netlink.SCOPE_LINK,
	}
	if err := netlink.RouteAdd(route); err != nil {
		t.Fatalf("add route to %s via ifindex %d: %v", dst, ifindex, err)
	}
}

// awaitLinkLocal waits for the link's link-local address to finish duplicate
// address detection. The kernel sends a Neighbor Solicitation only from a
// usable link-local address, and a link brought up moments ago still has a
// tentative one, so resolution would stall here where it never does on a node
// whose attachment has been up for longer than a second.
func awaitLinkLocal(t *testing.T, ifindex uint32) {
	t.Helper()
	link := &netlink.Device{LinkAttrs: netlink.LinkAttrs{Index: int(ifindex)}}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		addrs, err := netlink.AddrList(link, netlink.FAMILY_V6)
		if err != nil {
			t.Fatalf("list addresses on ifindex %d: %v", ifindex, err)
		}
		for _, a := range addrs {
			if a.IP.IsLinkLocalUnicast() && a.Flags&unix.IFA_F_TENTATIVE == 0 {
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("ifindex %d's link-local address was still tentative after 5s", ifindex)
}

// neighborValid reports whether ifindex has a neighbor entry for dst in a
// state bpf_fib_lookup accepts.
func neighborValid(t *testing.T, ifindex uint32, dst net.IP) bool {
	t.Helper()
	family := netlink.FAMILY_V6
	if dst.To4() != nil {
		family = netlink.FAMILY_V4
	}
	neighs, err := netlink.NeighList(int(ifindex), family)
	if err != nil {
		t.Fatalf("list neighbors on ifindex %d: %v", ifindex, err)
	}
	const valid = netlink.NUD_PERMANENT | netlink.NUD_NOARP | netlink.NUD_REACHABLE |
		netlink.NUD_STALE | netlink.NUD_DELAY | netlink.NUD_PROBE
	for _, n := range neighs {
		if n.IP.Equal(dst) && n.State&valid != 0 {
			return true
		}
	}
	return false
}

// send writes one SRv6 frame addressed to baseUSID, carrying an inner packet
// to innerDst, into the uplink tap, and returns the payload marker to look for
// on the far side. The inner packet is IPv4 or IPv6 to match innerDst.
func (lab *redirectLab) send(t *testing.T, innerDst net.IP, label string) []byte {
	t.Helper()
	marker := fmt.Appendf(nil, "galactic-egress-kind:%s:%d", label, time.Now().UnixNano())
	payload := make([]byte, 64)
	copy(payload, marker)

	var inner []byte
	var outerNextHdr byte
	if dst4 := innerDst.To4(); dst4 != nil {
		outerNextHdr = 4 // IPv4-in-IPv6
		totLen := uint16(20 + len(payload))
		inner = append(inner, 0x45, 0x00, byte(totLen>>8), byte(totLen), 0x00, 0x00, 0x40, 0x00)
		inner = append(inner, 64, 253, 0x00, 0x00) // ttl, experimental protocol, checksum unchecked here
		inner = append(inner, 192, 0, 2, 1)
		inner = append(inner, dst4...)
	} else {
		outerNextHdr = 41 // IPv6-in-IPv6
		payloadLen := uint16(len(payload))
		inner = append(inner, 0x60, 0x00, 0x00, 0x00, byte(payloadLen>>8), byte(payloadLen), 253, 64)
		src := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x02, 15: 0x01}
		inner = append(inner, src[:]...)
		inner = append(inner, innerDst.To16()...)
	}
	inner = append(inner, payload...)

	frame := make([]byte, 0, ethHeaderLen+ip6HeaderLen+len(inner))
	frame = append(frame, lab.uplinkMAC...)
	frame = append(frame, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x86, 0xDD)
	frame = append(frame, 0x60, 0x00, 0x00, 0x00, byte(len(inner)>>8), byte(len(inner)), outerNextHdr, 64)
	src := [16]byte{0x20, 0x01, 0x0d, 0xb8, 15: 0x01}
	frame = append(frame, src[:]...)
	dst := baseUSID.addr(t).As16()
	frame = append(frame, dst[:]...)
	frame = append(frame, inner...)

	if _, err := unix.Write(lab.uplinkFd, frame); err != nil {
		t.Fatalf("write frame into uplink tap: %v", err)
	}
	return marker
}

type frameReader func(fd int, buf []byte) (n int, accept bool, err error)

func readTap(fd int, buf []byte) (int, bool, error) {
	n, err := unix.Read(fd, buf)
	return n, true, err
}

// readCapture reads one frame from an AF_PACKET socket. outgoingOnly keeps just
// the frames its interface transmitted.
func readCapture(outgoingOnly bool) frameReader {
	return func(fd int, buf []byte) (int, bool, error) {
		n, from, err := unix.Recvfrom(fd, buf, unix.MSG_DONTWAIT)
		if err != nil || !outgoingOnly {
			return n, true, err
		}
		ll, ok := from.(*unix.SockaddrLinklayer)
		return n, ok && ll.Pkttype == unix.PACKET_OUTGOING, nil
	}
}

// awaitMarker reports whether a frame containing marker is read from fd within
// wait. Unrelated frames, such as IPv6 neighbor discovery, are skipped.
func awaitMarker(t *testing.T, fd int, marker []byte, wait time.Duration, read frameReader) bool {
	t.Helper()
	deadline := time.Now().Add(wait)
	buf := make([]byte, 65536)
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return false
		}
		fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		ready, err := unix.Poll(fds, int(remaining.Milliseconds())+1)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			t.Fatalf("poll fd %d: %v", fd, err)
		}
		if ready == 0 {
			return false
		}
		n, accept, err := read(fd, buf)
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			t.Fatalf("read fd %d: %v", fd, err)
		}
		if accept && bytes.Contains(buf[:n], marker) {
			return true
		}
	}
}

func openThreadNetns(t *testing.T) int {
	t.Helper()
	fd, err := unix.Open("/proc/thread-self/ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("open thread network namespace: %v", err)
	}
	return fd
}

func setNetns(t *testing.T, fd int) {
	t.Helper()
	if err := unix.Setns(fd, unix.CLONE_NEWNET); err != nil {
		t.Fatalf("setns: %v", err)
	}
}

// openTap creates a non-persistent tap owned by the returned descriptor and
// brings it up. Holding the descriptor open is what gives the tap carrier.
func openTap(t *testing.T, name string) (int, netlink.Link) {
	t.Helper()
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("open /dev/net/tun: %v", err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		t.Fatalf("ifreq for %s: %v", name, err)
	}
	ifr.SetUint16(unix.IFF_TAP | unix.IFF_NO_PI)
	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
		t.Fatalf("create tap %s: %v", name, err)
	}
	return fd, setLinkUp(t, name)
}

func setLinkUp(t *testing.T, name string) netlink.Link {
	t.Helper()
	link, err := netlink.LinkByName(name)
	if err != nil {
		t.Fatalf("look up %s: %v", name, err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		t.Fatalf("set %s up: %v", name, err)
	}
	if link, err = netlink.LinkByName(name); err != nil {
		t.Fatalf("re-read %s: %v", name, err)
	}
	return link
}

func openCapture(t *testing.T, ifindex int) int {
	t.Helper()
	proto := bswap16(unix.ETH_P_ALL)
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(proto))
	if err != nil {
		t.Fatalf("open packet socket: %v", err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: proto, Ifindex: ifindex}); err != nil {
		t.Fatalf("bind packet socket to ifindex %d: %v", ifindex, err)
	}
	return fd
}

// addHostRoute installs a /32 route and a permanent neighbor for dst in the
// lab's VRF table, so bpf_fib_lookup resolves both the egress interface and
// the destination MAC without any address resolution traffic.
func addHostRoute(t *testing.T, link netlink.Link, dst net.IP, mac net.HardwareAddr) {
	t.Helper()
	route := &netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       &net.IPNet{IP: dst, Mask: net.CIDRMask(32, 32)},
		Table:     redirectLabTableID,
		Scope:     netlink.SCOPE_LINK,
	}
	if err := netlink.RouteAdd(route); err != nil {
		t.Fatalf("add route to %s via %s: %v", dst, link.Attrs().Name, err)
	}
	neigh := &netlink.Neigh{
		LinkIndex:    link.Attrs().Index,
		Family:       netlink.FAMILY_V4,
		State:        netlink.NUD_PERMANENT,
		IP:           dst,
		HardwareAddr: mac,
	}
	if err := netlink.NeighAdd(neigh); err != nil {
		t.Fatalf("add neighbor %s on %s: %v", dst, link.Attrs().Name, err)
	}
}

func attachIngress(t *testing.T, link netlink.Link, program *ebpf.Program) {
	t.Helper()
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}
	if err := netlink.QdiscAdd(qdisc); err != nil {
		t.Fatalf("add clsact qdisc to %s: %v", link.Attrs().Name, err)
	}
	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_INGRESS,
			Handle:    netlink.MakeHandle(0, 1),
			Protocol:  unix.ETH_P_ALL,
			Priority:  1,
		},
		Fd:           program.FD(),
		Name:         "usid_ingress_test",
		DirectAction: true,
	}
	if err := netlink.FilterAdd(filter); err != nil {
		t.Fatalf("attach usid_ingress to %s: %v", link.Attrs().Name, err)
	}
}
