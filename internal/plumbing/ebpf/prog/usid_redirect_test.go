// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package prog

import (
	"bytes"
	"errors"
	"fmt"
	"net"
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

	lab := &redirectLab{objs: loadObjects(t)}

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
	marker := lab.send(t, vethInnerDst, label)
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

// send writes one SRv6 frame addressed to baseUSID, carrying an inner IPv4
// packet to innerDst, into the uplink tap, and returns the payload marker to
// look for on the far side.
func (lab *redirectLab) send(t *testing.T, innerDst net.IP, label string) []byte {
	t.Helper()
	marker := []byte(fmt.Sprintf("galactic-egress-kind:%s:%d", label, time.Now().UnixNano()))
	payload := make([]byte, 64)
	copy(payload, marker)

	inner := make([]byte, 0, 20+len(payload))
	totLen := uint16(20 + len(payload))
	inner = append(inner, 0x45, 0x00, byte(totLen>>8), byte(totLen), 0x00, 0x00, 0x40, 0x00)
	inner = append(inner, 64, 253, 0x00, 0x00) // ttl, experimental protocol, checksum unchecked here
	inner = append(inner, 192, 0, 2, 1)
	inner = append(inner, innerDst...)
	inner = append(inner, payload...)

	frame := make([]byte, 0, ethHeaderLen+ip6HeaderLen+len(inner))
	frame = append(frame, lab.uplinkMAC...)
	frame = append(frame, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x86, 0xDD)
	frame = append(frame, 0x60, 0x00, 0x00, 0x00, byte(len(inner)>>8), byte(len(inner)), 4, 64)
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
