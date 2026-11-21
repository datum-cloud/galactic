// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package natprog

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// These tests cover Local shard delivery (Galactic Worker's local.veth_pair
// handoff): a tenant on the shard's own node reaches the shard bare through
// its VPC's veth pair, whose NAT end nat_ingress runs on, and its replies go
// back into that pair rather than over the fabric.
//
// Each test runs in a private network namespace holding the pairs, a dummy
// uplink with a default route through a permanent neighbor, and, where a test
// needs it, a VLAN on that uplink. Packets are fed in with a test run whose
// context names the receiving interface, which is how the program tells a
// pair's NAT end from an uplink.

// xdpMD mirrors struct xdp_md for a test run's context.
type xdpMD struct {
	Data           uint32
	DataEnd        uint32
	DataMeta       uint32
	IngressIfindex uint32
	RxQueueIndex   uint32
	EgressIfindex  uint32
}

var (
	localShardSID = netip.MustParseAddr("fc00:9:9:9::")
	localPub6     = netip.MustParseAddr("2001:db8:9999::1")
	localPub4     = netip.MustParseAddr("192.0.2.10")
	localNSP      = netip.MustParseAddr("2001:db8:64::")
	localGuest    = netip.MustParseAddr("fd20::5")
	localDest6    = netip.MustParseAddr("2001:db8:1234::1")
	localDest4    = netip.MustParseAddr("8.8.8.8")
	localGwMAC    = net.HardwareAddr{0x02, 0, 0, 0, 0, 0x01}
)

const localGuestPort, localDestPort = 40000, 443

// tenantSID is this node's source SID completed with argument, as Worker
// reports it for a VPC's pair.
func tenantSID(argument uint16) netip.Addr {
	b := netip.MustParseAddr("fc00:0:1:1::").As16()
	b[8] = (b[8] & 0xF0) | byte(argument>>8&0x0F)
	b[9] = byte(argument)
	return netip.AddrFrom16(b)
}

type localPair struct {
	nat, tenant netlink.Link
	sid         netip.Addr
}

type localNet struct {
	objs *NatObjects
	up0  netlink.Link
}

func writeSysctl(t *testing.T, path, value string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(value), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// newLocalNet enters a private network namespace for the rest of the test
// and builds the uplink there.
func newLocalNet(t *testing.T) *localNet {
	t.Helper()
	requireRoot(t)
	runtime.LockOSThread()
	orig := openThreadNetns(t)
	if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
		_ = unix.Close(orig)
		runtime.UnlockOSThread()
		t.Fatalf("unshare network namespace: %v", err)
	}
	t.Cleanup(func() {
		setNetns(t, orig)
		_ = unix.Close(orig)
		runtime.UnlockOSThread()
	})

	setLinkUp(t, "lo")
	if err := netlink.LinkAdd(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "up0"}}); err != nil {
		t.Fatalf("add up0: %v", err)
	}
	up0 := setLinkUp(t, "up0")
	addLinkAddr(t, up0, netip.MustParseAddr("2001:db8:ff::2"), 64)
	addLinkAddr(t, up0, netip.MustParseAddr("10.99.0.2"), 24)
	gw6 := netip.MustParseAddr("fe80::1")
	gw4 := netip.MustParseAddr("10.99.0.1")
	for _, gw := range []netip.Addr{gw6, gw4} {
		family := netlink.FAMILY_V6
		if gw.Is4() {
			family = netlink.FAMILY_V4
		}
		if err := netlink.NeighSet(&netlink.Neigh{LinkIndex: up0.Attrs().Index, Family: family,
			State: netlink.NUD_PERMANENT, IP: gw.AsSlice(), HardwareAddr: localGwMAC}); err != nil {
			t.Fatalf("add neighbor %s: %v", gw, err)
		}
	}
	for _, r := range []netlink.Route{
		{LinkIndex: up0.Attrs().Index, Dst: &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)},
			Gw: gw6.AsSlice()},
		{LinkIndex: up0.Attrs().Index, Dst: &net.IPNet{IP: net.IPv4zero.To4(), Mask: net.CIDRMask(0, 32)},
			Gw: gw4.AsSlice()},
	} {
		if err := netlink.RouteAdd(&r); err != nil {
			t.Fatalf("add route %v: %v", r.Dst, err)
		}
	}

	objs := loadObjects(t)
	if err := objs.ShardConfigTable.Put(uint32(0), NatShardConfig{
		ShardSid: localShardSID.As16(), ShardPubAddr6: localPub6.As16(), Nat64Prefix: localNSP.As16(),
		ShardPubAddr4: v4ToWire(localPub4), ServesV6: 1, ServesV4: 1,
	}); err != nil {
		t.Fatalf("populate shard_config_table: %v", err)
	}
	return &localNet{objs: objs, up0: up0}
}

// addPair creates a veth pair, turns forwarding on, and writes its rows.
func (n *localNet) addPair(t *testing.T, name string, sid netip.Addr) localPair {
	t.Helper()
	if err := netlink.LinkAdd(&netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: name + "n"},
		PeerName: name + "t"}); err != nil {
		t.Fatalf("add pair %s: %v", name, err)
	}
	p := localPair{nat: setLinkUp(t, name+"n"), tenant: setLinkUp(t, name+"t"), sid: sid}
	writeSysctl(t, "/proc/sys/net/ipv6/conf/all/forwarding", "1")
	writeSysctl(t, "/proc/sys/net/ipv4/ip_forward", "1")
	writeSysctl(t, fmt.Sprintf("/proc/sys/net/ipv4/conf/%s/forwarding", name+"n"), "1")
	n.putRows(t, p)
	return p
}

func (n *localNet) putRows(t *testing.T, p localPair) {
	t.Helper()
	rv := NatNatLocalReturnValue{Ifindex: uint32(p.nat.Attrs().Index)}
	copy(rv.Smac[:], p.nat.Attrs().HardwareAddr)
	copy(rv.Dmac[:], p.tenant.Attrs().HardwareAddr)
	if err := n.objs.NatLocalReturn.Put(NatNatLocalReturnKey{TenantSid: p.sid.As16()}, rv); err != nil {
		t.Fatalf("put nat_local_return: %v", err)
	}
	if err := n.objs.NatLocalPair.Put(uint32(p.nat.Attrs().Index),
		NatNatLocalPairValue{TenantSid: p.sid.As16()}); err != nil {
		t.Fatalf("put nat_local_pair: %v", err)
	}
}

// run feeds frame to nat_ingress as received on ifindex.
func (n *localNet) run(t *testing.T, frame []byte, ifindex int) (uint32, []byte) {
	t.Helper()
	opts := &ebpf.RunOptions{
		Data:    frame,
		DataOut: make([]byte, len(frame)+256),
		Context: xdpMD{DataEnd: uint32(len(frame)), IngressIfindex: uint32(ifindex)},
	}
	ret, err := n.objs.NatIngress.Run(opts)
	if err != nil {
		t.Fatalf("test run on ifindex %d: %v", ifindex, err)
	}
	return ret, opts.DataOut
}

func (n *localNet) localStat(t *testing.T, s LocalStat) uint64 {
	t.Helper()
	return sumPerCPU(t, n.objs.NatLocalStats, uint32(s))
}

// tcp6Segment builds a TCP header with flags and a correct checksum.
func tcp6Segment(src, dst netip.Addr, sport, dport uint16, flags byte) []byte {
	seg := make([]byte, 20)
	binary.BigEndian.PutUint16(seg[0:2], sport)
	binary.BigEndian.PutUint16(seg[2:4], dport)
	binary.BigEndian.PutUint32(seg[4:8], 1000)
	seg[12] = 5 << 4
	seg[13] = flags
	binary.BigEndian.PutUint16(seg[14:16], 65535)
	binary.BigEndian.PutUint16(seg[16:18], l4Checksum6(src, dst, ipprotoTCP, seg))
	return seg
}

// l4Checksum6 is a reference IPv6 transport checksum over seg, whose own
// checksum field must be zero or already correct.
func l4Checksum6(src, dst netip.Addr, proto uint8, seg []byte) uint16 {
	var sum uint32
	add := func(b []byte) {
		for i := 0; i+1 < len(b); i += 2 {
			sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
		}
		if len(b)%2 == 1 {
			sum += uint32(b[len(b)-1]) << 8
		}
	}
	s, d := src.As16(), dst.As16()
	add(s[:])
	add(d[:])
	sum += uint32(len(seg)) + uint32(proto)
	add(seg)
	for sum>>16 != 0 {
		sum = sum&0xFFFF + sum>>16
	}
	return ^uint16(sum)
}

const (
	ip6SrcOff = ethLen + 8
	ip6DstOff = ethLen + 24
	l4Off6    = ethLen + ip6Len
)

// assertIntoPair checks a reply went back into p bare: framed from its NAT end
// to its tenant end, addressed to the guest's port, with a valid checksum.
func assertIntoPair(t *testing.T, ret uint32, out []byte, p localPair, proto uint8, from netip.Addr,
	guestPort uint16) {
	t.Helper()
	if ret != xdpRedirect {
		t.Fatalf("reply verdict = %d, want XDP_REDIRECT into the pair", ret)
	}
	if !bytes.Equal(out[0:6], p.tenant.Attrs().HardwareAddr) || !bytes.Equal(out[6:12], p.nat.Attrs().HardwareAddr) {
		t.Errorf("reply framed %x -> %x, want %s -> %s (the pair's NAT end to its tenant end)",
			out[6:12], out[0:6], p.nat.Attrs().HardwareAddr, p.tenant.Attrs().HardwareAddr)
	}
	if got := binary.BigEndian.Uint16(out[12:14]); got != 0x86DD {
		t.Fatalf("reply EtherType = %#x, want IPv6", got)
	}
	if out[ethLen+6] != proto {
		t.Errorf("reply next header = %d, want %d: a Local reply carries no SRv6 outer header", out[ethLen+6], proto)
	}
	if got := addrAt(out, ip6DstOff); got != localGuest {
		t.Errorf("reply destination = %s, want the guest %s", got, localGuest)
	}
	if got := addrAt(out, ip6SrcOff); got != from {
		t.Errorf("reply source = %s, want %s", got, from)
	}
	plen := int(binary.BigEndian.Uint16(out[ethLen+4 : ethLen+6]))
	seg := append([]byte{}, out[l4Off6:l4Off6+plen]...)
	var ckOff int
	switch proto {
	case ipprotoUDP:
		ckOff = 6
	case ipprotoTCP:
		ckOff = 16
	default:
		ckOff = 2
	}
	got := binary.BigEndian.Uint16(seg[ckOff : ckOff+2])
	seg[ckOff], seg[ckOff+1] = 0, 0
	if want := l4Checksum6(from, localGuest, proto, seg); got != want {
		t.Errorf("reply checksum = %#04x, want %#04x", got, want)
	}
	port := binary.BigEndian.Uint16(seg[2:4])
	if proto == ipprotoICMPv6 {
		port = binary.BigEndian.Uint16(seg[4:6])
	}
	if port != guestPort {
		t.Errorf("reply delivered to port/identifier %d, want %d", port, guestPort)
	}
}

// forward6 sends one tenant packet from p and returns the masquerade port or
// identifier the shard picked.
func (n *localNet) forward6(t *testing.T, p localPair, frame []byte, proto uint8) uint16 {
	t.Helper()
	before := n.localStat(t, LocalStatForward)
	ret, out := n.run(t, frame, p.nat.Attrs().Index)
	if ret != xdpRedirect {
		t.Fatalf("forward verdict = %d, want XDP_REDIRECT to the uplink", ret)
	}
	if got := n.localStat(t, LocalStatForward) - before; got != 1 {
		t.Errorf("local forward counter rose by %d, want 1", got)
	}
	if !bytes.Equal(out[0:6], localGwMAC) || !bytes.Equal(out[6:12], n.up0.Attrs().HardwareAddr) {
		t.Errorf("forward framed %x -> %x, want the uplink to its gateway", out[6:12], out[0:6])
	}
	if got := addrAt(out, ip6SrcOff); got != localPub6 {
		t.Errorf("forward source = %s, want the masquerade address %s", got, localPub6)
	}
	if proto == ipprotoICMPv6 {
		return binary.BigEndian.Uint16(out[l4Off6+4 : l4Off6+6])
	}
	return binary.BigEndian.Uint16(out[l4Off6 : l4Off6+2])
}

func TestLocalPair_NAT66OverlappingTenants(t *testing.T) {
	n := newLocalNet(t)
	pairs := []localPair{n.addPair(t, "pa", tenantSID(0x123)), n.addPair(t, "pb", tenantSID(0x456))}

	for _, tc := range []struct {
		name    string
		proto   uint8
		forward func() []byte
		reply   func(port uint16) []byte
	}{{
		name:  "udp",
		proto: ipprotoUDP,
		forward: func() []byte {
			return buildUDPPacket(t, localDest6, localGuest, localGuestPort, localDestPort, []byte("out"))
		},
		reply: func(port uint16) []byte {
			return buildUDPPacket(t, localPub6, localDest6, localDestPort, port, []byte("back"))
		},
	}, {
		name:  "tcp",
		proto: ipprotoTCP,
		forward: func() []byte {
			return ip6Packet(localGuest, localDest6, ipprotoTCP,
				tcp6Segment(localGuest, localDest6, localGuestPort, localDestPort, 0x02))
		},
		reply: func(port uint16) []byte {
			return ip6Packet(localDest6, localPub6, ipprotoTCP,
				tcp6Segment(localDest6, localPub6, localDestPort, port, 0x12))
		},
	}, {
		name:  "icmp",
		proto: ipprotoICMPv6,
		forward: func() []byte {
			return buildICMPv6Packet(localGuest, localDest6,
				icmpMessage(icmpv6EchoRequest, 0, echoWord(localGuestPort), []byte("ping")))
		},
		reply: func(id uint16) []byte {
			return buildICMPv6Packet(localDest6, localPub6,
				icmpMessage(icmpv6EchoReply, 0, echoWord(id), []byte("ping")))
		},
	}} {
		// No subtests: each runs on its own goroutine, off the thread that
		// holds this test's network namespace.
		func() {
			t.Logf("case %s", tc.name)
			// The same guest address and port in two VPCs: each pair's
			// tenant SID keeps its session apart.
			ports := make([]uint16, len(pairs))
			for i, p := range pairs {
				ports[i] = n.forward6(t, p, tc.forward(), tc.proto)
			}
			if ports[0] == ports[1] {
				t.Fatalf("both VPCs' flows got masquerade port %d; overlapping tenants must not share a session",
					ports[0])
			}
			for i, p := range pairs {
				before := n.localStat(t, LocalStatReturn)
				ret, out := n.run(t, tc.reply(ports[i]), n.up0.Attrs().Index)
				assertIntoPair(t, ret, out, p, tc.proto, localDest6, localGuestPort)
				if got := n.localStat(t, LocalStatReturn) - before; got != 1 {
					t.Errorf("local return counter rose by %d, want 1", got)
				}
			}
		}()
	}
}

func TestLocalPair_NAT64OverlappingTenants(t *testing.T) {
	n := newLocalNet(t)
	pairs := []localPair{n.addPair(t, "pa", tenantSID(0x123)), n.addPair(t, "pb", tenantSID(0x456))}
	synth := synthesize(localNSP, localDest4)

	for _, tc := range []struct {
		name    string
		proto   uint8
		forward func() []byte
		reply   func(port uint16) []byte
	}{{
		name:  "udp",
		proto: ipprotoUDP,
		forward: func() []byte {
			return buildUDPPacket(t, synth, localGuest, localGuestPort, localDestPort, []byte("out"))
		},
		reply: func(port uint16) []byte {
			return buildIPv4UDPPacket(t, localPub4, localDest4, localDestPort, port, []byte("back"))
		},
	}, {
		name:  "icmp",
		proto: ipprotoICMPv6,
		forward: func() []byte {
			return buildICMPv6Packet(localGuest, synth,
				icmpMessage(icmpv6EchoRequest, 0, echoWord(localGuestPort), []byte("ping")))
		},
		reply: func(id uint16) []byte {
			return buildICMPv4Packet(localDest4, localPub4,
				icmpMessage(icmpEchoReply, 0, echoWord(id), []byte("ping")))
		},
	}} {
		func() {
			t.Logf("case %s", tc.name)
			ports := make([]uint16, len(pairs))
			for i, p := range pairs {
				ret, out := n.run(t, tc.forward(), p.nat.Attrs().Index)
				if ret != xdpRedirect {
					t.Fatalf("forward verdict = %d, want XDP_REDIRECT to the uplink", ret)
				}
				if got := binary.BigEndian.Uint16(out[12:14]); got != 0x0800 {
					t.Fatalf("forward EtherType = %#x, want IPv4", got)
				}
				const l4Off4 = ethLen + 20
				if tc.proto == ipprotoICMPv6 {
					ports[i] = binary.BigEndian.Uint16(out[l4Off4+4 : l4Off4+6])
				} else {
					ports[i] = binary.BigEndian.Uint16(out[l4Off4 : l4Off4+2])
				}
			}
			if ports[0] == ports[1] {
				t.Fatalf("both VPCs' flows got masquerade port %d", ports[0])
			}
			for i, p := range pairs {
				ret, out := n.run(t, tc.reply(ports[i]), n.up0.Attrs().Index)
				assertIntoPair(t, ret, out, p, tc.proto, synth, localGuestPort)
			}
		}()
	}
}

// TestLocalPair_RemoteTenantStillEncapsulated: a session opened over the
// fabric is answered over the fabric, encapsulated toward the tenant's node,
// whatever pairs the shard also serves.
func TestLocalPair_RemoteTenantStillEncapsulated(t *testing.T) {
	n := newLocalNet(t)
	n.addPair(t, "pa", tenantSID(0x123))
	remoteNode := netip.MustParseAddr("fc00:0:2:2::a1b2")
	sidArg := localShardSID.As16()
	sidArg[8] = (sidArg[8] & 0xF0) | 0x01
	sidArg[9] = 0x23

	ret, out := n.run(t, buildEncappedUDPPacket(t, netip.AddrFrom16(sidArg), remoteNode, localGuest, localDest6,
		[]byte("out")), n.up0.Attrs().Index)
	if ret != xdpTx {
		t.Fatalf("remote forward verdict = %d, want XDP_TX back out the uplink", ret)
	}
	port := binary.BigEndian.Uint16(out[l4Off6 : l4Off6+2])

	before := n.localStat(t, LocalStatReturn)
	ret, out = n.run(t, buildUDPPacket(t, localPub6, localDest6, encappedDstPort, port, []byte("back")),
		n.up0.Attrs().Index)
	if ret != xdpTx {
		t.Fatalf("remote reply verdict = %d, want XDP_TX encapsulated toward the tenant node", ret)
	}
	if out[ethLen+6] != 41 {
		t.Fatalf("remote reply next header = %d, want 41 (IPv6-in-IPv6 toward the tenant node)", out[ethLen+6])
	}
	if got := addrAt(out, ip6DstOff); got != remoteNode {
		t.Errorf("remote reply outer destination = %s, want the tenant node %s", got, remoteNode)
	}
	if got := n.localStat(t, LocalStatReturn) - before; got != 0 {
		t.Errorf("local return counter rose by %d for a remote tenant, want 0", got)
	}
}

// TestLocalPair_RecreatedPairReusesSession: a pair Worker recreates gets a
// new NAT end ifindex but the same tenant SID, so the VPC's established
// sessions carry on through it.
func TestLocalPair_RecreatedPairReusesSession(t *testing.T) {
	n := newLocalNet(t)
	sid := tenantSID(0x123)
	old := n.addPair(t, "pa", sid)
	frame := func() []byte {
		return buildUDPPacket(t, localDest6, localGuest, localGuestPort, localDestPort, []byte("out"))
	}
	port := n.forward6(t, old, frame(), ipprotoUDP)

	oldIfindex := uint32(old.nat.Attrs().Index)
	if err := netlink.LinkDel(old.nat); err != nil {
		t.Fatalf("delete the pair: %v", err)
	}
	if err := n.objs.NatLocalPair.Delete(oldIfindex); err != nil {
		t.Fatalf("delete the old pair row: %v", err)
	}
	renewed := n.addPair(t, "pb", sid)
	if uint32(renewed.nat.Attrs().Index) == oldIfindex {
		t.Fatalf("recreated pair kept ifindex %d; the test needs a new one", oldIfindex)
	}

	if got := n.forward6(t, renewed, frame(), ipprotoUDP); got != port {
		t.Errorf("masquerade port after the pair was recreated = %d, want %d (the session reused)", got, port)
	}
	ret, out := n.run(t, buildUDPPacket(t, localPub6, localDest6, localDestPort, port, []byte("back")),
		n.up0.Attrs().Index)
	assertIntoPair(t, ret, out, renewed, ipprotoUDP, localDest6, localGuestPort)
}

// TestLocalPair_VLANEgressPushesTag: native XDP cannot redirect to a VLAN
// device, so a Local forward routed out of one pushes the tag itself and
// leaves through the lower device.
func TestLocalPair_VLANEgressPushesTag(t *testing.T) {
	n := newLocalNet(t)
	p := n.addPair(t, "pa", tenantSID(0x123))
	if err := netlink.LinkAdd(&netlink.Vlan{LinkAttrs: netlink.LinkAttrs{Name: "up0.100",
		ParentIndex: n.up0.Attrs().Index}, VlanId: 100}); err != nil {
		t.Fatalf("add VLAN: %v", err)
	}
	vlan := setLinkUp(t, "up0.100")
	addLinkAddr(t, vlan, netip.MustParseAddr("2001:db8:77::2"), 64)
	if err := netlink.NeighSet(&netlink.Neigh{LinkIndex: vlan.Attrs().Index, Family: netlink.FAMILY_V6,
		State: netlink.NUD_PERMANENT, IP: net.ParseIP("2001:db8:77::1"), HardwareAddr: localGwMAC}); err != nil {
		t.Fatalf("add VLAN neighbor: %v", err)
	}
	if err := n.objs.NatVlanEgress.Put(uint32(vlan.Attrs().Index), NatNatVlanEgressValue{
		LowerIfindex: uint32(n.up0.Attrs().Index), Vid: 100 << 8, Proto: 0x0081,
	}); err != nil {
		t.Fatalf("put nat_vlan_egress: %v", err)
	}

	dest := netip.MustParseAddr("2001:db8:77::1")
	ret, out := n.run(t, buildUDPPacket(t, dest, localGuest, localGuestPort, localDestPort, []byte("out")),
		p.nat.Attrs().Index)
	if ret != xdpRedirect {
		t.Fatalf("verdict = %d, want XDP_REDIRECT to the VLAN's lower device", ret)
	}
	if got := binary.BigEndian.Uint16(out[12:14]); got != 0x8100 {
		t.Fatalf("EtherType = %#x, want an 802.1Q tag", got)
	}
	if got := binary.BigEndian.Uint16(out[14:16]) & 0x0FFF; got != 100 {
		t.Errorf("VLAN ID = %d, want 100", got)
	}
	if got := binary.BigEndian.Uint16(out[16:18]); got != 0x86DD {
		t.Errorf("inner EtherType = %#x, want IPv6", got)
	}
	if got := addrAt(out, ip6SrcOff+4); got != localPub6 {
		t.Errorf("source behind the tag = %s, want the masquerade address", got)
	}
}

// TestLocalPair_UntranslatedNeverReachesTheHost: nothing from a pair's NAT
// end goes up the host's stack untranslated, except link-scoped IPv6.
func TestLocalPair_UntranslatedNeverReachesTheHost(t *testing.T) {
	n := newLocalNet(t)
	p := n.addPair(t, "pa", tenantSID(0x123))

	ns := buildICMPv6Packet(netip.MustParseAddr("fe80::5"), netip.MustParseAddr("ff02::1:ff00:1"),
		icmpMessage(icmpv6NeighborSolic, 0, 0, make([]byte, 16)))
	if ret, _ := n.run(t, ns, p.nat.Attrs().Index); ret != xdpPass {
		t.Errorf("Neighbor Solicitation verdict = %d, want XDP_PASS", ret)
	}

	before := n.localStat(t, LocalStatForwardUnclaimed)
	v4 := buildIPv4UDPPacket(t, localDest4, netip.MustParseAddr("10.0.0.5"), 1, 2, []byte("x"))
	if ret, _ := n.run(t, v4, p.nat.Attrs().Index); ret != xdpDrop {
		t.Errorf("IPv4 from a pair verdict = %d, want XDP_DROP", ret)
	}
	if got := n.localStat(t, LocalStatForwardUnclaimed) - before; got != 1 {
		t.Errorf("forward_unclaimed rose by %d, want 1", got)
	}
}
