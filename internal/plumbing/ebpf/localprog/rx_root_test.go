// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package localprog

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"go.datum.net/galactic/internal/plumbing/ebpf/attach"
	"go.datum.net/galactic/internal/plumbing/ebpf/edgeprog"
	"go.datum.net/galactic/internal/plumbing/ebpf/localprog/localfixture"
	"go.datum.net/galactic/internal/plumbing/ebpf/prog"
	"go.datum.net/galactic/internal/plumbing/ebpf/tpmap"
	"go.datum.net/galactic/internal/plumbing/ebpf/uformat"
	"go.datum.net/galactic/internal/plumbing/ebpf/usidmap"
	"go.datum.net/galactic/internal/plumbing/ebpf/vipxlatmap"
	"go.datum.net/galactic/internal/trafficpolicy"
)

const (
	rxBlock     = 0x20010db8ff01
	rxNode      = 0x0001
	rxArgument  = 0x1a5
	rxTable     = 77
	rxOtherArg  = 0x1a6
	rxOtherTbl  = 88
	rxSlot      = 7
	rxPort      = 443
	rxDenyPort  = 5353
	rxNoBinding = 444
	rxBackend   = 8443
	rxDenied    = 9 // the backend port the guest's policy denies on PublicService
	rxTPToken   = 0x4138
	rxTPMark    = 0x0de10000
	rxXDPDrv    = 1 << 2
)

var (
	rxVIP6    = netip.MustParseAddr("2001:db8:6060::1")
	rxVIP4    = netip.MustParseAddr("192.0.2.10")
	rxClient6 = netip.MustParseAddr("2001:db8:ffff::1")
	rxClient4 = netip.MustParseAddr("198.51.100.7")
	rxGuest   = netip.MustParseAddr("2001:db8:77::5")
	// rxClient4As6 is how the guest sees an IPv4 client.
	rxClient4As6 = netip.MustParseAddr("64:ff9b::c633:6407")
)

const statSIDMismatch = "rx_sid_mismatch"

func rxSID(node, argument, slot uint16) netip.Addr {
	a, err := uformat.Encode(uformat.Fields{Block: rxBlock, NodeID: node, Function: uformat.FunctionEndDT46,
		Argument: argument, Slot: slot})
	if err != nil {
		panic(err)
	}
	return a
}

// rxRig is a node whose public receiving device, pub0, runs the gateway's
// edge_lb in XDP and Local's local_rx at tc ingress, and a TAP stand-in,
// tap0, whose guest end is gst0. A client sends from cli0, pub0's peer.
type rxRig struct {
	t      *testing.T
	n      ns.NetNS
	usid   *prog.UsidObjects
	local  *Objects
	edge   edgeprog.EdgedsrObjects
	fix    localfixture.FixtureObjects
	pub    netlink.Link
	cli    netlink.Link
	tap    netlink.Link
	guest  netlink.Link
	tx, rx int
}

func newRxRig(t *testing.T) *rxRig {
	t.Helper()
	requireRoot(t)
	base := fmt.Sprintf("/sys/fs/bpf/galactic-localrx-test-%d", os.Getpid())
	_ = os.RemoveAll(base)
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	usid, err := attach.Load(filepath.Join(base, "usid"))
	if err != nil {
		t.Fatalf("load the uSID datapath: %v", err)
	}
	t.Cleanup(func() { _ = usid.Close() })
	local, err := Load(filepath.Join(base, "usid"), filepath.Join(base, "local"))
	if err != nil {
		t.Fatalf("load the Local programs: %v", err)
	}
	t.Cleanup(func() { _ = local.Close() })
	r := &rxRig{t: t, usid: usid, local: local}
	if err := edgeprog.LoadEdgedsrObjects(&r.edge, nil); err != nil {
		t.Fatalf("load edgedsr: %v", err)
	}
	t.Cleanup(func() { _ = r.edge.Close() })
	if err := localfixture.LoadFixtureObjects(&r.fix, nil); err != nil {
		t.Fatalf("load the fixture: %v", err)
	}
	t.Cleanup(func() { _ = r.fix.Close() })

	tp, err := tpmap.OpenPinned(filepath.Join(base, "usid"))
	if err != nil {
		t.Fatalf("open policy maps: %v", err)
	}
	t.Cleanup(tp.Close)

	if r.n, err = ns.TempNetNS(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.n.Close() })
	r.in(func() error {
		for _, k := range []string{"net/ipv6/conf/all/accept_dad", "net/ipv6/conf/default/accept_dad",
			"net/ipv6/conf/default/accept_ra"} {
			if err := os.WriteFile(filepath.Join("/proc/sys", k), []byte("0"), 0o644); err != nil {
				return err
			}
		}
		for _, v := range []*netlink.Veth{
			{LinkAttrs: netlink.LinkAttrs{Name: "pub0"}, PeerName: "cli0"},
			{LinkAttrs: netlink.LinkAttrs{Name: "tap0"}, PeerName: "gst0"},
		} {
			if err := netlink.LinkAdd(v); err != nil {
				return err
			}
		}
		links := map[string]*netlink.Link{"pub0": &r.pub, "cli0": &r.cli, "tap0": &r.tap, "gst0": &r.guest}
		for name, dst := range links {
			l, err := netlink.LinkByName(name)
			if err != nil {
				return err
			}
			if err := netlink.LinkSetUp(l); err != nil {
				return err
			}
			*dst = l
		}
		if err := netlink.NeighAdd(&netlink.Neigh{LinkIndex: r.tap.Attrs().Index, Family: netlink.FAMILY_V6,
			State: netlink.NUD_PERMANENT, IP: net.IP(rxGuest.AsSlice()),
			HardwareAddr: r.guest.Attrs().HardwareAddr}); err != nil {
			return err
		}
		if err := netlink.QdiscAdd(&netlink.GenericQdisc{QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: r.pub.Attrs().Index, Handle: netlink.MakeHandle(0xffff, 0), Parent: netlink.HANDLE_CLSACT,
		}, QdiscType: "clsact"}); err != nil {
			return err
		}
		if err := netlink.FilterAdd(&netlink.BpfFilter{
			FilterAttrs: netlink.FilterAttrs{LinkIndex: r.pub.Attrs().Index, Parent: netlink.HANDLE_MIN_INGRESS,
				Priority: 1, Protocol: unix.ETH_P_ALL},
			Fd: local.Programs.Rx.FD(), Name: "local-rx", DirectAction: true,
		}); err != nil {
			return err
		}
		if err := netlink.LinkSetXdpFdWithFlags(r.pub, r.edge.EdgeLb.FD(), rxXDPDrv); err != nil {
			return fmt.Errorf("attach edge_lb: %w", err)
		}
		var err error
		if r.tx, err = packetSocket(r.cli.Attrs().Index); err != nil {
			return err
		}
		r.rx, err = packetSocket(r.guest.Attrs().Index)
		return err
	})
	t.Cleanup(func() { _ = unix.Close(r.tx); _ = unix.Close(r.rx) })

	r.populate(tp)
	return r
}

func (r *rxRig) in(fn func() error) {
	r.t.Helper()
	if err := r.n.Do(func(ns.NetNS) error { return fn() }); err != nil {
		r.t.Fatal(err)
	}
}

func (r *rxRig) tapIndex() uint32 { return uint32(r.tap.Attrs().Index) } //nolint:gosec // a kernel ifindex

// populate writes what galactic-cni, Worker and the gateway write for one
// backend of each VIP on this node: this node's locator, End.DT46, the VPC's
// VRF, the VIP bindings, the TAP's claim and policy, and the gateway's Local
// rows.
func (r *rxRig) populate(tp *tpmap.Maps) {
	t := r.t
	loc, err := uformat.NewLocatorKey(rxBlock, rxNode)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.usid.LocatorTable.Put(uint64(loc), prog.UsidLocatorValue{Generation: 1}); err != nil {
		t.Fatal(err)
	}
	fn, err := uformat.NewFunctionKey(rxBlock, uformat.FunctionEndDT46)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.usid.FunctionTable.Put(uint64(fn), prog.UsidFunctionValue{Behavior: usidmap.BehaviorEndDT46}); err != nil {
		t.Fatal(err)
	}
	for arg, table := range map[uint16]uint32{rxArgument: rxTable, rxOtherArg: rxOtherTbl} {
		key, err := uformat.NewVRFKey(rxBlock, arg)
		if err != nil {
			t.Fatal(err)
		}
		if err := r.usid.VrfTable.Put(uint64(key), prog.UsidVrfValue{VrfTableId: table}); err != nil {
			t.Fatal(err)
		}
	}
	xlat := vipxlatmap.NewVipXlatTable(usidmap.KernelTable{Map: r.usid.VipXlatTable})
	guest := net.IP(rxGuest.AsSlice())
	for _, proto := range []uint8{unix.IPPROTO_TCP, unix.IPPROTO_UDP} {
		for _, vip := range []netip.Addr{rxVIP6, rxVIP4} {
			if err := xlat.RegisterIngress(rxBlock, rxArgument, rxSlot, proto, net.IP(vip.AsSlice()), rxPort,
				guest, rxBackend); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := xlat.RegisterIngress(rxBlock, rxArgument, rxSlot, unix.IPPROTO_UDP, net.IP(rxVIP6.AsSlice()),
		rxDenyPort, guest, rxDenied); err != nil {
		t.Fatal(err)
	}

	if err := r.local.Maps.Tap.Put(r.tapIndex(), LocalLtTapValue{Nh: rxGuest.As16(), TableId: rxTable}); err != nil {
		t.Fatal(err)
	}
	if err := tp.SetState(tpmap.State{Mode: tpmap.ModeEnforce, NATLocatorsSynced: true, Mark: rxTPMark,
		Capable: true}); err != nil {
		t.Fatal(err)
	}
	if err := tp.PutInterface(r.tapIndex(), rxTPToken, tpmap.KindTenant); err != nil {
		t.Fatal(err)
	}
	// Everything is allowed except UDP to the guest's port rxDenied on the
	// PublicService path.
	entries := []trafficpolicy.Entry{
		{Flags: trafficpolicy.FlagPath | trafficpolicy.FlagProto | trafficpolicy.FlagDestPorts, Rule: 0,
			Path: trafficpolicy.PathPublicService, Proto: unix.IPPROTO_UDP,
			DestPorts: trafficpolicy.PortRange{Start: rxDenied, End: rxDenied}},
		{Flags: trafficpolicy.FlagAllow, Rule: 1},
	}
	for _, dir := range []uint32{tpmap.DirIngress, tpmap.DirEgress} {
		if err := tp.Publish(r.tapIndex(), dir, rxTPToken, r.tapIndex()*4, entries); err != nil {
			t.Fatal(err)
		}
	}
}

// gateway registers vip's port on the gateway with one backend, sid, which
// is Local on this node behind tap0.
func (r *rxRig) gateway(proto uint8, vip netip.Addr, port uint16, sid netip.Addr) {
	r.t.Helper()
	var value edgeprog.EdgedsrVipValue
	value.BackendCount = 1
	value.Backends[0] = edgeprog.EdgedsrBackend{Addr: rxGuest.As16(), Port: htons(rxBackend), Usid: sid.As16()}
	if err := r.edge.VipTable.Put(edgeprog.EdgedsrVipKey{Proto: proto, Port: htons(port), Vip: vip.As16()},
		value); err != nil {
		r.t.Fatal(err)
	}
	if err := r.edge.EdgeLocalTable.Put(edgeprog.EdgedsrEdgeLocalKey{Usid: sid.As16()},
		edgeprog.EdgedsrEdgeLocalValue{TapIfindex: r.tapIndex(), Generation: 1}); err != nil {
		r.t.Fatal(err)
	}
}

// send writes an IPv6 or IPv4 TCP SYN or UDP datagram from the client to dst
// on pub0, with a correct checksum.
func (r *rxRig) send(proto uint8, src, dst netip.Addr, sport, dport uint16, payload string) {
	r.t.Helper()
	l4 := l4Segment(proto, sport, dport, payload)
	frame := append([]byte{}, r.pub.Attrs().HardwareAddr...)
	frame = append(frame, r.cli.Attrs().HardwareAddr...)
	if dst.Is6() {
		setL4Checksum(proto, l4, pseudo6(src, dst, proto, len(l4)))
		frame = append(frame, 0x86, 0xDD, 0x60, 0, 0, 0)
		frame = binary.BigEndian.AppendUint16(frame, uint16(len(l4))) //nolint:gosec // small
		frame = append(frame, proto, 64)
		s, d := src.As16(), dst.As16()
		frame = append(frame, s[:]...)
		frame = append(frame, d[:]...)
	} else {
		s, d := src.As4(), dst.As4()
		ph := append(append(append([]byte{}, s[:]...), d[:]...), 0, proto)
		ph = binary.BigEndian.AppendUint16(ph, uint16(len(l4))) //nolint:gosec // small
		setL4Checksum(proto, l4, ph)
		hdr := []byte{0x45, 0, 0, 0, 0x12, 0x34, 0x40, 0, 64, proto, 0, 0}
		binary.BigEndian.PutUint16(hdr[2:4], uint16(20+len(l4))) //nolint:gosec // small
		hdr = append(append(hdr, s[:]...), d[:]...)
		binary.BigEndian.PutUint16(hdr[10:12], ^csumAdd(0, hdr))
		frame = append(frame, 0x08, 0x00)
		frame = append(frame, hdr...)
	}
	frame = append(frame, l4...)
	if err := unix.Sendto(r.tx, frame, 0, &unix.SockaddrLinklayer{Ifindex: r.cli.Attrs().Index,
		Halen: 6, Addr: [8]byte(append(append([]byte{}, r.pub.Attrs().HardwareAddr...), 0, 0))}); err != nil {
		r.t.Fatal(err)
	}
}

func l4Segment(proto uint8, sport, dport uint16, payload string) []byte {
	b := binary.BigEndian.AppendUint16(nil, sport)
	b = binary.BigEndian.AppendUint16(b, dport)
	if proto == unix.IPPROTO_TCP {
		b = append(b, 0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x02, 0xff, 0xff, 0, 0, 0, 0)
	} else {
		b = binary.BigEndian.AppendUint16(b, uint16(8+len(payload))) //nolint:gosec // small
		b = append(b, 0, 0)
	}
	return append(b, payload...)
}

func pseudo6(src, dst netip.Addr, proto uint8, l4len int) []byte {
	s, d := src.As16(), dst.As16()
	b := append(append([]byte{}, s[:]...), d[:]...)
	b = binary.BigEndian.AppendUint32(b, uint32(l4len)) //nolint:gosec // small
	return append(b, 0, 0, 0, proto)
}

func csumAdd(sum uint32, b []byte) uint16 {
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return uint16(sum)
}

func csumOffset(proto uint8) int {
	if proto == unix.IPPROTO_TCP {
		return 16
	}
	return 6
}

func setL4Checksum(proto uint8, l4, pseudo []byte) {
	off := csumOffset(proto)
	l4[off], l4[off+1] = 0, 0
	c := ^csumAdd(uint32(csumAdd(0, pseudo)), l4)
	binary.BigEndian.PutUint16(l4[off:], c)
}

// arrived returns the first frame on gst0 carrying payload within wait.
func (r *rxRig) arrived(payload string, wait time.Duration) ([]byte, bool) {
	buf := make([]byte, 2048)
	deadline := time.Now().Add(wait)
	for time.Now().Before(deadline) {
		n, _, err := unix.Recvfrom(r.rx, buf, 0)
		if err != nil {
			continue
		}
		if bytes.Contains(buf[:n], []byte(payload)) {
			return append([]byte(nil), buf[:n]...), true
		}
	}
	return nil, false
}

func (r *rxRig) stat(name string) uint64 {
	r.t.Helper()
	s, err := Stats(r.local.Maps.Stats)
	if err != nil {
		r.t.Fatal(err)
	}
	return s[name]
}

// wantDelivered checks frame is an IPv6 packet from src to the guest's
// backend port with a valid L4 checksum, addressed to the guest's MAC.
func (r *rxRig) wantDelivered(frame []byte, proto uint8, src netip.Addr, sport, dport uint16) {
	r.t.Helper()
	if !bytes.Equal(frame[0:6], r.guest.Attrs().HardwareAddr) {
		r.t.Errorf("frame addressed to %x, want the guest %x", frame[0:6], r.guest.Attrs().HardwareAddr)
	}
	if binary.BigEndian.Uint16(frame[12:14]) != 0x86DD || frame[14]>>4 != 6 || frame[14+6] != proto {
		r.t.Fatalf("frame is not IPv6 proto %d: % x", proto, frame[:min(len(frame), 60)])
	}
	ip6 := frame[14:]
	gotSrc, gotDst := netip.AddrFrom16([16]byte(ip6[8:24])), netip.AddrFrom16([16]byte(ip6[24:40]))
	if gotSrc != src || gotDst != rxGuest {
		r.t.Errorf("packet %v -> %v, want %v -> %v", gotSrc, gotDst, src, rxGuest)
	}
	l4len := int(binary.BigEndian.Uint16(ip6[4:6]))
	l4 := ip6[40 : 40+l4len]
	if got := binary.BigEndian.Uint16(l4[0:2]); got != sport {
		r.t.Errorf("source port = %d, want %d", got, sport)
	}
	if got := binary.BigEndian.Uint16(l4[2:4]); got != dport {
		r.t.Errorf("destination port = %d, want %d", got, dport)
	}
	if c := csumAdd(uint32(csumAdd(0, pseudo6(gotSrc, gotDst, proto, l4len))), l4); c != 0xffff {
		r.t.Errorf("L4 checksum does not verify (sum %#04x)", c)
	}
}

// TestLocalRxRoot_GLM2TranslatesAndDelivers runs the gateway's edge_lb and
// Local's local_rx on one receiving device: a VIP packet for a Local backend
// reaches the TAP's guest translated to the backend's address and port, IPv6
// as is and IPv4 through SIIT from 64:ff9b::<client>, decided on the
// PublicService path, and the flow is recorded with the translated addresses.
func TestLocalRxRoot_GLM2TranslatesAndDelivers(t *testing.T) {
	r := newRxRig(t)
	sid := rxSID(rxNode, rxArgument, rxSlot)
	tests := []struct {
		name      string
		proto     uint8
		vip       netip.Addr
		client    netip.Addr
		guestPeer netip.Addr
	}{
		{"ipv6/tcp", unix.IPPROTO_TCP, rxVIP6, rxClient6, rxClient6},
		{"ipv6/udp", unix.IPPROTO_UDP, rxVIP6, rxClient6, rxClient6},
		{"ipv4/tcp", unix.IPPROTO_TCP, rxVIP4, rxClient4, rxClient4As6},
		{"ipv4/udp", unix.IPPROTO_UDP, rxVIP4, rxClient4, rxClient4As6},
	}
	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r.t = t
			r.gateway(tc.proto, tc.vip, rxPort, sid)
			sport := uint16(40000 + i) //nolint:gosec // small
			payload := "glm2-" + tc.name
			before := r.stat("rx_deliver")
			r.send(tc.proto, tc.client, tc.vip, sport, rxPort, payload)
			frame, ok := r.arrived(payload, time.Second)
			if !ok {
				t.Fatalf("the packet never reached the guest; Local stats %v", mustStats(t, r.local.Maps.Stats))
			}
			r.wantDelivered(frame, tc.proto, tc.guestPeer, sport, rxBackend)
			if got := r.stat("rx_deliver"); got != before+1 {
				t.Errorf("lt_stats[rx_deliver] = %d, want %d", got, before+1)
			}
			fk := LocalLtFlowKey{LinkIfindex: r.tapIndex(), Proto: tc.proto, LocalPort: htons(rxBackend),
				PeerPort: htons(sport), Local: rxGuest.As16(), Peer: tc.guestPeer.As16()}
			var fv LocalLtFlowValue
			if err := r.local.Maps.Flow.Lookup(fk, &fv); err != nil {
				t.Errorf("lt_flow has no row for the translated flow: %v", err)
			} else if fv.RxIfindex != uint32(r.pub.Attrs().Index) { //nolint:gosec // a kernel ifindex
				t.Errorf("lt_flow rx_ifindex = %d, want pub0's %d", fv.RxIfindex, r.pub.Attrs().Index)
			}
		})
	}
}

// TestLocalRxRoot_GLM2Refusals covers each GLM2 packet local_rx refuses:
// a uSID naming another VRF or another node, a VIP with no binding for the
// SID's slot, and a translated packet the guest's PublicService policy
// denies, which proves the decision sees the backend port.
func TestLocalRxRoot_GLM2Refusals(t *testing.T) {
	r := newRxRig(t)
	sid := rxSID(rxNode, rxArgument, rxSlot)
	tests := []struct {
		name string
		vip  netip.Addr
		port uint16
		sid  netip.Addr
		stat string
	}{
		{"another VRF", netip.MustParseAddr("2001:db8:6060::2"), rxPort, rxSID(rxNode, rxOtherArg, rxSlot),
			statSIDMismatch},
		{"another node", netip.MustParseAddr("2001:db8:6060::3"), rxPort, rxSID(rxNode+1, rxArgument, rxSlot),
			statSIDMismatch},
		{"no slot", netip.MustParseAddr("2001:db8:6060::4"), rxPort, rxSID(rxNode, rxArgument, 0),
			statSIDMismatch},
		{"no binding", rxVIP6, rxNoBinding, sid, "rx_no_binding"},
		{"policy denies the backend port", rxVIP6, rxDenyPort, sid, "rx_deny"},
	}
	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r.t = t
			r.gateway(unix.IPPROTO_UDP, tc.vip, tc.port, tc.sid)
			before := mustStats(t, r.local.Maps.Stats)
			payload := fmt.Sprintf("refused-%d", i)
			r.send(unix.IPPROTO_UDP, rxClient6, tc.vip, 41000, tc.port, payload)
			if _, ok := r.arrived(payload, 300*time.Millisecond); ok {
				t.Fatal("a refused packet reached the guest")
			}
			after := mustStats(t, r.local.Maps.Stats)
			if after[tc.stat] != before[tc.stat]+1 {
				t.Errorf("lt_stats[%s] = %d, want %d", tc.stat, after[tc.stat], before[tc.stat]+1)
			}
			if after["rx_deliver"] != before["rx_deliver"] {
				t.Error("a refused packet was counted as delivered")
			}
		})
	}
}

// TestLocalRxRoot_GLM1Unchanged covers a GLM1 writer, the fixture's gateway
// stand-in: the packet is delivered to the TAP exactly as sent, with no SID
// check and no translation.
func TestLocalRxRoot_GLM1Unchanged(t *testing.T) {
	r := newRxRig(t)
	r.in(func() error { return netlink.LinkSetXdpFdWithFlags(r.pub, r.fix.LtfGateway.FD(), rxXDPDrv) })
	if err := r.fix.LtfVip.Put(localfixture.FixtureLtfIn6{A: rxGuest.As16()},
		localfixture.FixtureLtfVipValue{TapIfindex: r.tapIndex(), Magic: 0x474c4d31}); err != nil {
		t.Fatal(err)
	}
	r.send(unix.IPPROTO_UDP, rxClient6, rxGuest, 41000, 53, "glm1")
	frame, ok := r.arrived("glm1", time.Second)
	if !ok {
		t.Fatalf("the GLM1 packet never reached the guest; Local stats %v", mustStats(t, r.local.Maps.Stats))
	}
	r.wantDelivered(frame, unix.IPPROTO_UDP, rxClient6, 41000, 53)
	if got := r.stat("rx_deliver"); got != 1 {
		t.Errorf("lt_stats[rx_deliver] = %d, want 1", got)
	}
}
