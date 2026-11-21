// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package local

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	workerv1alpha1 "go.datum.net/galactic/api/galactic/worker/v1alpha1"
	"go.datum.net/galactic/internal/config"
	"go.datum.net/galactic/internal/plumbing/ebpf/attach"
	"go.datum.net/galactic/internal/plumbing/ebpf/attachreg"
	"go.datum.net/galactic/internal/plumbing/ebpf/ifindexvrfmap"
	"go.datum.net/galactic/internal/plumbing/ebpf/prog"
	"go.datum.net/galactic/internal/plumbing/ebpf/tpmap"
	"go.datum.net/galactic/internal/plumbing/ebpf/xdpmode"
	"go.datum.net/galactic/internal/plumbing/intf"
	"go.datum.net/galactic/internal/worker/module"
)

// The remote side of the egress tests: a workload on another node in VPC a,
// reached through that node's SID for the VPC, over the receiving device.
var (
	remoteDst   = netip.MustParseAddr("2001:db8:4135:e::1")
	remoteSID   = netip.MustParseAddr("2001:db8:4136:2:e080::")
	remoteBlock = netip.MustParsePrefix("2001:db8:4136::/48")
	spoofSrc    = netip.MustParseAddr("fd20:80:ff04::66")
)

// routedUID is the attachment UID of the routed link claims.
const routedUID = "envoy-1"

// routedEgress is a rig with one routed_link claim in its first VPC, whose
// Local destination is the VPC's TAP guest.
type routedEgress struct {
	r      *rig
	a      *vpcRig
	pod    ns.NetNS
	claims []module.Claim
	host   string
	podEnd string
}

func newRoutedEgress(t *testing.T, name string) *routedEgress {
	t.Helper()
	r := newRig(t, name, xdpmode.Native)
	a := r.vpcs[0]
	pod, err := ns.TempNetNS()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pod.Close() })
	r.pods.add("pod-1", pod)
	dest := module.Destination{ID: "attachment/" + a.attUID, Mode: workerv1alpha1.Mode_MODE_LOCAL, VPC: a.vpc,
		Node: testNode, Addresses: []netip.Addr{guestAddr}, HostInterface: a.tap}
	claim := module.Claim{Key: module.ClaimKey{Node: testNode, VPC: a.vpc, AttachmentUID: routedUID},
		Owner: "galactic-system/envoy", Generation: 1, Handoff: workerv1alpha1.Handoff_HANDOFF_ROUTED_LINK,
		OwnerPod: "pod-1", Addresses: []netip.Addr{podAddr}, Destinations: []module.Destination{dest}}
	e := &routedEgress{r: r, a: a, pod: pod, claims: []module.Claim{claim},
		host: linkName(a.vpc, routedUID, intf.LocalRoleRoutedHost), podEnd: linkName(a.vpc, routedUID,
			intf.LocalRoleRoutedPod)}
	// galactic-cni's pass-through entry for its own tenant's address.
	if err := r.routes.RegisterPassThrough(a.table, ipnet(netip.PrefixFrom(guestAddr, 128))); err != nil {
		t.Fatal(err)
	}
	wantReady(t, r.reconcile(a.vpc, e.claims), e.claims)
	return e
}

// tcxChain returns the programs on name's tcx ingress, in order.
func (e *routedEgress) tcxChain(name string) []ebpf.ProgramID {
	e.r.t.Helper()
	var ids []ebpf.ProgramID
	e.r.in(e.r.node, func() error {
		l, err := netlink.LinkByName(name)
		if err != nil {
			return err
		}
		res, err := link.QueryPrograms(link.QueryOptions{Target: l.Attrs().Index, Attach: ebpf.AttachTCXIngress})
		if err != nil {
			return err
		}
		for _, p := range res.Programs {
			ids = append(ids, p.ID)
		}
		return nil
	})
	return ids
}

// guardID is the ID of the guard the rig's Worker loaded.
func (e *routedEgress) guardID() ebpf.ProgramID {
	e.r.kernel.mu.Lock()
	defer e.r.kernel.mu.Unlock()
	return e.r.kernel.progIDs[filterLinkGuard]
}

// wantGuardFirst fails unless the rig's guard runs first on the host end's
// tcx ingress and Local's clsact guard is gone.
func (e *routedEgress) wantGuardFirst(t *testing.T) {
	t.Helper()
	chain := e.tcxChain(e.host)
	if len(chain) == 0 || chain[0] != e.guardID() {
		t.Fatalf("tcx ingress of %s = %v, want the guard %d first", e.host, chain, e.guardID())
	}
	e.r.in(e.r.node, func() error {
		l, err := netlink.LinkByName(e.host)
		if err != nil {
			return err
		}
		if name, _, ok, err := attach.LocalFilter(l.Attrs().Index); err != nil || ok {
			t.Fatalf("Local's clsact filter %q is still on %s (%v)", name, e.host, err)
		}
		return nil
	})
}

// hostIndex returns the host end's ifindex.
func (e *routedEgress) hostIndex() uint32 {
	e.r.t.Helper()
	var idx int
	e.r.in(e.r.node, func() error {
		l, err := netlink.LinkByName(e.host)
		if err != nil {
			return err
		}
		idx = l.Attrs().Index
		return nil
	})
	return uint32(idx)
}

// wantEgress fails unless the host end carries the egress datapath as an
// infra interface: its programs, its ifindex_vrf_table, egress kind and
// infra traffic policy rows, and the node's source SID.
func (e *routedEgress) wantEgress(t *testing.T) {
	t.Helper()
	idx := e.hostIndex()
	e.r.in(e.r.node, func() error {
		chain, err := attach.HasEgressChain(e.host)
		if err != nil || !chain {
			t.Fatalf("the egress chain on %s: %t %v", e.host, chain, err)
		}
		if ok, err := attach.HasDeliver(e.host); err != nil || !ok {
			t.Fatalf("tp_deliver on %s: %t %v", e.host, ok, err)
		}
		return nil
	})
	var iv prog.UsidIfindexVrfValue
	if err := e.r.usid.IfindexVrfTable.Lookup(idx, &iv); err != nil || iv.Block != 0x4135 ||
		iv.Argument != e.a.argument {
		t.Fatalf("ifindex_vrf_table[%d] = %+v (%v), want the VPC's key", idx, iv, err)
	}
	kinds, closer, err := ifindexvrfmap.OpenPinnedEgressKind(e.r.kernel.PinDir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = closer.Close() }()
	if _, ok, err := kinds.Get(idx); err != nil || !ok {
		t.Fatalf("ifindex_egress_kind_table[%d]: %t %v", idx, ok, err)
	}
	var row prog.UsidTpIfaceValue
	if err := e.r.tp.Interfaces.Lookup(idx, &row); err != nil || row.Kind != tpmap.KindInfra {
		t.Fatalf("tp_iface_table[%d] = %+v (%v), want an infra row", idx, row, err)
	}
	want, err := nodeSIDBase(rigLocator)
	if err != nil {
		t.Fatal(err)
	}
	var src [16]byte
	if err := e.r.usid.NodeSrcAddrTable.Lookup(uint32(0), &src); err != nil || netip.AddrFrom16(src) != want {
		t.Fatalf("node_src_addr_table = %s (%v), want %s", netip.AddrFrom16(src), err, want)
	}
}

// wantNoEgress fails unless the host end idx carries no row or program of the
// egress datapath.
func (e *routedEgress) wantNoEgress(t *testing.T, idx uint32) {
	t.Helper()
	e.r.in(e.r.node, func() error {
		present, err := attachreg.HostLinkPresent(e.r.kernel.PinDir, idx, e.host)
		if err != nil {
			var nf netlink.LinkNotFoundError
			if !errors.As(err, &nf) {
				return err
			}
		}
		if present {
			t.Fatalf("%s keeps the egress datapath", e.host)
		}
		return nil
	})
	var iv prog.UsidIfindexVrfValue
	if err := e.r.usid.IfindexVrfTable.Lookup(idx, &iv); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("ifindex_vrf_table[%d] stays: %+v %v", idx, iv, err)
	}
	var row prog.UsidTpIfaceValue
	if err := e.r.tp.Interfaces.Lookup(idx, &row); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("tp_iface_table[%d] stays: %+v %v", idx, row, err)
	}
}

// blocked returns why the claim's routed link cannot carry its Fabric
// destinations, as the last Read found.
func (e *routedEgress) blocked() (module.Blocked, bool) {
	b, ok := e.r.mod.HandoffBlocked(module.Scope{VPC: e.a.vpc}, workerv1alpha1.Mode_MODE_FABRIC)[e.claims[0].Key]
	return b, ok
}

// remote makes the VPC's table encapsulate remoteDst toward remoteSID, over
// the receiving device to the client namespace, as galactic-router installs a
// remote route.
func (e *routedEgress) remote() {
	r := e.r
	// The receiving device is the node's SRv6 uplink.
	r.t.Setenv(config.EnvCNIEBPFInterfaces, r.rx)
	attach.InvalidateUplinkIndexes()
	r.t.Cleanup(attach.InvalidateUplinkIndexes)
	var clientMAC net.HardwareAddr
	r.in(r.client, func() error {
		l, err := netlink.LinkByName(r.clientIf)
		if err != nil {
			return err
		}
		clientMAC = l.Attrs().HardwareAddr
		return nil
	})
	r.in(r.node, func() error {
		l, err := netlink.LinkByName(r.rx)
		if err != nil {
			return err
		}
		if err := netlink.NeighSet(&netlink.Neigh{LinkIndex: l.Attrs().Index, Family: netlink.FAMILY_V6,
			State: netlink.NUD_PERMANENT, IP: net.IP(client.AsSlice()), HardwareAddr: clientMAC}); err != nil {
			return err
		}
		if err := netlink.RouteReplace(&netlink.Route{LinkIndex: l.Attrs().Index, Dst: ipnet(remoteBlock),
			Gw: net.IP(client.AsSlice())}); err != nil {
			return err
		}
		return r.routes.Register(e.a.table, ipnet(netip.PrefixFrom(remoteDst, 128)), net.IP(remoteSID.AsSlice()))
	})
}

// podConn configures the pod's end as the galactic-vrf sidecar does, once,
// and returns a UDP socket in the pod bound to src.
func (e *routedEgress) podConn(t *testing.T, src netip.Addr, port int) *net.UDPConn {
	t.Helper()
	var hostLL netip.Addr
	e.r.in(e.r.node, func() error {
		l, err := netlink.LinkByName(e.host)
		if err != nil {
			return err
		}
		hostLL = linkLocal(l)
		return nil
	})
	if !hostLL.IsValid() {
		t.Fatal("the routed link's host end has no link-local address")
	}
	var c *net.UDPConn
	if err := e.pod.Do(func(ns.NetNS) error {
		l, err := netlink.LinkByName(e.podEnd)
		if err != nil {
			return err
		}
		if err := netlink.AddrReplace(l, &netlink.Addr{IPNet: ipnet(netip.PrefixFrom(src, 128)),
			Flags: unix.IFA_F_NODAD}); err != nil {
			return err
		}
		if err := netlink.RouteReplace(&netlink.Route{LinkIndex: l.Attrs().Index,
			Dst: ipnet(netip.PrefixFrom(remoteDst, 128)), Gw: net.IP(hostLL.AsSlice())}); err != nil {
			return err
		}
		c, err = net.ListenUDP("udp6", &net.UDPAddr{IP: net.IP(src.AsSlice()), Port: port})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// encapFrame is an SRv6-encapsulated packet seen on the wire.
type encapFrame struct {
	outerSrc, outerDst netip.Addr
	innerSrc, innerDst netip.Addr
	payload            string
}

// wire captures what reaches the client's end of the receiving device.
type wire struct {
	fd     int
	frames chan encapFrame
}

func (e *routedEgress) wire(t *testing.T) *wire {
	t.Helper()
	w := &wire{frames: make(chan encapFrame, 256)}
	e.r.in(e.r.client, func() error {
		l, err := netlink.LinkByName(e.r.clientIf)
		if err != nil {
			return err
		}
		proto := int(htons(unix.ETH_P_ALL))
		if w.fd, err = unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, proto); err != nil {
			return err
		}
		return unix.Bind(w.fd, &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_ALL), Ifindex: l.Attrs().Index})
	})
	tv := unix.NsecToTimeval(int64(100 * time.Millisecond))
	if err := unix.SetsockoptTimeval(w.fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		buf := make([]byte, 65536)
		for {
			select {
			case <-done:
				return
			default:
			}
			n, _, err := unix.Recvfrom(w.fd, buf, 0)
			if err != nil {
				continue
			}
			if f, ok := parseEncap(buf[:n]); ok {
				select {
				case w.frames <- f:
				default:
				}
			}
		}
	}()
	t.Cleanup(func() { close(done); <-stopped; _ = unix.Close(w.fd) })
	return w
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }

// parseEncap parses an Ethernet frame carrying IPv6 in IPv6, with or without
// a Segment Routing Header, and a UDP payload.
func parseEncap(f []byte) (encapFrame, bool) {
	if len(f) < ethHdrLen+2*ip6HdrLen || binary.BigEndian.Uint16(f[12:]) != 0x86DD {
		return encapFrame{}, false
	}
	outer := f[ethHdrLen:]
	next, off := outer[6], ip6HdrLen
	if next == unix.IPPROTO_ROUTING {
		if len(outer) < off+8 {
			return encapFrame{}, false
		}
		next, off = outer[off], off+(int(outer[off+1])+1)*8
	}
	if next != unix.IPPROTO_IPV6 || len(outer) < off+ip6HdrLen+udpHdrLen {
		return encapFrame{}, false
	}
	inner := outer[off:]
	out := encapFrame{outerSrc: netip.AddrFrom16([16]byte(outer[8:24])),
		outerDst: netip.AddrFrom16([16]byte(outer[24:40])),
		innerSrc: netip.AddrFrom16([16]byte(inner[8:24])), innerDst: netip.AddrFrom16([16]byte(inner[24:40]))}
	if inner[6] == protoUDP {
		out.payload = string(inner[ip6HdrLen+udpHdrLen:])
	}
	return out, true
}

// expect returns the encapsulated frame carrying payload.
func (w *wire) expect(t *testing.T, payload string) encapFrame {
	t.Helper()
	deadline := time.After(3 * time.Second)
	for {
		select {
		case f := <-w.frames:
			if f.payload == payload {
				return f
			}
		case <-deadline:
			t.Fatalf("nothing carrying %q left encapsulated", payload)
			return encapFrame{}
		}
	}
}

// absent fails if an encapsulated frame carrying payload leaves within a
// short wait.
func (w *wire) absent(t *testing.T, payload string) {
	t.Helper()
	deadline := time.After(500 * time.Millisecond)
	for {
		select {
		case f := <-w.frames:
			if f.payload == payload {
				t.Fatalf("%q left encapsulated from %s, which the guard must drop", payload, f.innerSrc)
			}
		case <-deadline:
			return
		}
	}
}

// sendRemote sends payload from c to remoteDst and checks that it leaves
// encapsulated toward remoteSID from this node's source SID for the VPC.
func (e *routedEgress) sendRemote(t *testing.T, w *wire, c *net.UDPConn, payload string) {
	t.Helper()
	if _, err := c.WriteToUDP([]byte(payload), &net.UDPAddr{IP: net.IP(remoteDst.AsSlice()), Port: 9000}); err != nil {
		t.Fatal(err)
	}
	f := w.expect(t, payload)
	base, err := nodeSIDBase(rigLocator)
	if err != nil {
		t.Fatal(err)
	}
	wantSrc := spliceArgument(base.As16(), e.a.argument)
	if f.outerDst != remoteSID || f.outerSrc != wantSrc || f.innerSrc != podAddr || f.innerDst != remoteDst {
		t.Fatalf("%q left as %+v, want %s -> %s around %s -> %s", payload, f, wantSrc, remoteSID, podAddr, remoteDst)
	}
}

// foreignTCX returns a program that passes everything on to the next tcx
// program, standing in for another agent's.
func foreignTCX(t *testing.T) *ebpf.Program {
	t.Helper()
	p, err := ebpf.NewProgram(&ebpf.ProgramSpec{Name: "foreign_head", Type: ebpf.SchedCLS, License: "GPL",
		Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, -1), asm.Return()}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p
}

// attachHead attaches p at the head of the host end's tcx ingress.
func (e *routedEgress) attachHead(p *ebpf.Program) {
	e.r.t.Helper()
	idx := int(e.hostIndex())
	e.r.in(e.r.node, func() error {
		return link.RawAttachProgram(link.RawAttachProgramOptions{Target: idx, Program: p,
			Attach: ebpf.AttachTCXIngress, Anchor: link.Head()})
	})
}

// TestRoutedLinkEgressRoot checks a routed link's egress datapath: the guard
// runs first in tcx, the host end carries usid_service_egress, usid_egress
// and tp_deliver with its rows as an infra interface, a remote destination
// leaves encapsulated toward its SID, a Local destination reaches the
// kernel, a spoofed source is dropped before anything encapsulates it, and
// releasing the claim removes the guard, the programs and the rows.
func TestRoutedLinkEgressRoot(t *testing.T) {
	e := newRoutedEgress(t, "egress")
	e.wantGuardFirst(t)
	e.wantEgress(t)
	if !e.r.planEmpty(e.a.vpc, e.claims) {
		t.Fatal("a programmed routed link plans writes")
	}
	if b, ok := e.blocked(); ok {
		t.Fatalf("the routed link reports its egress blocked: %+v", b)
	}

	// A Local destination passes to the kernel, both ways, and the guard
	// drops a spoofed source toward it.
	routedTraffic(t, e.r, e.a, e.pod, e.host, e.podEnd)

	e.remote()
	w := e.wire(t)
	conn := e.podConn(t, podAddr, 4443)
	e.sendRemote(t, w, conn, "to-remote")

	// A source the pod was not given never reaches the egress datapath.
	spoof := e.podConn(t, spoofSrc, 4443)
	before := e.r.stats()
	if _, err := spoof.WriteToUDP([]byte("spoofed-remote"),
		&net.UDPAddr{IP: net.IP(remoteDst.AsSlice()), Port: 9000}); err != nil {
		t.Fatal(err)
	}
	w.absent(t, "spoofed-remote")
	if after := e.r.stats(); after["guard_drop"] <= before["guard_drop"] {
		t.Fatalf("the guard dropped nothing: before %v after %v", before, after)
	}

	idx := e.hostIndex()
	if st := e.r.reconcile(e.a.vpc, nil); len(st) != 0 {
		t.Fatalf("the released claim still reports %v", st)
	}
	e.r.in(e.r.node, func() error {
		if _, err := netlink.LinkByName(e.host); err == nil {
			t.Fatalf("routed link %s outlived its claim", e.host)
		}
		return nil
	})
	e.wantNoEgress(t, idx)
	kinds, closer, err := ifindexvrfmap.OpenPinnedEgressKind(e.r.kernel.PinDir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = closer.Close() }()
	if _, ok, err := kinds.Get(idx); err != nil || ok {
		t.Fatalf("ifindex_egress_kind_table[%d] stays: %t %v", idx, ok, err)
	}
	// The VPC's own entries stay: galactic-cni's and galactic-router's.
	for _, p := range []netip.Prefix{netip.PrefixFrom(guestAddr, 128), netip.PrefixFrom(remoteDst, 128)} {
		if _, ok, err := e.r.routes.LookupRow(e.a.table, ipnet(p)); err != nil || !ok {
			t.Fatalf("entry %s went with the claim: %t %v", p, ok, err)
		}
	}
}

// TestRoutedLinkGuardOrderRoot checks that nothing puts the egress datapath
// ahead of a routed link's guard: galactic-cni's start-up reattach leaves it
// first, a program attached ahead of it later is put behind it on the next
// pass, and a guard that cannot be made first takes the egress datapath off
// the link, which keeps its Local destination and reports its Fabric
// destinations RoutedLinkEgressUnavailable.
func TestRoutedLinkGuardOrderRoot(t *testing.T) {
	e := newRoutedEgress(t, "order")
	e.remote()
	w := e.wire(t)
	conn := e.podConn(t, podAddr, 4443)

	// galactic-cni's start-up repair over every managed interface.
	e.r.in(e.r.node, func() error {
		if _, err := attach.ReattachEgress(e.r.usid.UsidServiceEgress, e.r.usid.UsidEgress,
			e.r.usid.AttachmentIdentityTable); err != nil {
			return err
		}
		if _, err := attach.ReattachDeliver(e.r.usid.TpDeliver); err != nil {
			return err
		}
		_, err := attach.SweepAttachmentIdentities(e.r.usid.AttachmentIdentityTable)
		return err
	})
	e.wantGuardFirst(t)
	e.wantEgress(t)
	if !e.r.planEmpty(e.a.vpc, e.claims) {
		t.Fatal("galactic-cni's reattach left the routed link to repair")
	}
	e.sendRemote(t, w, conn, "after-reattach")

	// Another agent attaches ahead of the guard: the next pass puts the
	// guard first again.
	first := foreignTCX(t)
	e.attachHead(first)
	e.r.read(e.a.vpc)
	if b, ok := e.blocked(); !ok || b.Reason != workerv1alpha1.ReasonRoutedLinkEgressUnavailable {
		t.Fatalf("a program ahead of the guard reports %+v (%t), want %s", b, ok,
			workerv1alpha1.ReasonRoutedLinkEgressUnavailable)
	}
	if e.r.planEmpty(e.a.vpc, e.claims) {
		t.Fatal("a program ahead of the guard plans nothing")
	}
	wantReady(t, e.r.reconcile(e.a.vpc, e.claims), e.claims)
	e.wantGuardFirst(t)
	e.wantEgress(t)
	if b, ok := e.blocked(); ok {
		t.Fatalf("the restored guard reports its egress blocked: %+v", b)
	}
	e.sendRemote(t, w, conn, "after-reassert")

	// The guard cannot be made first: the egress datapath goes, the Local
	// destination stays ready, and the Fabric destinations report why.
	orig := ensureTCXGuardFn
	t.Cleanup(func() { ensureTCXGuardFn = orig })
	ensureTCXGuardFn = func(_ *ebpf.Program, name string) error {
		return fmt.Errorf("%w on %q", attach.ErrGuardNotFirst, name)
	}
	second := foreignTCX(t)
	e.attachHead(second)
	idx := e.hostIndex()
	wantReady(t, e.r.reconcile(e.a.vpc, e.claims), e.claims)
	b, ok := e.blocked()
	if !ok || b.Reason != workerv1alpha1.ReasonRoutedLinkEgressUnavailable {
		t.Fatalf("a guard that cannot be first reports %+v (%t), want %s", b, ok,
			workerv1alpha1.ReasonRoutedLinkEgressUnavailable)
	}
	e.wantNoEgress(t, idx)
	if !e.r.planEmpty(e.a.vpc, e.claims) {
		t.Fatal("a guard that stayed behind the same program is moved again on every pass")
	}
	if _, err := conn.WriteToUDP([]byte("blocked"), &net.UDPAddr{IP: net.IP(remoteDst.AsSlice()),
		Port: 9000}); err != nil {
		t.Fatal(err)
	}
	w.absent(t, "blocked")

	// The program ahead goes: the guard is first again and the egress
	// datapath comes back.
	ensureTCXGuardFn = orig
	e.r.in(e.r.node, func() error {
		return link.RawDetachProgram(link.RawDetachProgramOptions{Target: int(idx), Program: second,
			Attach: ebpf.AttachTCXIngress})
	})
	wantReady(t, e.r.reconcile(e.a.vpc, e.claims), e.claims)
	e.wantGuardFirst(t)
	e.wantEgress(t)
	if b, ok := e.blocked(); ok {
		t.Fatalf("the guard first again reports its egress blocked: %+v", b)
	}
	e.sendRemote(t, w, conn, "after-unblock")
}

// TestRoutedLinkRestartRoot checks that a restarted Worker takes over the
// routed link from the guard an earlier Worker attached, with no moment
// unguarded, and leaves one guard, its own, first.
func TestRoutedLinkRestartRoot(t *testing.T) {
	e := newRoutedEgress(t, "egrestart")
	old := e.guardID()
	k2 := &Kernel{PinDir: e.r.kernel.PinDir, LocalPinDir: e.r.kernel.LocalPinDir,
		DispatchDir: e.r.kernel.DispatchDir, Pods: e.r.pods, NodeLocator: e.r.kernel.NodeLocator}
	t.Cleanup(func() { _ = k2.Close() })
	m2, err := New(Config{Kernel: k2, Node: testNode})
	if err != nil {
		t.Fatal(err)
	}
	// The earlier Worker's programs stay loaded only while attached.
	_ = e.r.kernel.Close()
	e.r.kernel, e.r.mod = k2, m2
	wantReady(t, e.r.reconcile(e.a.vpc, e.claims), e.claims)
	e.wantGuardFirst(t)
	chain := e.tcxChain(e.host)
	if len(chain) != 1 || chain[0] == old {
		t.Fatalf("tcx ingress of %s = %v after a restart, want only the new guard (the old was %d)", e.host,
			chain, old)
	}
	e.wantEgress(t)
	if !e.r.planEmpty(e.a.vpc, e.claims) {
		t.Fatal("the restarted Worker plans writes")
	}
}
