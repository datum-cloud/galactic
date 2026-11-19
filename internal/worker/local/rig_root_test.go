// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package local

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/safchain/ethtool"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"

	workerv1alpha1 "go.datum.net/galactic/api/galactic/worker/v1alpha1"
	"go.datum.net/galactic/internal/plumbing/ebpf/attach"
	"go.datum.net/galactic/internal/plumbing/ebpf/egressroutemap"
	"go.datum.net/galactic/internal/plumbing/ebpf/localprog"
	"go.datum.net/galactic/internal/plumbing/ebpf/localprog/localfixture"
	"go.datum.net/galactic/internal/plumbing/ebpf/prog"
	"go.datum.net/galactic/internal/plumbing/ebpf/tpmap"
	"go.datum.net/galactic/internal/plumbing/ebpf/uformat"
	"go.datum.net/galactic/internal/plumbing/ebpf/xdpdispatch"
	"go.datum.net/galactic/internal/plumbing/ebpf/xdpmode"
	"go.datum.net/galactic/internal/plumbing/intf"
	"go.datum.net/galactic/internal/trafficpolicy"
	"go.datum.net/galactic/internal/worker/module"
)

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("test requires root to load the datapath and build network namespaces; run task test:unit-root")
	}
	if _, err := os.Stat("/dev/net/tun"); err != nil {
		t.Skipf("test requires /dev/net/tun: %v", err)
	}
}

// The rig's documentation addresses. Both VPCs' guests use one address.
var (
	guestAddr = netip.MustParseAddr("fd20:80:ff03::1:0:0")
	nodeAddr  = netip.MustParseAddr("2001:db8:4135:1::1")
	client    = netip.MustParseAddr("2001:db8:4135:1::2")
	clientNet = netip.MustParsePrefix("2001:db8:4135:1::/64")
	vipNet    = netip.MustParsePrefix("2001:db8:4135:a::/64")
	shardNet  = netip.MustParsePrefix("2001:db8:4135:5::/64")
	guestMAC  = net.HardwareAddr{0x02, 0x47, 0, 0, 0, 0x01}
	// natTable stands in for the shard resolver (#1437): the client's prefix
	// steers into the VPC's pair.
	podAddr = netip.MustParseAddr("fd20:80:ff04::50")
)

const (
	testNode = "node-a"
	bondName = "bond0"
	// rxLower0 is the node's end of the receiving device.
	rxLower0 = "rx0"
	// clientLower is the client's end of the receiving device.
	clientLower = "cl0"
	cellVLAN    = "vlan"
	cellBond    = "bond"
	tpMark      = 0x0de10000
	vlanID      = 120
	tableBase   = 4100
)

// vpcRig is one VPC of the rig: its VRF, its TAP guest and what the gateway
// and NAT stand-ins use for it.
type vpcRig struct {
	vpc      string
	table    uint32
	argument uint16
	tap      string
	tapIdx   int
	tapMAC   net.HardwareAddr
	guest    *guest
	vip      netip.Addr
	shard    netip.Addr
	attUID   string
	natUID   string
}

// rig is a node namespace holding the VPCs, a receiving device and the
// datapath, and a client namespace on the far side of the receiving device.
type rig struct {
	t      *testing.T
	node   ns.NetNS
	client ns.NetNS
	pin    string
	usid   *prog.UsidObjects
	tp     *tpmap.Maps
	routes *egressroutemap.EgressRouteTable
	fix    localfixture.FixtureObjects
	disp   *xdpdispatch.Dispatcher
	mode   xdpmode.Mode
	cell   string

	// rx is the device local_rx runs on, rxLower the devices the dispatcher
	// runs on, out the device the NAT stand-in sends from.
	rx       string
	rxLower  []string
	out      string
	outVID   uint32
	clientIf string

	kernel *Kernel
	mod    *Module
	vpcs   []*vpcRig
	pods   *fakePods
}

func newRig(t *testing.T, cell string, mode xdpmode.Mode) *rig {
	t.Helper()
	requireRoot(t)
	r := &rig{t: t, cell: cell, mode: mode, pods: &fakePods{}}
	r.pin = fmt.Sprintf("/sys/fs/bpf/galactic-local-test-%d-%s", os.Getpid(), cell)
	_ = os.RemoveAll(r.pin)
	t.Cleanup(func() { _ = os.RemoveAll(r.pin) })

	var err error
	if r.node, err = ns.TempNetNS(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.node.Close() })
	if r.client, err = ns.TempNetNS(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.client.Close() })
	for _, n := range []ns.NetNS{r.node, r.client} {
		r.in(n, func() error {
			for _, k := range []string{"net/ipv6/conf/all/accept_dad", "net/ipv6/conf/default/accept_dad",
				"net/ipv6/conf/default/accept_ra"} {
				if err := os.WriteFile(filepath.Join("/proc/sys", k), []byte("0"), 0o644); err != nil {
					return err
				}
			}
			return os.WriteFile("/proc/sys/net/ipv6/conf/all/forwarding", []byte("1"), 0o644)
		})
	}

	if r.usid, err = attach.Load(r.pin + "/usid"); err != nil {
		t.Fatalf("load the uSID datapath: %v", err)
	}
	t.Cleanup(func() { _ = r.usid.Close() })
	if r.tp, err = tpmap.OpenPinned(r.pin + "/usid"); err != nil {
		t.Fatalf("open policy maps: %v", err)
	}
	t.Cleanup(r.tp.Close)
	table, closer, err := egressroutemap.OpenPinnedEgressRouteTable(r.pin + "/usid")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = closer.Close() })
	r.routes = table
	if err := r.tp.SetState(tpmap.State{Mode: tpmap.ModeEnforce, NATLocatorsSynced: true, Mark: tpMark,
		Capable: true}); err != nil {
		t.Fatal(err)
	}
	if err := localfixture.LoadFixtureObjects(&r.fix, nil); err != nil {
		t.Fatalf("load the fixture programs: %v", err)
	}
	t.Cleanup(func() { _ = r.fix.Close() })

	r.buildReceiver()
	r.vpcs = []*vpcRig{
		r.addVPC("80", 0x80, netip.MustParseAddr("2001:db8:4135:a::80"), netip.MustParseAddr("2001:db8:4135:5::80")),
		r.addVPC("81", 0x81, netip.MustParseAddr("2001:db8:4135:a::81"), netip.MustParseAddr("2001:db8:4135:5::81")),
	}
	r.buildDispatcher()

	r.kernel = &Kernel{PinDir: r.pin + "/usid", LocalPinDir: r.pin + "/local", DispatchDir: r.pin + "/xdp",
		Pods: r.pods}
	t.Cleanup(func() { _ = r.kernel.Close() })
	if r.mod, err = New(Config{Kernel: r.kernel, Node: testNode}); err != nil {
		t.Fatal(err)
	}
	return r
}

// in runs fn in n on a locked thread.
func (r *rig) in(n ns.NetNS, fn func() error) {
	r.t.Helper()
	if err := n.Do(func(ns.NetNS) error { return fn() }); err != nil {
		r.t.Fatal(err)
	}
}

func addrOn(name string, p netip.Prefix) error {
	l, err := netlink.LinkByName(name)
	if err != nil {
		return err
	}
	return netlink.AddrAdd(l, &netlink.Addr{IPNet: ipnet(p), Flags: unix.IFA_F_NODAD})
}

func up(name string) error {
	l, err := netlink.LinkByName(name)
	if err != nil {
		return err
	}
	return netlink.LinkSetUp(l)
}

// wireLike makes a veth end stand in for the far side of a physical link,
// which sends complete checksums. GRO stays as the kernel left it: what lets
// the client's end take a native redirect is the XDP program buildReceiver
// attaches.
func wireLike(name string) error {
	et, err := ethtool.NewEthtool()
	if err != nil {
		return err
	}
	defer et.Close()
	return et.Change(name, map[string]bool{featureTxChecksum: false, featureGRO: false})
}

// buildReceiver builds the receiving device for r.cell: a veth (plain), a
// VLAN on one (vlan), or an active-backup bond over two (bond).
func (r *rig) buildReceiver() {
	clientFd := int(r.client.Fd())
	pairs := []struct{ node, client string }{{rxLower0, clientLower}}
	if r.cell == cellBond {
		pairs = append(pairs, struct{ node, client string }{"rx1", "cl1"})
	}
	r.in(r.node, func() error {
		for _, p := range pairs {
			v := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: p.node, MTU: 1500}, PeerName: p.client,
				PeerNamespace: netlink.NsFd(clientFd)}
			if err := netlink.LinkAdd(v); err != nil {
				return err
			}
		}
		return nil
	})
	r.clientIf, r.rx = clientLower, rxLower0
	r.rxLower = []string{rxLower0}
	switch r.cell {
	case cellVLAN:
		r.rx, r.clientIf = fmt.Sprintf("rx0.%d", vlanID), fmt.Sprintf("cl0.%d", vlanID)
		r.out, r.outVID = rxLower0, vlanID
	case cellBond:
		r.rx, r.clientIf = bondName, bondName
		r.rxLower = []string{rxLower0, "rx1"}
		r.out = bondName
	default:
		r.out = rxLower0
	}
	build := func(side ns.NetNS, lowers []string, top string) {
		r.in(side, func() error {
			for _, l := range lowers {
				if err := wireLike(l); err != nil {
					return err
				}
			}
			switch r.cell {
			case cellVLAN:
				parent, err := netlink.LinkByName(lowers[0])
				if err != nil {
					return err
				}
				if err := netlink.LinkAdd(&netlink.Vlan{LinkAttrs: netlink.LinkAttrs{Name: top,
					ParentIndex: parent.Attrs().Index}, VlanId: vlanID}); err != nil {
					return err
				}
			case cellBond:
				b := netlink.NewLinkBond(netlink.LinkAttrs{Name: top})
				b.Mode = netlink.BOND_MODE_ACTIVE_BACKUP
				if err := netlink.LinkAdd(b); err != nil {
					return err
				}
				for _, l := range lowers {
					m, err := netlink.LinkByName(l)
					if err != nil {
						return err
					}
					if err := netlink.LinkSetBondSlave(m, &netlink.Bond{LinkAttrs: *b.Attrs()}); err != nil {
						return err
					}
				}
			}
			for _, l := range append(append([]string(nil), lowers...), top) {
				if err := up(l); err != nil {
					return err
				}
			}
			return nil
		})
	}
	clientLowers := []string{clientLower}
	if r.cell == cellBond {
		clientLowers = []string{clientLower, "cl1"}
	}
	build(r.node, r.rxLower, r.rx)
	build(r.client, clientLowers, r.clientIf)
	// The NAT stand-in redirects out of the node's end, natively, so the
	// client's end must run NAPI: an XDP program turns it on whatever the
	// kernel does with GRO. On a bond it goes to the members through the
	// bond.
	pass := clientLower
	if r.cell == cellBond {
		pass = bondName
	}
	r.in(r.client, func() error {
		l, err := netlink.LinkByName(pass)
		if err != nil {
			return err
		}
		return netlink.LinkSetXdpFdWithFlags(l, r.fix.LtfPass.FD(), xdpDrvMode)
	})
	r.in(r.node, func() error { return addrOn(r.rx, netip.PrefixFrom(nodeAddr, 64)) })
	r.in(r.client, func() error {
		if err := addrOn(r.clientIf, netip.PrefixFrom(client, 64)); err != nil {
			return err
		}
		l, err := netlink.LinkByName(r.clientIf)
		if err != nil {
			return err
		}
		for _, p := range []netip.Prefix{vipNet, shardNet} {
			if err := netlink.RouteAdd(&netlink.Route{LinkIndex: l.Attrs().Index, Dst: ipnet(p),
				Gw: net.IP(nodeAddr.AsSlice())}); err != nil {
				return err
			}
		}
		return nil
	})
}

// addVPC adds a VPC with a VRF, a TAP guest at guestAddr carrying
// galactic-cni's chain and registration, and its policy.
func (r *rig) addVPC(id string, argument uint16, vip, shard netip.Addr) *vpcRig {
	v := &vpcRig{vpc: "00000" + id, argument: argument, table: tableBase + uint32(argument), vip: vip, shard: shard,
		attUID: "00000000-0000-4000-8000-0000000000" + id, natUID: "00000000-0000-4000-8000-0000000001" + id}
	v.tap = intf.GenerateInterfaceNameHost(v.vpc, "001")
	r.in(r.node, func() error {
		vrf := &netlink.Vrf{LinkAttrs: netlink.LinkAttrs{Name: intf.GenerateInterfaceNameVRF(v.vpc)}, Table: v.table}
		if err := netlink.LinkAdd(vrf); err != nil {
			return err
		}
		return up(vrf.Name)
	})
	r.addTap(v)
	return v
}

// addTap creates v's TAP, as galactic-tap does, and its guest.
func (r *rig) addTap(v *vpcRig) {
	r.in(r.node, func() error {
		g, err := newGuest(v.tap)
		if err != nil {
			return err
		}
		v.guest = g
		r.t.Cleanup(g.close)
		l, err := netlink.LinkByName(v.tap)
		if err != nil {
			return err
		}
		vrf, err := netlink.LinkByName(intf.GenerateInterfaceNameVRF(v.vpc))
		if err != nil {
			return err
		}
		if err := netlink.LinkSetMaster(l, vrf); err != nil {
			return err
		}
		if err := netlink.LinkSetUp(l); err != nil {
			return err
		}
		if l, err = netlink.LinkByName(v.tap); err != nil {
			return err
		}
		v.tapIdx, v.tapMAC = l.Attrs().Index, l.Attrs().HardwareAddr
		g.hostMAC = v.tapMAC
		// The guest's own route, which galactic-tap installs.
		if err := netlink.RouteReplace(&netlink.Route{LinkIndex: v.tapIdx, Table: int(v.table),
			Dst: ipnet(netip.PrefixFrom(guestAddr, 128))}); err != nil {
			return err
		}
		if err := attach.AttachEgress(r.usid.UsidServiceEgress, r.usid.UsidEgress, v.tap); err != nil {
			return err
		}
		return attach.AttachDeliver(r.usid.TpDeliver, v.tap)
	})
	key, err := uformat.NewVRFKey(0x4135, v.argument)
	if err != nil {
		r.t.Fatal(err)
	}
	if err := r.usid.IfindexVrfTable.Put(uint32(v.tapIdx),
		prog.UsidIfindexVrfValue{Block: 0x4135, Argument: v.argument}); err != nil {
		r.t.Fatal(err)
	}
	if err := r.usid.VrfTable.Put(uint64(key), prog.UsidVrfValue{VrfTableId: v.table}); err != nil {
		r.t.Fatal(err)
	}
	if err := r.tp.PutInterface(uint32(v.tapIdx), 0x4135, tpmap.KindTenant); err != nil {
		r.t.Fatal(err)
	}
	r.policy(v)
}

// policy binds the handoff policy to v's TAP: every path is allowed except
// UDP port 9 on the public paths both ways, and a PublicService reply from
// the guest's port 8, so a request to port 8 is delivered and its reply
// denied.
func (r *rig) policy(v *vpcRig) {
	if v.tapIdx == 0 {
		return
	}
	port9 := trafficpolicy.PortRange{Start: 9, End: 9}
	allow := trafficpolicy.Entry{Flags: trafficpolicy.FlagAllow, Rule: 3}
	for dir, toGuest := range map[uint32]bool{tpmap.DirIngress: true, tpmap.DirEgress: false} {
		entries := []trafficpolicy.Entry{
			denyPort(0, trafficpolicy.PathPublicService, true, port9),
			denyPort(1, trafficpolicy.PathPublicNAT, true, port9),
			denyPort(2, trafficpolicy.PathPublicNAT, false, port9),
			allow,
		}
		if !toGuest {
			entries[0] = denyPort(0, trafficpolicy.PathPublicService, false, trafficpolicy.PortRange{Start: 8, End: 8})
		}
		if err := r.tp.Publish(uint32(v.tapIdx), dir, 0x4135, uint32(v.tapIdx)*4, entries); err != nil {
			r.t.Fatal(err)
		}
	}
}

// denyPort denies UDP on path from or to port.
func denyPort(rule uint16, path trafficpolicy.Path, dport bool, port trafficpolicy.PortRange) trafficpolicy.Entry {
	e := trafficpolicy.Entry{Flags: trafficpolicy.FlagPath | trafficpolicy.FlagProto, Rule: rule, Path: path,
		Proto: protoUDP}
	if dport {
		e.Flags |= trafficpolicy.FlagDestPorts
		e.DestPorts = port
	} else {
		e.Flags |= trafficpolicy.FlagSourcePorts
		e.SourcePorts = port
	}
	return e
}

// buildDispatcher puts the gateway stand-in in the public slot of the
// receiving device's dispatcher.
func (r *rig) buildDispatcher() {
	ctx := context.Background()
	var err error
	if r.disp, err = xdpdispatch.Open(ctx, r.pin+"/xdp", r.mode); err != nil {
		r.t.Fatal(err)
	}
	r.t.Cleanup(func() { _ = r.disp.Close() })
	r.in(r.node, func() error {
		lock, err := r.disp.Lock(ctx)
		if err != nil {
			return err
		}
		defer lock.Unlock()
		for _, name := range r.rxLower {
			l, err := netlink.LinkByName(name)
			if err != nil {
				return err
			}
			if _, err := lock.EnsureLink(l.Attrs().Index); err != nil {
				return fmt.Errorf("attach the dispatcher to %s: %w", name, err)
			}
			if err := lock.SetRole(l.Attrs().Index, xdpdispatch.RolePublicLB); err != nil {
				return err
			}
		}
		return lock.Fill(xdpdispatch.SlotGatewayLB, r.fix.LtfGateway)
	})
	for _, v := range r.vpcs {
		r.vip(v.vip, v.tapIdx, 0)
	}
}

// vip makes the gateway stand-in mark packets for addr with tapIdx and magic,
// the product's when 0.
func (r *rig) vip(addr netip.Addr, tapIdx int, magic uint32) {
	if magic == 0 {
		magic = 0x474c4d31
	}
	if err := r.fix.LtfVip.Put(localfixture.FixtureLtfIn6{A: addr.As16()},
		localfixture.FixtureLtfVipValue{TapIfindex: uint32(tapIdx), Magic: magic}); err != nil {
		r.t.Fatal(err)
	}
}

// claims returns a local.tap claim and a local.veth_pair claim for each VPC.
func (r *rig) claims(v *vpcRig) []module.Claim {
	dest := module.Destination{ID: "attachment/" + v.attUID, Mode: workerv1alpha1.Mode_MODE_LOCAL, VPC: v.vpc,
		Node: testNode, Addresses: []netip.Addr{guestAddr}, HostInterface: v.tap}
	return []module.Claim{
		{Key: module.ClaimKey{Node: testNode, VPC: v.vpc, AttachmentUID: "gw-" + v.vpc}, Owner: "galactic-system/gw",
			Generation: 1, Handoff: workerv1alpha1.Handoff_HANDOFF_TAP, Destinations: []module.Destination{dest}},
		{Key: module.ClaimKey{Node: testNode, VPC: v.vpc, AttachmentUID: v.natUID}, Owner: "galactic-system/nat",
			Generation: 1, Handoff: workerv1alpha1.Handoff_HANDOFF_VETH_PAIR, Destinations: []module.Destination{dest}},
	}
}

// reconcile plans, applies when needed, and reads one VPC's claims, as
// Worker's reconcile does, and returns the read-back.
func (r *rig) reconcile(vpc string, claims []module.Claim) module.State {
	r.t.Helper()
	var st module.State
	r.in(r.node, func() error {
		ctx := context.Background()
		scope := module.Scope{VPC: vpc}
		ch, err := r.mod.Plan(ctx, scope, claims)
		if err != nil {
			return err
		}
		if !ch.Empty() {
			if err := r.mod.Apply(ctx, scope, ch); err != nil {
				return err
			}
		}
		st, err = r.mod.Read(ctx, scope)
		return err
	})
	return st
}

// planEmpty reports whether a Plan of vpc's claims would write nothing.
func (r *rig) planEmpty(vpc string, claims []module.Claim) bool {
	r.t.Helper()
	empty := false
	r.in(r.node, func() error {
		ch, err := r.mod.Plan(context.Background(), module.Scope{VPC: vpc}, claims)
		if err != nil {
			return err
		}
		empty = ch.Empty()
		return nil
	})
	return empty
}

// natStandIn plays NAT for v: the client's prefix steers into v's pair, the
// NAT stand-in runs native on the pair's NAT end, and the gateway stand-in
// sends v's shard address back into the pair.
func (r *rig) natStandIn(v *vpcRig) {
	r.t.Helper()
	if err := r.routes.RegisterPassThroughAs(v.table, ipnet(clientNet), egressroutemap.PassThroughLocalNAT); err != nil {
		r.t.Fatal(err)
	}
	natName := linkName(v.vpc, v.natUID, intf.LocalRolePairNAT)
	tenantName := linkName(v.vpc, v.natUID, intf.LocalRolePairTenant)
	var natIdx int
	var natMAC, tenantMAC, outMAC, clientMAC net.HardwareAddr
	var outIdx int
	r.in(r.client, func() error {
		l, err := netlink.LinkByName(r.clientIf)
		if err != nil {
			return err
		}
		clientMAC = l.Attrs().HardwareAddr
		return nil
	})
	r.in(r.node, func() error {
		nat, err := netlink.LinkByName(natName)
		if err != nil {
			return err
		}
		tenant, err := netlink.LinkByName(tenantName)
		if err != nil {
			return err
		}
		out, err := netlink.LinkByName(r.out)
		if err != nil {
			return err
		}
		rx, err := netlink.LinkByName(r.rx)
		if err != nil {
			return err
		}
		natIdx, natMAC, tenantMAC = nat.Attrs().Index, nat.Attrs().HardwareAddr, tenant.Attrs().HardwareAddr
		outIdx, outMAC = out.Attrs().Index, rx.Attrs().HardwareAddr
		return netlink.LinkSetXdpFdWithFlags(nat, r.fix.LtfNat.FD(), int(xdpDrvMode))
	})
	snat := localfixture.FixtureLtfSnatValue{OutIfindex: uint32(outIdx), Vid: r.outVID, Guest: guestAddr.As16(),
		Shard: v.shard.As16()}
	copy(snat.Smac[:], outMAC)
	copy(snat.Dmac[:], clientMAC)
	if err := r.fix.LtfSnat.Put(uint32(natIdx), snat); err != nil {
		r.t.Fatal(err)
	}
	ret := localfixture.FixtureLtfShardValue{PeerIfindex: uint32(natIdx), Guest: guestAddr.As16()}
	copy(ret.Smac[:], natMAC)
	copy(ret.Dmac[:], tenantMAC)
	if err := r.fix.LtfShard.Put(localfixture.FixtureLtfIn6{A: v.shard.As16()}, ret); err != nil {
		r.t.Fatal(err)
	}
}

// xdpDrvMode is XDP_FLAGS_DRV_MODE.
const xdpDrvMode = 1 << 2

// clientSocket is a UDP socket in the client namespace.
type clientSocket struct {
	conn *net.UDPConn
}

func (r *rig) clientSocket(port int) *clientSocket {
	r.t.Helper()
	var c *net.UDPConn
	r.in(r.client, func() error {
		var err error
		c, err = net.ListenUDP("udp6", &net.UDPAddr{IP: net.IP(client.AsSlice()), Port: port})
		return err
	})
	r.t.Cleanup(func() { _ = c.Close() })
	return &clientSocket{conn: c}
}

func (c *clientSocket) send(t *testing.T, to netip.Addr, port int, payload string) {
	t.Helper()
	if _, err := c.conn.WriteToUDP([]byte(payload), &net.UDPAddr{IP: net.IP(to.AsSlice()), Port: port}); err != nil {
		t.Fatalf("send to %s: %v", to, err)
	}
}

// recv returns the next datagram within wait, and false when none arrives.
func (c *clientSocket) recv(wait time.Duration) (netip.Addr, string, bool) {
	buf := make([]byte, 2048)
	_ = c.conn.SetReadDeadline(time.Now().Add(wait))
	n, from, err := c.conn.ReadFromUDPAddrPort(buf)
	if err != nil {
		return netip.Addr{}, "", false
	}
	return from.Addr().Unmap(), string(buf[:n]), true
}

// expect reads datagrams until one carries payload, and fails unless it
// arrives from want.
func (c *clientSocket) expect(t *testing.T, want netip.Addr, payload string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		from, got, ok := c.recv(time.Until(deadline))
		if !ok {
			break
		}
		if got == payload {
			if from != want {
				t.Fatalf("%q arrived from %s, want %s", payload, from, want)
			}
			return
		}
	}
	t.Fatalf("the client never received %q", payload)
}

// absent fails if a datagram carrying payload arrives within a short wait.
func (c *clientSocket) absent(t *testing.T, payload string) {
	t.Helper()
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		_, got, ok := c.recv(time.Until(deadline))
		if !ok {
			return
		}
		if got == payload {
			t.Fatalf("the client received %q, which policy denies", payload)
		}
	}
}

// guest is a TAP's reader: the hypervisor and its guest. It answers
// Neighbor Discovery for guestAddr and queues every UDP frame.
type guest struct {
	file    *os.File
	hostMAC net.HardwareAddr
	frames  chan udpFrame
	done    chan struct{}
	once    sync.Once
}

func newGuest(name string) (*guest, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	ifr.SetUint16(unix.IFF_TAP | unix.IFF_NO_PI | unix.IFF_VNET_HDR)
	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("create TAP %s: %w", name, err)
	}
	g := &guest{file: os.NewFile(uintptr(fd), name), frames: make(chan udpFrame, 64), done: make(chan struct{})}
	go g.run()
	return g, nil
}

func (g *guest) close() {
	g.once.Do(func() {
		_ = g.file.Close()
		<-g.done
	})
}

func (g *guest) run() {
	defer close(g.done)
	buf := make([]byte, 65536)
	for {
		n, err := g.file.Read(buf)
		if err != nil {
			if errors.Is(err, os.ErrClosed) {
				return
			}
			continue
		}
		if n <= vnetHdrLen {
			continue
		}
		f := buf[vnetHdrLen:n]
		if target, from, mac, ok := neighborSolicitation(f); ok {
			if target == guestAddr {
				_, _ = g.file.Write(vnet(neighborAdvertisement(guestMAC, guestAddr, from, mac), false))
			}
			continue
		}
		if u, ok := parseUDP(f); ok {
			// The host hands a frame with a checksum to finish when its
			// sender left it; only the payload is compared then.
			if buf[0]&vnetNeedsCsum != 0 {
				u.checksumVerified = true
			}
			select {
			case g.frames <- u:
			default:
			}
		}
	}
}

// send writes a UDP frame from the guest to the host.
func (g *guest) send(t *testing.T, src, dst netip.Addr, sport, dport uint16, payload string, partial bool) {
	t.Helper()
	f := udp(guestMAC, g.hostMAC, src, dst, sport, dport, []byte(payload), partial)
	if _, err := g.file.Write(vnet(f, partial)); err != nil {
		t.Fatalf("guest send: %v", err)
	}
}

// expect returns the guest's next frame carrying payload.
func (g *guest) expect(t *testing.T, payload string) udpFrame {
	t.Helper()
	deadline := time.After(3 * time.Second)
	for {
		select {
		case u := <-g.frames:
			if string(u.payload) == payload {
				if !u.checksumVerified {
					t.Fatalf("%q reached the guest with a bad checksum", payload)
				}
				return u
			}
		case <-deadline:
			t.Fatalf("the guest never received %q", payload)
			return udpFrame{}
		}
	}
}

// absent fails if a frame carrying payload reaches the guest within a short
// wait.
func (g *guest) absent(t *testing.T, payload string) {
	t.Helper()
	deadline := time.After(500 * time.Millisecond)
	for {
		select {
		case u := <-g.frames:
			if string(u.payload) == payload {
				t.Fatalf("the guest received %q, which it must not", payload)
			}
		case <-deadline:
			return
		}
	}
}

// fakePods is a PodNetns over test namespaces, by pod UID.
type fakePods struct {
	mu   sync.Mutex
	pods map[string]ns.NetNS
}

func (f *fakePods) add(uid string, n ns.NetNS) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.pods == nil {
		f.pods = map[string]ns.NetNS{}
	}
	f.pods[uid] = n
}

func (f *fakePods) Open(uid string) (nsHandle, error) {
	f.mu.Lock()
	n, ok := f.pods[uid]
	f.mu.Unlock()
	if !ok {
		return nsNone(), fmt.Errorf("%w: pod %s", ErrPodNotFound, uid)
	}
	// A test namespace's path can name another thread's namespace; its
	// descriptor does not.
	fd, err := unix.Dup(int(n.Fd()))
	if err != nil {
		return nsNone(), err
	}
	return netns.NsHandle(fd), nil
}

type nsHandle = netns.NsHandle

func nsNone() netns.NsHandle { return netns.None() }

func statsOf(m *ebpf.Map) (map[string]uint64, error) { return localprog.Stats(m) }

// stats reads the Local counters.
func (r *rig) stats() map[string]uint64 {
	r.t.Helper()
	m, err := ebpf.LoadPinnedMap(filepath.Join(r.pin, "local", "lt_stats"), nil)
	if err != nil {
		r.t.Fatal(err)
	}
	defer m.Close() //nolint:errcheck // test descriptor
	s, err := statsOf(m)
	if err != nil {
		r.t.Fatal(err)
	}
	return s
}

// fixShard returns the gateway stand-in's return entry for shard.
func (r *rig) fixShard(shard netip.Addr) (localfixture.FixtureLtfShardValue, error) {
	var v localfixture.FixtureLtfShardValue
	err := r.fix.LtfShard.Lookup(localfixture.FixtureLtfIn6{A: shard.As16()}, &v)
	return v, err
}

// fixPutShard makes the gateway stand-in send a return for shard as v says.
func (r *rig) fixPutShard(shard netip.Addr, v localfixture.FixtureLtfShardValue) error {
	return r.fix.LtfShard.Put(localfixture.FixtureLtfIn6{A: shard.As16()}, v)
}
