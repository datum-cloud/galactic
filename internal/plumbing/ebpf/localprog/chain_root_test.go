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

	"github.com/cilium/ebpf"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"go.datum.net/galactic/internal/plumbing/ebpf/attach"
	"go.datum.net/galactic/internal/plumbing/ebpf/egressroutemap"
	"go.datum.net/galactic/internal/plumbing/ebpf/prog"
	"go.datum.net/galactic/internal/plumbing/ebpf/uformat"
	"go.datum.net/galactic/internal/plumbing/ebpf/usidmap"
)

const (
	chainTenantLink  = "tenant0"
	chainGuestLink   = "guest0"
	chainPairTenant  = "pairt0"
	chainPairNATLink = "pairn0"

	chainTable    = 77
	chainBlock    = 0x20010db8ff01
	chainArgument = 0x1a5
)

var (
	chainGuest    = netip.MustParseAddr("2001:db8:77::5")
	chainInternet = netip.MustParseAddr("2001:db8:ffff::1")
)

// chain is a tenant interface whose tc ingress runs galactic-cni's
// usid_egress and then Local's local_link_rx, the order the two filters
// have on a node, and a service-internal veth pair for its VPC.
type chain struct {
	t       *testing.T
	n       ns.NetNS
	usid    *prog.UsidObjects
	local   *Objects
	guest   netlink.Link // the guest's end of the tenant link
	tenant  netlink.Link // the tenant interface: the host's end
	pairT   netlink.Link // the pair's tenant end
	pairNAT netlink.Link // the pair's NAT end
	rx, tx  int          // AF_PACKET sockets on the NAT end and the guest end
}

func newChain(t *testing.T) *chain {
	t.Helper()
	requireRoot(t)
	base := fmt.Sprintf("/sys/fs/bpf/galactic-localchain-test-%d", os.Getpid())
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

	c := &chain{t: t, usid: usid, local: local}
	if c.n, err = ns.TempNetNS(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.n.Close() })
	c.in(func() error {
		for _, k := range []string{"net/ipv6/conf/all/accept_dad", "net/ipv6/conf/default/accept_dad"} {
			if err := os.WriteFile(filepath.Join("/proc/sys", k), []byte("0"), 0o644); err != nil {
				return err
			}
		}
		for _, v := range []*netlink.Veth{
			{LinkAttrs: netlink.LinkAttrs{Name: chainTenantLink}, PeerName: chainGuestLink},
			{LinkAttrs: netlink.LinkAttrs{Name: chainPairTenant}, PeerName: chainPairNATLink},
		} {
			if err := netlink.LinkAdd(v); err != nil {
				return err
			}
		}
		for _, name := range []string{chainTenantLink, chainGuestLink, chainPairTenant, chainPairNATLink} {
			l, err := netlink.LinkByName(name)
			if err != nil {
				return err
			}
			if err := netlink.LinkSetUp(l); err != nil {
				return err
			}
			switch name {
			case chainTenantLink:
				c.tenant = l
			case chainGuestLink:
				c.guest = l
			case chainPairTenant:
				c.pairT = l
			case chainPairNATLink:
				c.pairNAT = l
			}
		}
		if err := netlink.QdiscAdd(&netlink.GenericQdisc{QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: c.tenant.Attrs().Index, Handle: netlink.MakeHandle(0xffff, 0), Parent: netlink.HANDLE_CLSACT,
		}, QdiscType: "clsact"}); err != nil {
			return err
		}
		for prio, p := range map[uint16]*ebpf.Program{1: usid.UsidEgress, 2: local.Programs.LinkRx} {
			if err := netlink.FilterAdd(&netlink.BpfFilter{
				FilterAttrs: netlink.FilterAttrs{LinkIndex: c.tenant.Attrs().Index, Parent: netlink.HANDLE_MIN_INGRESS,
					Priority: prio, Protocol: unix.ETH_P_ALL},
				Fd: p.FD(), Name: fmt.Sprintf("chain-%d", prio), DirectAction: true,
			}); err != nil {
				return err
			}
		}
		var err error
		if c.rx, err = packetSocket(c.pairNAT.Attrs().Index); err != nil {
			return err
		}
		c.tx, err = packetSocket(c.guest.Attrs().Index)
		return err
	})
	t.Cleanup(func() { _ = unix.Close(c.rx); _ = unix.Close(c.tx) })

	c.populate()
	return c
}

func (c *chain) in(fn func() error) {
	c.t.Helper()
	if err := c.n.Do(func(ns.NetNS) error { return fn() }); err != nil {
		c.t.Fatal(err)
	}
}

func packetSocket(ifindex int) (int, error) {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return -1, err
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_ALL), Ifindex: ifindex}); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	tv := unix.Timeval{Usec: 100_000}
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }

// populate writes what galactic-cni and Local write for one attachment of
// VPC chainArgument: its VRF and table, the node's source SID, the VPC's
// ::/0 on the NAT66 group, a group whose only member is this node's own
// shard, and Local's lt_link row naming the VPC's pair.
func (c *chain) populate() {
	t := c.t
	tenant := uint32(c.tenant.Attrs().Index) //nolint:gosec // a kernel ifindex
	if err := c.usid.IfindexVrfTable.Put(tenant, prog.UsidIfindexVrfValue{Block: chainBlock,
		Argument: chainArgument}); err != nil {
		t.Fatal(err)
	}
	vrfKey, err := uformat.NewVRFKey(chainBlock, chainArgument)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.usid.VrfTable.Put(uint64(vrfKey), prog.UsidVrfValue{VrfTableId: chainTable}); err != nil {
		t.Fatal(err)
	}
	src := netip.MustParseAddr("2001:db8:ff01:1:e000::").As16()
	if err := c.usid.NodeSrcAddrTable.Put(uint32(0), src); err != nil {
		t.Fatal(err)
	}
	routes := egressroutemap.NewEgressRouteTable(usidmap.KernelTable{Map: c.usid.EgressRouteTable})
	if err := routes.RegisterGroup(chainTable, egressroutemap.DefaultPrefix, egressroutemap.NAT66ShardGroup,
		chainArgument); err != nil {
		t.Fatal(err)
	}
	groups := egressroutemap.NewShardGroupTable(egressroutemap.NewKernelGroupStore(c.usid.EgressShardGroups)).
		WithLocalView(egressroutemap.NewKernelGroupStore(c.usid.EgressShardLocalGroups))
	if _, err := groups.Apply(egressroutemap.NAT66ShardGroup, egressroutemap.GroupPolicy{},
		[]egressroutemap.ShardCandidate{{SID: net.IP(chainShard().AsSlice()), Local: true}}); err != nil {
		t.Fatal(err)
	}
	c.setPair(uint32(c.pairT.Attrs().Index)) //nolint:gosec // a kernel ifindex
}

func chainShard() netip.Addr {
	a, err := uformat.Encode(uformat.Fields{Block: 0x20010db8ff09, NodeID: 0x10, Function: uformat.FunctionEndDT46})
	if err != nil {
		panic(err)
	}
	return a
}

func (c *chain) setPair(pair uint32) {
	c.t.Helper()
	v := LocalLtLinkValue{TableId: chainTable, PairIfindex: pair}
	copy(v.PairSmac[:], c.pairT.Attrs().HardwareAddr)
	copy(v.PairDmac[:], c.pairNAT.Attrs().HardwareAddr)
	if err := c.local.Maps.Link.Put(uint32(c.tenant.Attrs().Index), v); err != nil { //nolint:gosec // ifindex
		c.t.Fatal(err)
	}
}

func (c *chain) row(present bool) {
	c.t.Helper()
	tbl := egressroutemap.NewLocalShardTable(c.usid.EgressLocalShard)
	var err error
	if present {
		err = tbl.Put(chainTable, egressroutemap.LocalShard{ShardSID: chainShard(),
			PairIfindex: uint32(c.pairT.Attrs().Index)}) //nolint:gosec // a kernel ifindex
	} else {
		err = tbl.Delete(chainTable)
	}
	if err != nil {
		c.t.Fatal(err)
	}
}

// send writes a UDP frame from the guest toward the internet, carrying
// payload.
func (c *chain) send(payload string) {
	c.t.Helper()
	udpLen := 8 + len(payload)
	frame := make([]byte, 0, 14+40+udpLen)
	frame = append(frame, c.tenant.Attrs().HardwareAddr...)
	frame = append(frame, c.guest.Attrs().HardwareAddr...)
	frame = append(frame, 0x86, 0xDD, 0x60, 0, 0, 0)
	frame = binary.BigEndian.AppendUint16(frame, uint16(udpLen)) //nolint:gosec // small
	frame = append(frame, 17, 64)
	s, d := chainGuest.As16(), chainInternet.As16()
	frame = append(frame, s[:]...)
	frame = append(frame, d[:]...)
	frame = binary.BigEndian.AppendUint16(frame, 40000)
	frame = binary.BigEndian.AppendUint16(frame, 53)
	frame = binary.BigEndian.AppendUint16(frame, uint16(udpLen)) //nolint:gosec // small
	frame = append(frame, 0, 0)
	frame = append(frame, payload...)
	if err := unix.Sendto(c.tx, frame, 0, &unix.SockaddrLinklayer{Ifindex: c.guest.Attrs().Index,
		Halen: 6, Addr: [8]byte(append(append([]byte{}, c.tenant.Attrs().HardwareAddr...), 0, 0))}); err != nil {
		c.t.Fatal(err)
	}
}

// arrived reports whether a frame carrying payload reached the pair's NAT
// end within wait, and returns it.
func (c *chain) arrived(payload string, wait time.Duration) ([]byte, bool) {
	buf := make([]byte, 2048)
	deadline := time.Now().Add(wait)
	for time.Now().Before(deadline) {
		n, _, err := unix.Recvfrom(c.rx, buf, 0)
		if err != nil {
			continue
		}
		if bytes.Contains(buf[:n], []byte(payload)) {
			return append([]byte(nil), buf[:n]...), true
		}
	}
	return nil, false
}

func (c *chain) localStat(name string) uint64 {
	c.t.Helper()
	s, err := Stats(c.local.Maps.Stats)
	if err != nil {
		c.t.Fatal(err)
	}
	return s[name]
}

func shardStat(t *testing.T, m *ebpf.Map, index uint32) uint64 {
	t.Helper()
	var perCPU []uint64
	if err := m.Lookup(index, &perCPU); err != nil {
		t.Fatal(err)
	}
	var n uint64
	for _, v := range perCPU {
		n += v
	}
	return n
}

// TestChainRoot_LocalShardMarkerEntersThePair runs the real tc chain: the
// marker usid_egress leaves in skb->cb survives to local_link_rx on the same
// ingress, which sends the packet into the VPC's pair, where it arrives on
// the NAT end unencapsulated and readdressed to it.
func TestChainRoot_LocalShardMarkerEntersThePair(t *testing.T) {
	c := newChain(t)

	// No row: the base view has no member that can take the packet, so it
	// is dropped as an empty group, never handed to the pair.
	empty := shardStat(t, c.usid.EgressShardStats, prog.EgressShardStatGroupEmpty)
	c.send("no-row")
	if _, ok := c.arrived("no-row", 300*time.Millisecond); ok {
		t.Fatal("a packet with no egress_local_shard row reached the pair")
	}
	if shardStat(t, c.usid.EgressShardStats, prog.EgressShardStatGroupEmpty) == empty {
		t.Error("the no-row packet was not counted as an empty group")
	}

	c.row(true)
	c.send("with-row")
	frame, ok := c.arrived("with-row", time.Second)
	if !ok {
		t.Fatalf("the packet never reached the pair's NAT end; Local stats %v", mustStats(t, c.local.Maps.Stats))
	}
	natMAC, tenantMAC := c.pairNAT.Attrs().HardwareAddr, c.pairT.Attrs().HardwareAddr
	if !bytes.Equal(frame[0:6], natMAC) || !bytes.Equal(frame[6:12], tenantMAC) {
		t.Errorf("frame addressed %x from %x, want the NAT end from the tenant end", frame[0:6], frame[6:12])
	}
	if binary.BigEndian.Uint16(frame[12:14]) != 0x86DD || !bytes.Equal(frame[14+24:14+40], chainInternet.AsSlice()) {
		t.Errorf("frame is not the tenant's own unencapsulated packet: %x", frame[:54])
	}
	if got := c.localStat("link_local_shard"); got != 1 {
		t.Errorf("lt_stats[link_local_shard] = %d, want 1", got)
	}
	if got := shardStat(t, c.usid.EgressShardStats, prog.EgressShardStatLocal); got != 1 {
		t.Errorf("egress_shard_stats[local] = %d, want 1", got)
	}

	// The VPC has no pair on this node: dropped and counted, never sent on.
	c.setPair(0)
	c.send("no-pair")
	if _, ok := c.arrived("no-pair", 300*time.Millisecond); ok {
		t.Fatal("a packet for a VPC with no pair reached the pair")
	}
	if got := c.localStat("link_local_shard_no_pair"); got != 1 {
		t.Errorf("lt_stats[link_local_shard_no_pair] = %d, want 1", got)
	}
}

func mustStats(t *testing.T, m *ebpf.Map) map[string]uint64 {
	t.Helper()
	s, err := Stats(m)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// sendL4 writes a frame from the guest toward dst whose IPv6 next header is
// nexthdr and whose payload is l4, to dst's multicast MAC for a multicast
// destination and to the tenant interface otherwise.
func (c *chain) sendL4(dst netip.Addr, nexthdr byte, l4 []byte) {
	c.t.Helper()
	d := dst.As16()
	dmac := []byte(c.tenant.Attrs().HardwareAddr)
	if d[0] == 0xff {
		dmac = []byte{0x33, 0x33, d[12], d[13], d[14], d[15]}
	}
	frame := make([]byte, 0, 14+40+len(l4))
	frame = append(frame, dmac...)
	frame = append(frame, c.guest.Attrs().HardwareAddr...)
	frame = append(frame, 0x86, 0xDD, 0x60, 0, 0, 0)
	frame = binary.BigEndian.AppendUint16(frame, uint16(len(l4))) //nolint:gosec // small
	frame = append(frame, nexthdr, 255)
	s := chainGuest.As16()
	frame = append(frame, s[:]...)
	frame = append(frame, d[:]...)
	frame = append(frame, l4...)
	if err := unix.Sendto(c.tx, frame, 0, &unix.SockaddrLinklayer{Ifindex: c.guest.Attrs().Index,
		Halen: 6, Addr: [8]byte(append(append([]byte{}, dmac...), 0, 0))}); err != nil {
		c.t.Fatal(err)
	}
}

// neighborSolicitation returns an ICMPv6 Neighbor Solicitation for target,
// followed by marker.
func neighborSolicitation(target netip.Addr, marker string) []byte {
	b := []byte{135, 0, 0, 0, 0, 0, 0, 0}
	tgt := target.As16()
	b = append(b, tgt[:]...)
	return append(b, marker...)
}

// udpTo returns a UDP header and marker as a payload.
func udpTo(marker string) []byte {
	b := binary.BigEndian.AppendUint16(nil, 40000)
	b = binary.BigEndian.AppendUint16(b, 53)
	b = binary.BigEndian.AppendUint16(b, uint16(8+len(marker))) //nolint:gosec // small
	b = append(b, 0, 0)
	return append(b, marker...)
}

// TestChainRoot_OrderedLocalRouteLeavesLinkTraffic gives the VPC the class
// route ordered mode writes for a Local shard, a PassThroughLocalNAT ::/0,
// and checks it takes only traffic bound off the link into the pair. A
// guest's Neighbor Solicitation for its gateway, multicast or unicast, and
// anything to a link-local address stay with this host: steering them into
// the pair would leave the guest unable to resolve its gateway, so no
// packet of its would ever leave it.
func TestChainRoot_OrderedLocalRouteLeavesLinkTraffic(t *testing.T) {
	c := newChain(t)
	routes := egressroutemap.NewEgressRouteTable(usidmap.KernelTable{Map: c.usid.EgressRouteTable})
	_, all, _ := net.ParseCIDR("::/0")
	if err := routes.RegisterPassThroughAs(chainTable, all, egressroutemap.PassThroughLocalNAT); err != nil {
		t.Fatal(err)
	}

	c.send("internet")
	if _, ok := c.arrived("internet", time.Second); !ok {
		t.Fatalf("a packet to the internet never entered the pair; Local stats %v", mustStats(t, c.local.Maps.Stats))
	}
	if got := c.localStat("link_nat"); got != 1 {
		t.Fatalf("lt_stats[link_nat] = %d, want 1", got)
	}

	gateway := netip.MustParseAddr("2001:db8:77::1")
	solicited := netip.MustParseAddr("ff02::1:ff00:1")
	for _, tc := range []struct {
		name, marker string
		dst          netip.Addr
		nexthdr      byte
		l4           []byte
	}{
		{"multicast solicitation", "ns-multicast", solicited, 58, neighborSolicitation(gateway, "ns-multicast")},
		{"unicast solicitation", "ns-unicast", gateway, 58, neighborSolicitation(gateway, "ns-unicast")},
		{"link-local destination", "to-link-local", netip.MustParseAddr("fe80::1"), 17, udpTo("to-link-local")},
	} {
		c.sendL4(tc.dst, tc.nexthdr, tc.l4)
		if _, ok := c.arrived(tc.marker, 300*time.Millisecond); ok {
			t.Errorf("%s: the class route took it into the pair", tc.name)
		}
	}
	if got := c.localStat("link_nat"); got != 1 {
		t.Errorf("lt_stats[link_nat] = %d after link traffic, want still 1", got)
	}
}
