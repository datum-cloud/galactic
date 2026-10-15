// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package prog

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// These tests drive the ingress traffic policy through the redirect lab: a
// real veth and tap attachment in a private namespace, fed encapsulated
// frames through usid_ingress. They write the policy maps directly, since
// tpmap, which normally writes them, imports this package. Each runs its
// steps in sequence on the lab's locked thread rather than in subtests,
// which could run on another thread outside the lab's namespace.

const (
	tpModeEnforce = 2
	tpDirIngress  = 0
	tpKindTenant  = 1
	tpFlagAllow   = 1 << 0
	tpFlagPath    = 1 << 1
	tpPathNAT     = 2
	tpTestMark    = 0x0de10000
	tpTestToken   = 0x5eed
)

func (lab *redirectLab) tpState(t *testing.T, synced bool) {
	t.Helper()
	v := UsidTpStateValue{Mode: tpModeEnforce, Mark: tpTestMark, Capable: 1}
	if synced {
		v.NatLocatorsSynced = 1
	}
	if err := lab.objs.TpState.Put(uint32(0), v); err != nil {
		t.Fatalf("write tp_state: %v", err)
	}
}

func (lab *redirectLab) tpIface(t *testing.T, ifindex uint32) {
	t.Helper()
	row := UsidTpIfaceValue{PolicyToken: tpTestToken, Kind: tpKindTenant}
	if err := lab.objs.TpIfaceTable.Put(ifindex, row); err != nil {
		t.Fatalf("write tp_iface_table: %v", err)
	}
}

// tpPublish binds a one-entry ingress snapshot to ifindex, counting into
// rule counter row ifindex.
func (lab *redirectLab) tpPublish(t *testing.T, ifindex uint32, entry UsidTpEntry) {
	t.Helper()
	inner, err := ebpf.NewMap(&ebpf.MapSpec{
		Type: ebpf.Array, KeySize: 4, ValueSize: uint32(binary.Size(UsidTpEntry{})), MaxEntries: 257,
	})
	if err != nil {
		t.Fatalf("create snapshot: %v", err)
	}
	defer inner.Close() //nolint:errcheck // the outer map holds a reference
	if err := inner.Put(uint32(0), UsidTpHeader{PolicyToken: tpTestToken, CounterBase: ifindex, Count: 1}); err != nil {
		t.Fatalf("write header: %v", err)
	}
	if err := inner.Put(uint32(1), entry); err != nil {
		t.Fatalf("write entry: %v", err)
	}
	if err := lab.objs.TpBindingTable.Put(UsidTpBindingKey{Ifindex: ifindex, Direction: tpDirIngress}, inner); err != nil {
		t.Fatalf("bind snapshot: %v", err)
	}
}

func (lab *redirectLab) tpHits(t *testing.T, row uint32) uint64 {
	t.Helper()
	var per []UsidTpCounter
	if err := lab.objs.TpRuleCounters.Lookup(row, &per); err != nil {
		t.Fatalf("read rule counter %d: %v", row, err)
	}
	var n uint64
	for _, c := range per {
		n += c.Packets
	}
	return n
}

func (lab *redirectLab) assertNotDelivered(t *testing.T, fd int, read frameReader, label string, innerDst []byte) {
	t.Helper()
	marker := lab.send(t, innerDst, label)
	if awaitMarker(t, fd, marker, quietWait, read) {
		t.Errorf("%s: frame was delivered, want it denied", label)
	}
}

// TestUsidIngress_TrafficPolicyDecidesDelivery covers the receiving
// workload's policy on both delivery helpers: no interface row and a
// deny-all deny; an allow-all delivers, counted once.
func TestUsidIngress_TrafficPolicyDecidesDelivery(t *testing.T) {
	lab := newRedirectLab(t)
	lab.registerVeth(t)
	lab.tpState(t, true)

	lab.assertNotDelivered(t, lab.vethPeerCapture, readCapture(false), "veth, no interface row", vethInnerDst)

	lab.tpIface(t, lab.vethIfindex)
	lab.tpPublish(t, lab.vethIfindex, UsidTpEntry{})
	lab.assertNotDelivered(t, lab.vethPeerCapture, readCapture(false), "veth, deny-all", vethInnerDst)
	if n := lab.tpHits(t, lab.vethIfindex); n != 1 {
		t.Errorf("deny-all hits = %d, want 1", n)
	}

	lab.tpPublish(t, lab.vethIfindex, UsidTpEntry{Flags: tpFlagAllow})
	lab.assertVethDelivers(t, "veth, allow-all", true)
	if n := lab.tpHits(t, lab.vethIfindex); n != 2 {
		t.Errorf("hits after the allowed frame = %d, want 2", n)
	}
}

// TestUsidIngress_TrafficPolicyDecidesOnceOnTap checks a tap delivery,
// which plain bpf_redirect transmits through the tap's tc egress, is decided
// by usid_ingress and passed by tp_deliver without being counted again.
func TestUsidIngress_TrafficPolicyDecidesOnceOnTap(t *testing.T) {
	lab := newRedirectLab(t)
	lab.registerTap(t)
	lab.tpState(t, true)
	lab.tpIface(t, lab.tapIfindex)
	tap, err := netlink.LinkByIndex(int(lab.tapIfindex))
	if err != nil {
		t.Fatal(err)
	}
	attachEgress(t, tap, lab.objs.TpDeliver)

	lab.tpPublish(t, lab.tapIfindex, UsidTpEntry{Flags: tpFlagAllow})
	lab.assertTapDelivers(t, "tap, allow-all")
	if n := lab.tpHits(t, lab.tapIfindex); n != 1 {
		t.Errorf("hits = %d, want 1: tp_deliver must skip a packet usid_ingress decided", n)
	}

	lab.tpPublish(t, lab.tapIfindex, UsidTpEntry{})
	marker := lab.send(t, tapInnerDst, "tap, deny-all")
	if awaitMarker(t, lab.tapFd, marker, quietWait, readTap) {
		t.Error("tap, deny-all: frame was delivered")
	}
}

// TestUsidIngress_TrafficPolicyClassifiesNATReturns checks the outer source
// decides the path: a frame from a NAT shard's SID is PublicNAT, any other
// Private, and before the NAT locators sync a path rule denies.
func TestUsidIngress_TrafficPolicyClassifiesNATReturns(t *testing.T) {
	lab := newRedirectLab(t)
	lab.registerVeth(t)
	lab.tpState(t, true)
	lab.tpIface(t, lab.vethIfindex)
	lab.tpPublish(t, lab.vethIfindex, UsidTpEntry{Flags: tpFlagAllow | tpFlagPath, Path: tpPathNAT})

	// send uses outer source 2001:db8::1, whose top 64 bits are the locator.
	lab.assertNotDelivered(t, lab.vethPeerCapture, readCapture(false), "not from a shard", vethInnerDst)

	locator := binary.NativeEndian.Uint64([]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0})
	if err := lab.objs.TpNatLocatorTable.Put(locator, uint8(1)); err != nil {
		t.Fatal(err)
	}
	lab.assertVethDelivers(t, "from a shard", true)

	lab.tpState(t, false)
	lab.assertNotDelivered(t, lab.vethPeerCapture, readCapture(false), "before the locators sync", vethInnerDst)
}

func attachEgress(t *testing.T, link netlink.Link, program *ebpf.Program) {
	t.Helper()
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: link.Attrs().Index, Handle: netlink.MakeHandle(0xffff, 0), Parent: netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}
	if err := netlink.QdiscReplace(qdisc); err != nil {
		t.Fatalf("add clsact qdisc to %s: %v", link.Attrs().Name, err)
	}
	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index, Parent: netlink.HANDLE_MIN_EGRESS, Handle: netlink.MakeHandle(0, 1),
			Protocol: unix.ETH_P_ALL, Priority: 1,
		},
		Fd: program.FD(), Name: "tp_deliver_test", DirectAction: true,
	}
	if err := netlink.FilterAdd(filter); err != nil {
		t.Fatalf("attach tp_deliver to %s: %v", link.Attrs().Name, err)
	}
}

// sendInner6 writes one encapsulated frame carrying inner, an IPv6 packet,
// into the lab's uplink.
func (lab *redirectLab) sendInner6(t *testing.T, inner []byte) {
	t.Helper()
	frame := make([]byte, 0, ethHeaderLen+ip6HeaderLen+len(inner))
	frame = append(frame, lab.uplinkMAC...)
	frame = append(frame, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x86, 0xDD)
	frame = append(frame, 0x60, 0x00, 0x00, 0x00, byte(len(inner)>>8), byte(len(inner)), 41, 64)
	src := [16]byte{0x20, 0x01, 0x0d, 0xb8, 15: 0x01}
	frame = append(frame, src[:]...)
	dst := baseUSID.addr(t).As16()
	frame = append(frame, dst[:]...)
	frame = append(frame, inner...)
	if _, err := unix.Write(lab.uplinkFd, frame); err != nil {
		t.Fatalf("write frame into uplink tap: %v", err)
	}
}

// TestUsidIngress_TunneledNeighborDiscoveryIsNotALinkOperation checks a
// neighbor solicitation that arrives through the fabric with hop limit 255
// is ordinary traffic: it came from another node, so the link-operation
// exception would let a remote tenant spoof neighbor discovery past policy.
func TestUsidIngress_TunneledNeighborDiscoveryIsNotALinkOperation(t *testing.T) {
	lab := newRedirectLab(t)
	lab.registerVeth(t)
	lab.tpState(t, true)
	lab.tpIface(t, lab.vethIfindex)

	dst := lab.addUnresolvedVethHost(t, "fd00:3::1/64", "fd00:3::10/64")

	// A Neighbor Solicitation: type 135, code 0, 4 reserved bytes and a
	// 16-byte target, hop limit 255.
	ns := func(marker string) []byte {
		icmp := append([]byte{135, 0, 0, 0, 0, 0, 0, 0}, dst.To16()...)
		icmp = append(icmp, marker...)
		inner := []byte{0x60, 0, 0, 0, byte(len(icmp) >> 8), byte(len(icmp)), 58, 255}
		// A routable source: the kernel's FIB lookup will not forward a
		// link-local one, and the ingress link-operation check never looks
		// at the source anyway, only the hop limit.
		inner = append(inner, net.ParseIP("fd00:9::66").To16()...)
		inner = append(inner, dst.To16()...)
		return append(inner, icmp...)
	}

	// With an allow-all it is delivered, which shows the path works.
	lab.tpPublish(t, lab.vethIfindex, UsidTpEntry{Flags: tpFlagAllow})
	const allowed = "galactic-tunneled-ns-allowed-0001"
	lab.sendInner6(t, ns(allowed))
	if !awaitMarker(t, lab.vethPeerCapture, []byte(allowed), deliveryWait, readCapture(false)) {
		t.Fatal("a tunneled neighbor solicitation was not delivered under an allow-all")
	}
	// With a deny-all it is decided by the rule, not passed as a link
	// operation.
	lab.tpPublish(t, lab.vethIfindex, UsidTpEntry{})
	before := lab.tpHits(t, lab.vethIfindex)
	lab.sendInner6(t, ns("galactic-tunneled-ns-denied-0001"))
	if awaitMarker(t, lab.vethPeerCapture, []byte("galactic-tunneled-ns-denied-0001"), quietWait, readCapture(false)) {
		t.Error("a tunneled neighbor solicitation was delivered past a deny-all")
	}
	if n := lab.tpHits(t, lab.vethIfindex) - before; n != 1 {
		t.Errorf("deny-all hits = %d, want 1: it must be decided by the rules", n)
	}
}
