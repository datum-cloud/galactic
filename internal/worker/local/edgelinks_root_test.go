// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package local

import (
	"net"
	"net/netip"
	"testing"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"

	workerv1alpha1 "go.datum.net/galactic/api/galactic/worker/v1alpha1"
	"go.datum.net/galactic/internal/edge/hostattach"
	"go.datum.net/galactic/internal/plumbing/ebpf/forwardgatemap"
	"go.datum.net/galactic/internal/plumbing/ebpf/prog"
	"go.datum.net/galactic/internal/plumbing/ebpf/tpmap"
	"go.datum.net/galactic/internal/plumbing/ebpf/xdpmode"
	"go.datum.net/galactic/internal/plumbing/intf"
	"go.datum.net/galactic/internal/trafficpolicy"
	"go.datum.net/galactic/internal/worker/module"
)

// The edge link of a connector claim, as galactic-edge creates it: a veth
// from the VPC's VRF to a provider pod, stamped with the attachment's ID.
var edgeLinkAddr = netip.MustParseAddr("2001:db8:4135:e::10")

const (
	edgeHostEnd = "Eedge0"
	edgeProvEnd = "pe0"
	edgeUID     = "00000000-0000-4000-8000-0000000000ee"
)

// edgeRig adds an edge link to v's VRF and a provider namespace on its far
// side, and writes the link's gate row, as galactic-edge does before it
// claims the link. It returns the provider namespace and the host end's
// ifindex.
func (r *rig) edgeRig(v *vpcRig) (ns.NetNS, uint32) {
	r.t.Helper()
	prov, err := ns.TempNetNS()
	if err != nil {
		r.t.Fatal(err)
	}
	r.t.Cleanup(func() { _ = prov.Close() })
	var idx uint32
	r.in(r.node, func() error {
		veth := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: edgeHostEnd}, PeerName: edgeProvEnd}
		if err := netlink.LinkAdd(veth); err != nil {
			return err
		}
		l, err := netlink.LinkByName(edgeHostEnd)
		if err != nil {
			return err
		}
		if err := netlink.LinkSetAlias(l, hostattach.Alias(hostattach.LinkID(v.vpc, edgeUID))); err != nil {
			return err
		}
		vrf, err := netlink.LinkByName(intf.GenerateInterfaceNameVRF(v.vpc))
		if err != nil {
			return err
		}
		if err := netlink.LinkSetMaster(l, vrf); err != nil {
			return err
		}
		peer, err := netlink.LinkByName(edgeProvEnd)
		if err != nil {
			return err
		}
		if err := netlink.LinkSetNsFd(peer, int(prov.Fd())); err != nil {
			return err
		}
		idx = uint32(l.Attrs().Index)
		gates, err := forwardgatemap.OpenPinned(r.pin + "/usid")
		if err != nil {
			return err
		}
		defer func() { _ = gates.Close() }()
		return gates.SetLink(idx, edgeLinkAddr)
	})
	return prov, idx
}

func edgeClaimOf(v *vpcRig, gen uint64) module.Claim {
	return module.Claim{Key: module.ClaimKey{Node: testNode, VPC: v.vpc, AttachmentUID: edgeUID},
		Owner: "galactic-system/galactic-edge", Generation: gen, Handoff: workerv1alpha1.Handoff_HANDOFF_ROUTED_LINK,
		Destinations: []module.Destination{{ID: "attachment/" + edgeUID, Mode: workerv1alpha1.Mode_MODE_LOCAL,
			VPC: v.vpc, Node: testNode, Addresses: []netip.Addr{edgeLinkAddr}, HostInterface: edgeHostEnd}},
		EdgeLink: &module.EdgeLink{Name: edgeHostEnd, Address: edgeLinkAddr}}
}

// allowAll binds an allow-everything policy to ifindex under its token, as
// galactic-router binds the attachment's snapshots.
func (r *rig) allowAll(ifindex uint32) {
	r.t.Helper()
	var row prog.UsidTpIfaceValue
	if err := r.tp.Interfaces.Lookup(ifindex, &row); err != nil {
		r.t.Fatalf("the edge link has no policy row: %v", err)
	}
	allow := []trafficpolicy.Entry{{Flags: trafficpolicy.FlagAllow, Rule: 0}}
	for _, dir := range []uint32{tpmap.DirIngress, tpmap.DirEgress} {
		if err := r.tp.Publish(ifindex, dir, row.PolicyToken, ifindex*4, allow); err != nil {
			r.t.Fatal(err)
		}
	}
}

// TestEdgeLinkRevocationRoot registers a connector claim's edge link,
// delivers a provider's packet through it to the tenant guest, and stops
// delivery to the guest once the claim is withdrawn, as Worker withdraws it
// when its EdgeAttachment loses Admitted, while the link stays up and the
// provider keeps sending.
func TestEdgeLinkRevocationRoot(t *testing.T) {
	r := newRig(t, "edge", xdpmode.Native)
	v := r.vpcs[0]
	prov, idx := r.edgeRig(v)
	claims := []module.Claim{edgeClaimOf(v, 1)}
	// CNI's pass-through entry for the guest, which a workload's attach
	// writes, so the guest's traffic reaches the kernel's VRF route.
	if err := r.routes.RegisterPassThrough(v.table, ipnet(netip.PrefixFrom(guestAddr, 128))); err != nil {
		t.Fatal(err)
	}

	st := r.reconcile(v.vpc, claims)
	wantState(t, st, claims[0], true, false, false, workerv1alpha1.ReasonHandoffInterfaceMissing)
	if !r.planEmpty(v.vpc, claims) {
		t.Fatal("a registered edge link plans another change")
	}
	r.allowAll(idx)

	// galactic-edge brings the link up once the claim is Programmed, and
	// the provider routes the tenant's address over it.
	var hostMAC net.HardwareAddr
	r.in(r.node, func() error {
		if err := up(edgeHostEnd); err != nil {
			return err
		}
		l, err := netlink.LinkByName(edgeHostEnd)
		if err == nil {
			hostMAC = l.Attrs().HardwareAddr
		}
		return err
	})
	var conn *net.UDPConn
	if err := prov.Do(func(ns.NetNS) error {
		if err := up("lo"); err != nil {
			return err
		}
		if err := addrOn(edgeProvEnd, netip.PrefixFrom(edgeLinkAddr, 128)); err != nil {
			return err
		}
		if err := up(edgeProvEnd); err != nil {
			return err
		}
		l, err := netlink.LinkByName(edgeProvEnd)
		if err != nil {
			return err
		}
		if err := netlink.RouteAdd(&netlink.Route{LinkIndex: l.Attrs().Index,
			Dst: ipnet(netip.PrefixFrom(guestAddr, 128))}); err != nil {
			return err
		}
		if err := netlink.NeighAdd(&netlink.Neigh{LinkIndex: l.Attrs().Index, Family: netlink.FAMILY_V6,
			IP: net.IP(guestAddr.AsSlice()), HardwareAddr: hostMAC, State: netlink.NUD_PERMANENT}); err != nil {
			return err
		}
		conn, err = net.ListenUDP("udp6", &net.UDPAddr{IP: net.IP(edgeLinkAddr.AsSlice()), Port: 4443})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	st = r.reconcile(v.vpc, claims)
	wantReady(t, st, claims)

	to := &net.UDPAddr{IP: net.IP(guestAddr.AsSlice()), Port: 8080}
	send := func(payload string) {
		t.Helper()
		if _, err := conn.WriteToUDP([]byte(payload), to); err != nil {
			t.Fatal(err)
		}
	}
	send("before-revocation")
	if f := v.guest.expect(t, "before-revocation"); f.src != edgeLinkAddr {
		t.Fatalf("the guest received the provider's packet from %s", f.src)
	}

	// Worker withdraws the revoked claim: its scope's desired state no
	// longer holds it. The link stays up and the provider keeps sending.
	st = r.reconcile(v.vpc, nil)
	if _, left := st[claims[0].Key]; left {
		t.Fatalf("the withdrawn claim is still reported: %+v", st[claims[0].Key])
	}
	r.in(r.node, func() error {
		has, err := pinnedEdgeHost{pinDir: r.pin + "/usid"}.HasRows(idx)
		if err == nil && has {
			t.Error("the withdrawn edge link still has its ifindex_vrf_table row")
		}
		return err
	})
	send("after-revocation")
	v.guest.absent(t, "after-revocation")
}
