// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package edgeprog

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"go.datum.net/galactic/internal/plumbing/ebpf/xmitdrops"
)

// outIface is the interface the route to the client points out of.
const outIface = "out0"

// TestEdgeReturn_RedirectToNonXDPInterfaceIsCounted covers a reply that
// edge_return forwards to an interface that cannot take an XDP frame. The FIB
// lookup succeeds and the program returns XDP_REDIRECT, so it counts no drop,
// but the kernel then drops the frame. Only the xmitdrops tracepoint counters
// record that loss.
func TestEdgeReturn_RedirectToNonXDPInterfaceIsCounted(t *testing.T) {
	for _, tt := range []struct {
		name string
		// target creates the interface the route to the client points out of,
		// in the current namespace, and returns its name and its next hop's
		// MAC address.
		target func(t *testing.T) (string, net.HardwareAddr)
		want   func(ifindex uint32) xmitdrops.Key
	}{
		{
			// A dummy implements no ndo_xdp_xmit, so xdp_do_redirect refuses
			// the frame.
			name: "driver without XDP transmit",
			target: func(t *testing.T) (string, net.HardwareAddr) {
				if err := netlink.LinkAdd(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: outIface}}); err != nil {
					t.Fatalf("add dummy link: %v", err)
				}
				return outIface, net.HardwareAddr{0x02, 0, 0, 0, 0, 0x02}
			},
			want: func(ifindex uint32) xmitdrops.Key {
				return xmitdrops.Key{Ifindex: ifindex, Stage: xmitdrops.StageRedirect, Errno: uint32(unix.EOPNOTSUPP)}
			},
		},
		{
			// A veth advertises XDP transmit only while its peer can receive
			// XDP frames, which needs an XDP program or GRO on the peer.
			// Without either, xdp_do_redirect refuses the frame as for a
			// driver with no XDP transmit at all.
			name: "veth whose peer cannot receive XDP frames",
			target: func(t *testing.T) (string, net.HardwareAddr) {
				veth := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: outIface}, PeerName: "out1"}
				if err := netlink.LinkAdd(veth); err != nil {
					t.Fatalf("add veth pair: %v", err)
				}
				return outIface, setLinkUp(t, "out1").Attrs().HardwareAddr
			},
			want: func(ifindex uint32) xmitdrops.Key {
				return xmitdrops.Key{Ifindex: ifindex, Stage: xmitdrops.StageRedirect, Errno: uint32(unix.EOPNOTSUPP)}
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			requireRoot(t)
			runRedirectDropCase(t, tt.target, tt.want)
		})
	}
}

func runRedirectDropCase(t *testing.T, target func(t *testing.T) (string, net.HardwareAddr),
	want func(ifindex uint32) xmitdrops.Key,
) {
	t.Helper()
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

	// A counter attached in the original namespace counts only drops to
	// interfaces there, so it must not count this one.
	outside, err := xmitdrops.Attach()
	if err != nil {
		t.Fatalf("attach the transmit drop counters in the original namespace: %v", err)
	}
	t.Cleanup(func() { _ = outside.Close() })

	if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
		t.Fatalf("unshare gateway network namespace: %v", err)
	}
	for _, path := range []string{"/proc/sys/net/ipv6/conf/all/forwarding", "/proc/sys/net/ipv6/conf/default/forwarding"} {
		if err := os.WriteFile(path, []byte("1"), 0o644); err != nil {
			t.Fatalf("enable forwarding via %s: %v", path, err)
		}
	}

	// in0 is the compute-facing interface the reply arrives on, from its veth
	// peer in1. A veth rather than a tap: veth runs XDP from NAPI and flushes
	// redirected frames at the end of each poll, as a NIC driver does, while a
	// tap's write path never flushes them.
	if err := netlink.LinkAdd(&netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "in0"}, PeerName: "in1"}); err != nil {
		t.Fatalf("add veth pair: %v", err)
	}
	sender := openCapture(t, setLinkUp(t, "in1").Attrs().Index)
	in := setLinkUp(t, "in0")
	outName, nextHopMAC := target(t)
	out := setLinkUp(t, outName)
	capture := openCapture(t, out.Attrs().Index)

	local, nextHop := netip.MustParseAddr("fd00:6::1"), netip.MustParseAddr("fd00:6::2")
	client := netip.MustParseAddr("2001:db8:ffff::1")
	addLinkAddr(t, out, local)
	if err := netlink.NeighAdd(&netlink.Neigh{
		LinkIndex:    out.Attrs().Index,
		Family:       netlink.FAMILY_V6,
		State:        netlink.NUD_PERMANENT,
		IP:           net.IP(nextHop.AsSlice()),
		HardwareAddr: nextHopMAC,
	}); err != nil {
		t.Fatalf("add a neighbor entry for %v: %v", nextHop, err)
	}
	routeOver(t, out, client, nextHop)

	objs := loadObjects(t)
	vip := netip.MustParseAddr("2001:db8::100")
	claimReturnAddr(t, objs, vip)
	xdp, err := link.AttachXDP(link.XDPOptions{Program: objs.EdgeReturn, Interface: in.Attrs().Index})
	if err != nil {
		t.Fatalf("attach edge_return to %s: %v", in.Attrs().Name, err)
	}
	t.Cleanup(func() { _ = xdp.Close() })

	counter, err := xmitdrops.Attach()
	if err != nil {
		t.Fatalf("attach the transmit drop counters: %v", err)
	}
	t.Cleanup(func() { _ = counter.Close() })
	key := want(uint32(out.Attrs().Index))
	read := func(c *xmitdrops.Counter) map[xmitdrops.Key]uint64 {
		counts, err := c.Read()
		if err != nil {
			t.Fatalf("read the transmit drop counters: %v", err)
		}
		return counts
	}
	outsideBefore := read(outside)[key]

	marker := fmt.Appendf(nil, "edge-xmitdrops:%d", time.Now().UnixNano())
	pkt := buildL4Packet(t, ipprotoUDP, client, vip, 443, 41000, marker)
	copy(pkt[0:6], in.Attrs().HardwareAddr)
	if _, err := unix.Write(sender, pkt); err != nil {
		t.Fatalf("write the reply into %s: %v", in.Attrs().Name, err)
	}

	// The reply is lost: it never leaves out0, and edge_return claimed it
	// and counted no drop.
	if awaitMarker(t, capture, marker, time.Second) {
		t.Fatalf("the reply left %s, so the redirect did not fail; the test no longer exercises a lost redirect",
			out.Attrs().Name)
	}
	var claimed uint64
	for _, row := range returnStatsRows(t, objs) {
		claimed += row.Packets
	}
	if claimed != 1 {
		t.Fatalf("edge_return claimed %d replies, want 1", claimed)
	}
	for i := range DropReasonCount {
		if got := sumPerCPU(t, objs.DropReasons, i); got != 0 {
			t.Errorf("drop_reasons[%s] = %d, want 0: edge_return redirected the reply", DropReasonNames[i], got)
		}
	}

	deadline := time.Now().Add(2 * time.Second)
	for read(counter)[key] == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if counts := read(counter); counts[key] != 1 {
		t.Errorf("drops counted under %+v (%s) = %d, want 1; counters: %v", key,
			xmitdrops.Reason(key.Stage, key.Errno), counts[key], counts)
	}
	if got := read(outside)[key] - outsideBefore; got != 0 {
		t.Errorf("the counter in the original namespace counted %d drops to this namespace's %s, want 0",
			got, out.Attrs().Name)
	}
}
