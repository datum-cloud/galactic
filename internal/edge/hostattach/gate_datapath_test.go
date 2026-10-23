// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package hostattach

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/containernetworking/plugins/pkg/ns"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv6"

	"go.datum.net/galactic/internal/edge/timing"
	"go.datum.net/galactic/internal/plumbing/ebpf/attach"
	"go.datum.net/galactic/internal/plumbing/ebpf/forwardgatemap"
)

// TestForwardingGateDatapath runs the Galactic Edge forwarding gate on a real
// kernel: VPC A's packet attachment on node X is an edge link holding the
// site prefix only while its gate is open. Node Y reaches it through
// usid_ingress's bpf_redirect_peer, and a workload on X through the kernel
// and tp_deliver. Each of those, and usid_egress for what the pod sends,
// carries the site's traffic only under an unexpired gate, and the
// attachment's own address always. The expiry is measured against the
// cell's real lease duration.
func TestForwardingGateDatapath(t *testing.T) {
	requireRoot(t)
	f := newDatapathFixture(t)
	att := f.atts[pod3A]
	link := uint32(f.results[pod3A].HostIndex)
	gates, err := forwardgatemap.OpenPinned(f.pinDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = gates.Close() })
	// The CNI-style registration the fixture uses does not attach
	// tp_deliver; RegisterHostLink does.
	f.x.do(t, func() error {
		program, err := ebpf.LoadPinnedProgram(filepath.Join(f.pinDir, attach.TpDeliverPinName), nil)
		if err != nil {
			return err
		}
		defer func() { _ = program.Close() }()
		return attach.AttachDeliver(program, att.HostLink)
	})
	if err := gates.SetLink(link, att.Address); err != nil {
		t.Fatal(err)
	}
	stats := func() forwardgatemap.Stats {
		t.Helper()
		s, err := gates.Stats()
		if err != nil {
			t.Fatal(err)
		}
		return s
	}

	t.Run("Closed", func(t *testing.T) {
		before := stats()
		if err := ping(f.wlYA, siteHost, 128); !errors.Is(err, errNoReply) {
			t.Fatalf("remote workload to the site with no gate: %v, want no reply", err)
		}
		if err := ping(f.wlXA, siteHost, 128); !errors.Is(err, errNoReply) {
			t.Fatalf("same-node workload to the site with no gate: %v, want no reply", err)
		}
		after := stats()
		if after.Ingress <= before.Ingress || after.Deliver <= before.Deliver || after.Egress != before.Egress {
			t.Fatalf("closed-gate drops: ingress %d->%d, deliver %d->%d, egress %d->%d; want the requests "+
				"dropped on the way in", before.Ingress, after.Ingress, before.Deliver, after.Deliver,
				before.Egress, after.Egress)
		}
		if n := f.tunA.echoes.Load(); n != 0 {
			t.Fatalf("the site answered %d requests through a closed gate", n)
		}
		// The attachment's own address is never gated.
		if err := ping(f.wlYA, att.Address, 128); err != nil {
			t.Fatalf("remote workload to the attachment's own address: %v", err)
		}
	})

	t.Run("Open", func(t *testing.T) {
		open := forwardgatemap.Gate{Deadline: timing.BootClock() + time.Minute, Epoch: 1}
		if err := gates.Set(link, sitePrefix, open); err != nil {
			t.Fatal(err)
		}
		if err := ping(f.wlYA, siteHost, 128); err != nil {
			t.Fatalf("remote workload to the site through an open gate: %v", err)
		}
		if err := ping(f.wlXA, siteHost, 128); err != nil {
			t.Fatalf("same-node workload to the site through an open gate: %v", err)
		}
		testOpenGate(t, f, gates, link, att.Address, open.Deadline)
	})

	t.Run("SpoofedSource", func(t *testing.T) { testSpoofedSource(t, f, stats) })
	t.Run("NarrowerClosedGate", func(t *testing.T) { testNarrowerClosedGate(t, f, gates, link) })

	t.Run("Expiry", func(t *testing.T) {
		// A gate renewed now, for the cell's lease duration: forwarding
		// must stop by the deadline plus the margin, with no packet
		// carried after the deadline.
		p := timing.Params
		start := timing.BootClock()
		deadline := start + p.Duration
		renewed := forwardgatemap.Gate{Deadline: deadline, RenewStart: start, Epoch: 2}
		if err := gates.Set(link, sitePrefix, renewed); err != nil {
			t.Fatal(err)
		}
		var lastOK, firstLost time.Duration
		for {
			sent := timing.BootClock()
			err := probe(f.wlYA, siteHost, 100*time.Millisecond)
			if err == nil {
				lastOK = sent
			} else if sent >= deadline {
				firstLost = sent
				break
			}
			if sent > deadline+2*p.Margin {
				t.Fatal("still forwarding past the deadline plus the margin")
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Logf("lease duration %v: last packet carried %v after the renewal, first lost %v after it, bound %v",
			p.Duration, lastOK-start, firstLost-start, p.Duration+p.Margin)
		if lastOK >= deadline {
			t.Fatalf("a probe sent %v after the deadline was carried", lastOK-deadline)
		}
		if firstLost-start > p.Duration+p.Margin {
			t.Fatalf("forwarding stopped %v after the renewal, past the %v bound", firstLost-start, p.Duration+p.Margin)
		}
		if lastOK-start < p.Duration-time.Second {
			t.Fatalf("forwarding stopped %v after the renewal, well before its deadline", lastOK-start)
		}
	})
}

// testOpenGate: under an open gate on link every address of the site prefix
// answers a remote and a same-node workload, the reply coming back through
// the gate's egress check, and the gate reads open exactly for the link's
// own address and the gated prefix until its deadline, as galactic-router
// reads it before advertising the prefix.
func testOpenGate(t *testing.T, f *datapathFixture, gates *forwardgatemap.Table, link uint32, own netip.Addr,
	deadline time.Duration) {
	for _, dst := range []string{"fd00:5::9", "fd00:5:0:1::1", "fd00:5:0:ffff:ffff:ffff:ffff:fffe"} {
		before := f.tunA.echoes.Load()
		for where, w := range map[string]testNS{"remote": f.wlYA, "same-node": f.wlXA} {
			if err := ping(w, netip.MustParseAddr(dst), 128); err != nil {
				t.Fatalf("%s workload to %s through an open gate: %v", where, dst, err)
			}
		}
		if got := f.tunA.echoes.Load() - before; got != 2 {
			t.Fatalf("site answered %d of 2 requests to %s", got, dst)
		}
	}
	now := timing.BootClock()
	for _, tc := range []struct {
		addr   netip.Addr
		prefix netip.Prefix
		want   bool
	}{
		{own, sitePrefix, true},
		{own, netip.MustParsePrefix("fd00:5::/64"), false},
		{netip.MustParseAddr("fd00:10:0:e::99"), sitePrefix, false},
	} {
		if got, err := gates.Open(link, tc.addr, tc.prefix, now); err != nil || got != tc.want {
			t.Errorf("Open(%s, %s) = %t, %v; want %t", tc.addr, tc.prefix, got, err, tc.want)
		}
	}
	if got, err := gates.Open(link, own, sitePrefix, deadline); err != nil || got {
		t.Errorf("Open at the deadline = %t, %v; want closed", got, err)
	}
}

// testSpoofedSource has the pod forward what its site sends from a source
// neither its own nor under its open gate: the host link drops it.
func testSpoofedSource(t *testing.T, f *datapathFixture, stats func() forwardgatemap.Stats) {
	before := stats()
	if _, err := f.tunA.f.Write(udpPacket(netip.MustParseAddr("fd00:bb::9"), remoteWorkloadAddr)); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for stats().Egress == before.Egress && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if stats().Egress == before.Egress {
		t.Fatal("spoofed source was not dropped by the egress gate")
	}
}

// testNarrowerClosedGate: the longest matching gate decides, so a closed
// narrower gate inside an open wider one closes its addresses and only
// those.
func testNarrowerClosedGate(t *testing.T, f *datapathFixture, gates *forwardgatemap.Table, link uint32) {
	narrow := netip.MustParsePrefix("fd00:5::/64")
	if err := gates.Set(link, narrow, forwardgatemap.Gate{Epoch: 1}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = gates.Delete(link, narrow) })
	if err := ping(f.wlYA, siteHost, 128); !errors.Is(err, errNoReply) {
		t.Fatalf("site host under a closed narrower gate: %v, want no reply", err)
	}
	if err := ping(f.wlYA, netip.MustParseAddr("fd00:5:0:1::1"), 128); err != nil {
		t.Fatalf("site address outside the closed narrower gate: %v", err)
	}
	if err := gates.Delete(link, narrow); err != nil {
		t.Fatal(err)
	}
}

// probe sends one ICMPv6 echo request from inside n and waits up to timeout
// for its reply.
func probe(n testNS, dst netip.Addr, timeout time.Duration) error {
	return n.Do(func(ns.NetNS) error {
		var lc net.ListenConfig
		c, err := lc.ListenPacket(context.Background(), "ip6:ipv6-icmp", "::")
		if err != nil {
			return err
		}
		defer func() { _ = c.Close() }()
		id := int(echoID.Add(1) & 0xffff)
		msg := icmp.Message{Type: ipv6.ICMPTypeEchoRequest, Body: &icmp.Echo{ID: id, Seq: 1, Data: make([]byte, 32)}}
		wire, err := msg.Marshal(nil)
		if err != nil {
			return err
		}
		if _, err := c.WriteTo(wire, &net.IPAddr{IP: dst.AsSlice()}); err != nil {
			return err
		}
		_ = c.SetReadDeadline(time.Now().Add(timeout))
		buf := make([]byte, 1500)
		for {
			nr, _, err := c.ReadFrom(buf)
			if err != nil {
				return errNoReply
			}
			if m, err := icmp.ParseMessage(58, buf[:nr]); err == nil && m.Type == ipv6.ICMPTypeEchoReply {
				if e, ok := m.Body.(*icmp.Echo); ok && e.ID == id {
					return nil
				}
			}
		}
	})
}

// udpPacket is an IPv6 UDP datagram from src to dst with an 8-byte payload.
func udpPacket(src, dst netip.Addr) []byte {
	pkt := make([]byte, 40+8+8)
	pkt[0] = 6 << 4
	binary.BigEndian.PutUint16(pkt[4:6], 16)
	pkt[6], pkt[7] = 17, 64
	s, d := src.As16(), dst.As16()
	copy(pkt[8:24], s[:])
	copy(pkt[24:40], d[:])
	binary.BigEndian.PutUint16(pkt[40:42], 4000)
	binary.BigEndian.PutUint16(pkt[42:44], workloadPort)
	binary.BigEndian.PutUint16(pkt[44:46], 16)
	return pkt
}
