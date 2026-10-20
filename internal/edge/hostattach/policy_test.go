// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package hostattach

import (
	"errors"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cilium/ebpf"

	"go.datum.net/galactic/internal/config"
	"go.datum.net/galactic/internal/plumbing/ebpf/attach"
	"go.datum.net/galactic/internal/plumbing/ebpf/tpmap"
	"go.datum.net/galactic/internal/plumbing/intf"
	"go.datum.net/galactic/internal/trafficpolicy"
)

// policyHarness does on node X what galactic-bgp and galactic-router do for an
// ordinary workload interface: a policy row with its own token, the
// interface's addresses, tp_deliver on the host link, and snapshots bound per
// direction. It applies them to host-owned attachment links unchanged.
type policyHarness struct {
	f        *datapathFixture
	maps     *tpmap.Maps
	tokens   map[uint32]uint64
	nextBase uint32
}

func newPolicyHarness(t *testing.T, f *datapathFixture) *policyHarness {
	t.Helper()
	maps, err := tpmap.OpenPinned(f.pinDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(maps.Close)
	p := &policyHarness{f: f, maps: maps, tokens: map[uint32]uint64{}}
	program, err := ebpf.LoadPinnedProgram(filepath.Join(f.pinDir, attach.TpDeliverPinName), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = program.Close() }()
	for ifindex, key := range f.hostKeys {
		vpc, att, _ := strings.Cut(key, "/")
		token, err := tpmap.NewPolicyToken()
		if err != nil {
			t.Fatal(err)
		}
		if err := maps.PutInterface(ifindex, token, tpmap.KindTenant); err != nil {
			t.Fatal(err)
		}
		p.tokens[ifindex] = token
		f.x.do(t, func() error { return attach.AttachDeliver(program, intf.GenerateInterfaceNameHost(vpc, att)) })
	}
	state := tpmap.State{Mode: tpmap.ModeEnforce, Mark: config.DefaultPolicyMark, Capable: true}
	if err := maps.SetState(state); err != nil {
		t.Fatal(err)
	}
	return p
}

// bind publishes policy as ifindex's snapshot in dir, as galactic-router
// does when a binding resolves.
func (p *policyHarness) bind(t *testing.T, ifindex int, dir uint32, policy trafficpolicy.Policy) {
	t.Helper()
	entries, err := trafficpolicy.Compile(policy)
	if err != nil {
		t.Fatal(err)
	}
	base, rows := p.nextBase, uint32(len(policy.Rules)) //nolint:gosec // a handful of rules
	p.nextBase += rows
	if err := p.maps.ZeroCounters(base, rows); err != nil {
		t.Fatal(err)
	}
	idx := uint32(ifindex) //nolint:gosec // a kernel ifindex
	if err := p.maps.Publish(idx, dir, p.tokens[idx], base, entries); err != nil {
		t.Fatal(err)
	}
}

func ptr[T any](v T) *T { return &v }

func allowAll() trafficpolicy.Policy {
	return trafficpolicy.Policy{Rules: []trafficpolicy.Rule{{Name: "all", Allow: true}}}
}

func allowTCP(src, dst string, srcPort, dstPort uint16) trafficpolicy.Policy {
	m := trafficpolicy.Match{
		Proto:       ptr(trafficpolicy.ProtoTCP),
		Source:      []netip.Prefix{netip.MustParsePrefix(src)},
		Destination: []netip.Prefix{netip.MustParsePrefix(dst)},
	}
	if srcPort != 0 {
		m.SourcePorts = []trafficpolicy.PortRange{{Start: srcPort, End: srcPort}}
	}
	if dstPort != 0 {
		m.DestPorts = []trafficpolicy.PortRange{{Start: dstPort, End: dstPort}}
	}
	return trafficpolicy.Policy{Rules: []trafficpolicy.Rule{{Name: "tcp", Allow: true, Match: m}}}
}

func allowICMPv6(icmpType uint8) trafficpolicy.Policy {
	return trafficpolicy.Policy{Rules: []trafficpolicy.Rule{{Name: "icmp", Allow: true, Match: trafficpolicy.Match{
		Proto: ptr(trafficpolicy.ProtoICMPv6), ICMP: &trafficpolicy.ICMP{Type: icmpType},
	}}}}
}

// TestHostAttachmentTrafficPolicy enforces interface traffic policy on
// host-owned attachment links through the same rows, tokens, tp_deliver
// filter and snapshots an ordinary workload interface uses, in both
// directions and across live policy updates.
func TestHostAttachmentTrafficPolicy(t *testing.T) {
	requireRoot(t)
	f := newDatapathFixture(t)
	p := newPolicyHarness(t, f)
	for ifindex, key := range f.hostKeys {
		if strings.HasSuffix(key, "/"+dpWorkloadAtt) {
			p.bind(t, int(ifindex), tpmap.DirIngress, allowAll())
			p.bind(t, int(ifindex), tpmap.DirEgress, allowAll())
		}
	}
	socket := f.results[pod1A].HostIndex
	tun := f.results[pod3A].HostIndex
	dst := netip.MustParseAddrPort("[fd00:aa::1]:8000")
	remote := remoteWorkloadAddr.String() + "/128"
	inbound := allowTCP(remote, "fd00:aa::1/128", 0, podPort)
	outbound := allowTCP("fd00:aa::1/128", remote, podPort, 0)

	t.Run("UnboundAttachmentDeniesEverything", func(t *testing.T) {
		if _, err := dialIdentity(f.wlYA, "", dst); err == nil {
			t.Fatal("dial to an attachment with no policy bound succeeded")
		}
		pkts, _, err := p.maps.FallbackCounter(uint32(socket), p.tokens[uint32(socket)], //nolint:gosec // ifindex
			tpmap.DirIngress, tpmap.ReasonPolicyUnavailable)
		if err != nil || pkts == 0 {
			t.Fatalf("policy_unavailable ingress count = %d (%v), want > 0", pkts, err)
		}
	})

	t.Run("BoundPolicyAdmitsBothDirections", func(t *testing.T) {
		p.bind(t, socket, tpmap.DirIngress, inbound)
		p.bind(t, socket, tpmap.DirEgress, outbound)
		expectIdentity(t, f.wlYA, "", dst, "pod1-A")
	})

	t.Run("IngressUpdateTakesEffect", func(t *testing.T) {
		p.bind(t, socket, tpmap.DirIngress, trafficpolicy.Default())
		if _, err := dialIdentity(f.wlYA, "", dst); err == nil {
			t.Fatal("dial succeeded after the ingress policy changed to deny")
		}
		p.bind(t, socket, tpmap.DirIngress, inbound)
		expectIdentity(t, f.wlYA, "", dst, "pod1-A")
	})

	t.Run("EgressUpdateTakesEffect", func(t *testing.T) {
		p.bind(t, socket, tpmap.DirEgress, trafficpolicy.Default())
		if _, err := dialIdentity(f.wlYA, "", dst); err == nil {
			t.Fatal("dial succeeded with the attachment's replies denied")
		}
		p.bind(t, socket, tpmap.DirEgress, outbound)
		expectIdentity(t, f.wlYA, "", dst, "pod1-A")
	})

	t.Run("PacketConsumerPolicyBothDirections", func(t *testing.T) {
		p.bind(t, tun, tpmap.DirIngress, allowICMPv6(128))
		p.bind(t, tun, tpmap.DirEgress, allowICMPv6(129))
		if err := ping(f.wlYA, siteHost, 128); err != nil {
			t.Fatalf("ping with echo allowed both ways: %v", err)
		}
		p.bind(t, tun, tpmap.DirEgress, outbound)
		if err := ping(f.wlYA, siteHost, 128); !errors.Is(err, errNoReply) {
			t.Fatalf("ping with echo replies denied = %v, want no reply", err)
		}
	})
}
