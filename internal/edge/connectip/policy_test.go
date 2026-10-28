// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package connectip

import (
	"context"
	"encoding/binary"
	"net/http"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv6"
)

var (
	// policyRoute does not overlap the connector's /96, so a source or
	// destination check cannot pass by accident.
	policyRoute  = netip.MustParsePrefix("fd00:b::/64")
	policyTarget = netip.MustParseAddr("fd00:b::1")
	// sibling is in another connector's /96 of the same VPC.
	sibling = netip.MustParseAddr("fd00:a::2:0:1")
	// router is a gVPC router outside the advertised routes.
	router = netip.MustParseAddr("fd00:ff::1")
)

// withExtension returns pkt with an extension header of type next and
// content hdr inserted directly after the fixed header.
func withExtension(pkt []byte, next byte, hdr []byte) []byte {
	out := make([]byte, 0, len(pkt)+len(hdr))
	out = append(append(append(out, pkt[:ipv6HeaderLen]...), hdr...), pkt[ipv6HeaderLen:]...)
	out[ipv6HeaderLen] = pkt[6]
	out[6] = next
	binary.BigEndian.PutUint16(out[4:6], uint16(len(out)-ipv6HeaderLen))
	return out
}

// options returns an empty options header of size bytes, a multiple of 8.
func options(size int) []byte {
	h := make([]byte, size)
	h[1] = byte(size/8 - 1)
	return h
}

func routingHeader(segmentsLeft byte) []byte {
	h := make([]byte, 24)
	h[1], h[2], h[3] = 2, 4, segmentsLeft
	return h
}

// icmpError returns an ICMPv6 error of type typ from src to dst quoting
// invoking.
func icmpError(t *testing.T, typ ipv6.ICMPType, src, dst netip.Addr, invoking []byte) []byte {
	t.Helper()
	var body icmp.MessageBody = &icmp.DstUnreach{Data: invoking}
	if typ == ipv6.ICMPTypePacketTooBig {
		body = &icmp.PacketTooBig{MTU: 1280, Data: invoking}
	}
	return ipv6Packet(t, src, dst, &icmp.Message{Type: typ, Body: body})
}

func ipv4Packet() []byte {
	p := make([]byte, 28)
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	p[8], p[9] = 64, 1
	copy(p[12:16], []byte{192, 0, 2, 1})
	copy(p[16:20], []byte{198, 51, 100, 1})
	return p
}

func TestPacketPolicyFromClient(t *testing.T) {
	policy := newPacketPolicy(firstPrefix, []netip.Prefix{policyRoute})
	echo := echoRequest(t, firstClient, policyTarget, 1, 100)
	tooLong := append([]byte(nil), echo...)
	binary.BigEndian.PutUint16(tooLong[4:6], uint16(len(echo)))
	jumbo := append([]byte(nil), echo...)
	binary.BigEndian.PutUint16(jumbo[4:6], 0)
	nine := echo
	for range 9 {
		nine = withExtension(nine, protoDestOptions, options(8))
	}
	eight := echo
	for range 8 {
		eight = withExtension(eight, protoDestOptions, options(8))
	}
	truncatedExt := withExtension(echo, protoDestOptions, options(8))
	truncatedExt[ipv6HeaderLen+1] = 30
	// A Packet Too Big as connect-ip-go composes it for a gVPC packet the
	// tunnel could not carry: from the client's address to the sender.
	ptb := icmpError(t, ipv6.ICMPTypePacketTooBig, firstClient, policyTarget,
		echoRequest(t, policyTarget, firstClient, 2, 1400))

	for _, tc := range []struct {
		name string
		pkt  []byte
		want string
	}{
		{"allowed", echo, ""},
		{"hop-by-hop and destination options", withExtension(withExtension(echo, protoDestOptions, options(8)),
			protoHopByHop, options(8)), ""},
		{"eight extension headers", eight, ""},
		{"256 extension header bytes", withExtension(echo, protoDestOptions, options(256)), ""},
		{"routing header with no segments left", withExtension(echo, protoRouting, routingHeader(0)), ""},
		{"packet too big from the library", ptb, ""},
		{"empty", nil, reasonMalformed},
		{"unknown version", append([]byte{0x50}, echo[1:]...), reasonMalformed},
		{"shorter than the fixed header", echo[:39], reasonMalformed},
		{"payload length past the packet", tooLong, reasonMalformed},
		{"payload length short of the packet", append(append([]byte(nil), echo...), 0), reasonMalformed},
		{"jumbogram", jumbo, reasonMalformed},
		{"truncated ICMPv6", withLength(echo[:ipv6HeaderLen+2]), reasonMalformed},
		{"hop-by-hop after another header", withExtension(withExtension(echo, protoHopByHop, options(8)),
			protoDestOptions, options(8)), reasonMalformed},
		{"extension header past the packet", truncatedExt, reasonMalformed},
		{"IPv4", ipv4Packet(), reasonIPv4},
		{"atomic fragment", withExtension(echo, protoFragment, make([]byte, 8)), reasonFragment},
		{"fragment behind another header", withExtension(withExtension(echo, protoFragment, make([]byte, 8)),
			protoDestOptions, options(8)), reasonFragment},
		{"nine extension headers", nine, reasonExtensionHeaders},
		{"264 extension header bytes", withExtension(withExtension(echo, protoDestOptions, options(256)),
			protoDestOptions, options(8)), reasonExtensionHeaders},
		{"mobility header", withExtension(echo, 135, options(8)), reasonExtensionHeaders},
		{"routing header with segments left", withExtension(echo, protoRouting, routingHeader(1)),
			reasonRoutingHeader},
		{"source outside the /96", echoRequest(t, router, policyTarget, 3, 100), reasonSource},
		{"source in another connector's /96", echoRequest(t, sibling, policyTarget, 4, 100), reasonSource},
		{"ICMPv6 error from a spoofed source", icmpError(t, ipv6.ICMPTypeDestinationUnreachable, router,
			policyTarget, echoRequest(t, policyTarget, firstClient, 5, 100)), reasonSource},
		{"destination outside the routes", echoRequest(t, firstClient, router, 6, 100), reasonDestination},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := policy.fromClient(tc.pkt); got != tc.want {
				t.Fatalf("fromClient = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestPacketPolicyToClient(t *testing.T) {
	policy := newPacketPolicy(firstPrefix, []netip.Prefix{policyRoute})
	sent := echoRequest(t, firstClient, policyTarget, 1, 1400)
	for _, tc := range []struct {
		name string
		pkt  []byte
		want string
	}{
		{"allowed", echoRequest(t, policyTarget, firstClient, 1, 100), ""},
		{"error from a route", icmpError(t, ipv6.ICMPTypeDestinationUnreachable, policyTarget, firstClient, sent), ""},
		{"packet too big from a router", icmpError(t, ipv6.ICMPTypePacketTooBig, router, firstClient, sent), ""},
		{"IPv4", ipv4Packet(), reasonIPv4},
		{"fragment", withExtension(echoRequest(t, policyTarget, firstClient, 2, 100), protoFragment,
			make([]byte, 8)), reasonFragment},
		{"destination in another connector's /96", echoRequest(t, policyTarget, sibling, 3, 100),
			reasonDestination},
		{"source outside the routes", echoRequest(t, router, firstClient, 4, 100), reasonSource},
		{"error quoting another connector's packet", icmpError(t, ipv6.ICMPTypePacketTooBig, router,
			firstClient, echoRequest(t, sibling, policyTarget, 5, 1400)), reasonSource},
		{"error quoting a packet to outside the routes", icmpError(t, ipv6.ICMPTypePacketTooBig, router,
			firstClient, echoRequest(t, firstClient, router, 6, 1400)), reasonSource},
		{"echo request quoting a client packet", ipv6Packet(t, router, firstClient, &icmp.Message{
			Type: ipv6.ICMPTypeEchoRequest, Body: &icmp.Echo{ID: 7, Seq: 1, Data: sent}}), reasonSource},
		{"error quoting a truncated header", icmpError(t, ipv6.ICMPTypePacketTooBig, router, firstClient,
			sent[:20]), reasonMalformed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := policy.toClient(tc.pkt); got != tc.want {
				t.Fatalf("toClient = %q, want %q", got, tc.want)
			}
		})
	}
}

// withLength returns a copy of pkt with its payload length set to match.
func withLength(pkt []byte) []byte {
	out := append([]byte(nil), pkt...)
	binary.BigEndian.PutUint16(out[4:6], uint16(len(out)-ipv6HeaderLen))
	return out
}

// TestProxyRefusesPacketsOutsidePolicy sends raw datagrams over an admitted
// request, past connect-ip-go's client-side checks, and injects packets on
// the backend, then checks that only allowed packets arrive on either side
// and that each refusal is counted.
func TestProxyRefusesPacketsOutsidePolicy(t *testing.T) {
	env := startServer(t, nil)
	ctx, cancel := context.WithTimeout(t.Context(), testTimeout)
	defer cancel()

	cc := (&http3.Transport{EnableDatagrams: true}).NewClientConn(env.dialQUIC(t))
	select {
	case <-cc.ReceivedSettings():
	case <-ctx.Done():
		t.Fatal("no HTTP/3 settings from server")
	}
	rstr, err := cc.OpenRequestStream(ctx)
	if err != nil {
		t.Fatalf("OpenRequestStream: %v", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodConnect, env.template.Raw(), nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Proto = "connect-ip"
	req.Host = req.URL.Host
	req.Header = authHeaders(tokenAlice, vpcBlue)
	if err := rstr.SendRequestHeader(req); err != nil {
		t.Fatalf("SendRequestHeader: %v", err)
	}
	rsp, err := rstr.ReadResponse()
	if err != nil || rsp.StatusCode != http.StatusOK {
		t.Fatalf("response = %v, %v; want 200", rsp, err)
	}
	sess := env.backend.nextOpened(t)

	counted := func(direction, reason string) float64 {
		return testutil.ToFloat64(packetsDenied.WithLabelValues(direction, reason))
	}
	type count struct{ direction, reason string }
	want := map[count]float64{}
	for _, c := range []count{
		{toVPC, reasonFragment}, {toVPC, reasonSource},
		{toClient, reasonFragment}, {toClient, reasonDestination}, {toClient, reasonSource},
	} {
		want[c] = counted(c.direction, c.reason) + 1
	}

	send := func(pkt []byte) {
		t.Helper()
		if err := rstr.SendDatagram(append([]byte{0}, pkt...)); err != nil {
			t.Fatalf("SendDatagram: %v", err)
		}
	}
	send(withExtension(echoRequest(t, firstClient, testTarget, 10, 100), protoFragment, make([]byte, 8)))
	// connect-ip-go passes an ICMP error from any source when the packet it
	// quotes could have crossed the tunnel.
	send(icmpError(t, ipv6.ICMPTypeDestinationUnreachable, netip.MustParseAddr("fd00:a::dead"), testTarget,
		echoRequest(t, testTarget, firstClient, 11, 100)))
	send(echoRequest(t, firstClient, testTarget, 12, 100))

	sess.inject(withExtension(echoRequest(t, testTarget, firstClient, 20, 100), protoFragment, make([]byte, 8)))
	sess.inject(echoRequest(t, testTarget, sibling, 21, 100))
	sess.inject(echoRequest(t, router, firstClient, 22, 100))
	sess.inject(echoRequest(t, testTarget, firstClient, 23, 100))

	var got []int
	for len(got) < 2 {
		data, err := rstr.ReceiveDatagram(ctx)
		if err != nil {
			t.Fatalf("ReceiveDatagram after %v: %v", got, err)
		}
		// Skip the admission MTU probe, which uses an unregistered context ID.
		if data[0] != 0 {
			continue
		}
		got = append(got, echoID(t, parseICMPv6(t, data[1:])))
	}
	// The reply to 12 and the injected 23 are the only packets the client
	// may receive, in either order.
	slices.Sort(got)
	if !slices.Equal(got, []int{12, 23}) {
		t.Fatalf("client received echo ids %v, want 12 and 23", got)
	}
	pkts := sess.packets()
	if len(pkts) != 1 || echoID(t, parseICMPv6(t, pkts[0])) != 12 {
		t.Fatalf("backend received %d packets, want only echo id 12", len(pkts))
	}
	deadline := time.Now().Add(testTimeout)
	for c, n := range want {
		for counted(c.direction, c.reason) != n && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
		if got := counted(c.direction, c.reason); got != n {
			t.Errorf("%s/%s denials = %v, want %v", c.direction, c.reason, got, n)
		}
	}
}

// TestProxyReturnsPacketTooBig injects a gVPC packet too large for the
// client's QUIC path and checks that the Packet Too Big connect-ip-go builds
// for it passes the policy and reaches the sender.
func TestProxyReturnsPacketTooBig(t *testing.T) {
	env := startServer(t, nil)
	s := open(t, newClientConn(t, env.dialQUIC(t)), env.newRequest(t, authHeaders(tokenAlice, vpcBlue)))
	sess := env.backend.nextOpened(t)
	sess.inject(echoRequest(t, testTarget, s.address, 30, 1500))
	deadline := time.Now().Add(testTimeout)
	for time.Now().Before(deadline) {
		for _, pkt := range sess.packets() {
			if p, err := tryParseICMPv6(pkt); err == nil && p.msg.Type == ipv6.ICMPTypePacketTooBig {
				if p.src != s.address || p.dst != testTarget {
					t.Fatalf("Packet Too Big from %s to %s, want %s to %s", p.src, p.dst, s.address, testTarget)
				}
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("no Packet Too Big reached the backend")
}

// ipv4RouteAdmission grants every request an IPv4 route besides its IPv6
// one.
type ipv4RouteAdmission struct{ *testAdmission }

type ipv4RouteLease struct{ Lease }

func (a ipv4RouteAdmission) Admit(ctx context.Context, token, vpc string) (Lease, error) {
	l, err := a.testAdmission.Admit(ctx, token, vpc)
	if err != nil {
		return nil, err
	}
	return ipv4RouteLease{l}, nil
}

func (l ipv4RouteLease) Routes() []netip.Prefix {
	return append(l.Lease.Routes(), netip.MustParsePrefix("198.51.100.0/24"))
}

func TestRefusesGrantWithIPv4Route(t *testing.T) {
	env := startServer(t, func(c *Config) { c.Admission = ipv4RouteAdmission{newTestAdmission()} })
	conn, rsp, err := newClientConn(t, env.dialQUIC(t)).Dial(env.newRequest(t, authHeaders(tokenAlice, vpcBlue)))
	if err == nil {
		_ = conn.Close()
		t.Fatal("a grant with an IPv4 route was accepted")
	}
	if rsp == nil || rsp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("response = %v (err %v), want 503", rsp, err)
	}
	if n := len(env.backend.all()); n != 0 {
		t.Fatalf("backend has %d sessions, want 0", n)
	}
}
