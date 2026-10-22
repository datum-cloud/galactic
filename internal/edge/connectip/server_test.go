// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package connectip

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"

	connectip "github.com/quic-go/connect-ip-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv6"
)

// echoID returns the identifier of an ICMPv6 echo request or reply.
func echoID(t *testing.T, p parsedICMPv6) int {
	t.Helper()
	echo, ok := p.msg.Body.(*icmp.Echo)
	if !ok {
		t.Fatalf("message type %v is not an echo", p.msg.Type)
	}
	return echo.ID
}

// ping sends one echo request of size bytes from s to testTarget and returns
// the reply.
func ping(t *testing.T, s *session, id, size int) parsedICMPv6 {
	t.Helper()
	icmpErr, err := s.conn.WritePacket(echoRequest(t, s.address, testTarget, id, size))
	if err != nil || icmpErr != nil {
		t.Fatalf("WritePacket: err=%v icmp=%x", err, icmpErr)
	}
	reply := parseICMPv6(t, readPacket(t, s.conn))
	if reply.msg.Type != ipv6.ICMPTypeEchoReply || echoID(t, reply) != id {
		t.Fatalf("reply = %v id %d, want echo reply id %d", reply.msg.Type, echoID(t, reply), id)
	}
	if reply.src != testTarget || reply.dst != s.address {
		t.Fatalf("reply %s -> %s, want %s -> %s", reply.src, reply.dst, testTarget, s.address)
	}
	return reply
}

func TestEchoThroughIndependentClient(t *testing.T) {
	env := startServer(t, nil)
	tr := &connectip.Transport{
		TLSClientConfig: env.clientTLS(),
		QUICConfig:      &quic.Config{EnableDatagrams: true, InitialPacketSize: DefaultInitialPacketSize},
	}
	conn, rsp, err := tr.Dial(env.newRequest(t, authHeaders(tokenAlice, vpcBlue)))
	s := accepted(t, conn, rsp, err)

	if s.address != firstClient {
		t.Errorf("assigned %s, want %s", s.address, firstClient)
	}
	wantRoutes := []connectip.IPRoute{{
		StartIP: netip.MustParseAddr("fd00:a::"),
		EndIP:   netip.MustParseAddr("fd00:a::ffff:ffff:ffff:ffff"),
	}}
	if !slices.Equal(s.routes, wantRoutes) {
		t.Errorf("routes = %v, want %v", s.routes, wantRoutes)
	}
	sess := env.backend.nextOpened(t)
	want := SessionInfo{
		ID: sess.info.ID, Principal: principalAlice, VPC: vpcBlue, Prefix: firstPrefix,
		Connector: "connector-1", Attachment: "attachment-blue", Claim: "claim-1", Epoch: 1,
	}
	if sess.info != want {
		t.Errorf("backend session = %+v, want %+v", sess.info, want)
	}

	reply := ping(t, s, 7, 128)
	// The backend replies with hop limit 64 and the proxy decrements it.
	if reply.hopLimit != 63 {
		t.Errorf("reply hop limit = %d, want 63", reply.hopLimit)
	}
	got := sess.packets()
	if len(got) != 1 {
		t.Fatalf("backend received %d packets, want 1", len(got))
	}
	// The client sends hop limit 64 and decrements it before tunnelling.
	if req := parseICMPv6(t, got[0]); req.hopLimit != 63 || req.src != firstClient || echoID(t, req) != 7 {
		t.Errorf("backend packet = %s hop %d id %d, want %s hop 63 id 7",
			req.src, req.hopLimit, echoID(t, req), firstClient)
	}

	t.Run("AddressRequestKeepsAssignment", func(t *testing.T) {
		if _, err := s.conn.RequestAddresses([]netip.Prefix{netip.MustParsePrefix("::/128")}); err != nil {
			t.Fatalf("RequestAddresses: %v", err)
		}
		ctx, cancel := context.WithTimeout(t.Context(), testTimeout)
		defer cancel()
		assigned, err := s.conn.ReceiveAddressAssignment(ctx)
		if err != nil {
			t.Fatalf("ReceiveAddressAssignment: %v", err)
		}
		if len(assigned) != 1 || assigned[0].IPPrefix != firstPrefix {
			t.Fatalf("assignment = %v, want %s/96", assigned, firstClient)
		}
		ping(t, s, 8, 128)
	})
}

func TestMultiplexedRequestsStayInTheirVPC(t *testing.T) {
	env := startServer(t, nil)
	cc := newClientConn(t, env.dialQUIC(t))

	blue := open(t, cc, env.newRequest(t, authHeaders(tokenAlice, vpcBlue)))
	blueSess := env.backend.nextOpened(t)
	green := open(t, cc, env.newRequest(t, authHeaders(tokenAlice, vpcGreen)))
	greenSess := env.backend.nextOpened(t)

	if blue.address != green.address {
		t.Fatalf("blue %s and green %s should overlap", blue.address, green.address)
	}
	if blueSess.info.VPC != vpcBlue || greenSess.info.VPC != vpcGreen {
		t.Fatalf("sessions opened for %q and %q, want blue and green", blueSess.info.VPC, greenSess.info.VPC)
	}

	for range 3 {
		ping(t, blue, 1, 200)
		ping(t, green, 2, 200)
	}
	for _, tc := range []struct {
		sess   *memorySession
		wantID int
	}{{blueSess, 1}, {greenSess, 2}} {
		pkts := tc.sess.packets()
		if len(pkts) != 3 {
			t.Errorf("%s received %d packets, want 3", tc.sess.info.VPC, len(pkts))
		}
		for _, pkt := range pkts {
			if id := echoID(t, parseICMPv6(t, pkt)); id != tc.wantID {
				t.Errorf("%s received echo id %d, want only %d", tc.sess.info.VPC, id, tc.wantID)
			}
		}
	}
}

func TestCancelledRequestLeavesSiblingRunning(t *testing.T) {
	env := startServer(t, nil)
	cc := newClientConn(t, env.dialQUIC(t))

	blue := open(t, cc, env.newRequest(t, authHeaders(tokenAlice, vpcBlue)))
	blueSess := env.backend.nextOpened(t)
	green := open(t, cc, env.newRequest(t, authHeaders(tokenAlice, vpcGreen)))
	greenSess := env.backend.nextOpened(t)
	ping(t, blue, 1, 100)
	ping(t, green, 2, 100)

	if err := blue.conn.Close(); err != nil {
		t.Fatalf("close blue: %v", err)
	}
	blueSess.waitClosed(t)

	for range 3 {
		ping(t, green, 2, 100)
	}
	if greenSess.isClosed() {
		t.Fatal("green session closed when only blue was cancelled")
	}

	// The cancelled request's address returns to the pool.
	again := open(t, cc, env.newRequest(t, authHeaders(tokenAlice, vpcBlue)))
	if again.address != blue.address {
		t.Errorf("reopened blue got %s, want released %s", again.address, blue.address)
	}
	ping(t, again, 3, 100)
}

func TestAdmissionRejectsWithoutBackendSession(t *testing.T) {
	env := startServer(t, nil)
	cc := newClientConn(t, env.dialQUIC(t))

	bearer := func(values ...string) http.Header {
		h := http.Header{}
		for _, v := range values {
			h.Add("Authorization", v)
		}
		return h
	}
	withVPC := func(h http.Header, vpcs ...string) http.Header {
		for _, v := range vpcs {
			h.Add(VPCHeader, v)
		}
		return h
	}
	tests := []struct {
		name    string
		headers http.Header
		want    int
	}{
		{"NoCredential", withVPC(http.Header{}, vpcBlue), http.StatusUnauthorized},
		{"UnknownToken", withVPC(bearer("Bearer test-token-unknown"), vpcBlue), http.StatusUnauthorized},
		{"WrongScheme", withVPC(bearer("Basic "+tokenAlice), vpcBlue), http.StatusUnauthorized},
		{"EmptyToken", withVPC(bearer("Bearer "), vpcBlue), http.StatusUnauthorized},
		{"TwoCredentials", withVPC(bearer("Bearer "+tokenAlice, "Bearer "+tokenBob), vpcBlue), http.StatusUnauthorized},
		{"NoVPC", bearer("Bearer " + tokenAlice), http.StatusBadRequest},
		{"TwoVPCFields", withVPC(bearer("Bearer "+tokenAlice), vpcBlue, vpcGreen), http.StatusBadRequest},
		{"VPCList", withVPC(bearer("Bearer "+tokenAlice), "blue, green"), http.StatusBadRequest},
		{"VPCNotGranted", withVPC(bearer("Bearer "+tokenBob), vpcBlue), http.StatusForbidden},
		{"VPCGrantedToNobody", withVPC(bearer("Bearer "+tokenAlice), vpcRed), http.StatusForbidden},
		{"UnknownVPC", withVPC(bearer("Bearer "+tokenAlice), "purple"), http.StatusForbidden},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn, rsp, err := cc.Dial(env.newRequest(t, tt.headers))
			if err == nil {
				_ = conn.Close()
				t.Fatal("request was accepted")
			}
			if rsp == nil || rsp.StatusCode != tt.want {
				t.Fatalf("response = %v (err %v), want status %d", rsp, err, tt.want)
			}
			if tt.want == http.StatusUnauthorized && rsp.Header.Get("WWW-Authenticate") != "Bearer" {
				t.Errorf("WWW-Authenticate = %q, want Bearer", rsp.Header.Get("WWW-Authenticate"))
			}
		})
	}
	if n := len(env.backend.all()); n != 0 {
		t.Fatalf("backend opened %d sessions for rejected requests", n)
	}

	// The connection that carried the rejections still accepts a valid request.
	s := open(t, cc, env.newRequest(t, authHeaders(tokenBob, vpcGreen)))
	ping(t, s, 1, 100)
	if n := len(env.backend.all()); n != 1 {
		t.Fatalf("backend has %d sessions, want 1", n)
	}
}

// TestProxyEnforcesPacketPolicy speaks CONNECT-IP directly over an HTTP/3
// request stream, bypassing connect-ip-go's client-side checks, so that the
// proxy's own source and destination checks are what drop the packets. The
// request omits Capsule-Protocol, which RFC 9484 does not require.
func TestProxyEnforcesPacketPolicy(t *testing.T) {
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

	send := func(src, dst netip.Addr, id int) {
		t.Helper()
		pkt := append([]byte{0}, echoRequest(t, src, dst, id, 100)...)
		if err := rstr.SendDatagram(pkt); err != nil {
			t.Fatalf("SendDatagram: %v", err)
		}
	}
	spoofed := netip.MustParseAddr("fd00:a::1ff")
	outside := netip.MustParseAddr("fd00:b::1")
	send(spoofed, testTarget, 10)     // source is not the assigned address
	send(firstClient, outside, 11)    // destination is outside the advertised routes
	send(firstClient, testTarget, 12) // allowed

	for {
		data, err := rstr.ReceiveDatagram(ctx)
		if err != nil {
			t.Fatalf("ReceiveDatagram: %v", err)
		}
		// Skip the admission MTU probe, which uses an unregistered context ID.
		if data[0] != 0 {
			if len(data) != 1+MinInnerMTU {
				t.Errorf("probe datagram has %d bytes, want %d", len(data), 1+MinInnerMTU)
			}
			continue
		}
		if id := echoID(t, parseICMPv6(t, data[1:])); id != 12 {
			t.Fatalf("reply for echo id %d, want 12", id)
		}
		break
	}
	pkts := sess.packets()
	if len(pkts) != 1 || echoID(t, parseICMPv6(t, pkts[0])) != 12 {
		t.Fatalf("backend received %d packets, want only echo id 12", len(pkts))
	}
}

func TestMinimumInnerMTU(t *testing.T) {
	env := startServer(t, nil)
	qconn := env.dialQUIC(t)
	cc := newClientConn(t, qconn)
	s := open(t, cc, env.newRequest(t, authHeaders(tokenAlice, vpcBlue)))
	sess := env.backend.nextOpened(t)

	var tooLarge *quic.DatagramTooLargeError
	if err := qconn.SendDatagram(make([]byte, maxPacketSize)); !errors.As(err, &tooLarge) {
		t.Fatalf("oversized SendDatagram error = %v, want DatagramTooLargeError", err)
	}
	t.Logf("client max QUIC datagram payload: %d bytes", tooLarge.MaxDatagramPayloadSize)

	t.Run("1280BytesBothWays", func(t *testing.T) {
		reply := ping(t, s, 1, MinInnerMTU)
		if n := len(reply.msg.Body.(*icmp.Echo).Data) + ipv6.HeaderLen + 8; n != MinInnerMTU {
			t.Fatalf("reply is %d bytes, want %d", n, MinInnerMTU)
		}
	})

	t.Run("OversizedFromClientYieldsPacketTooBig", func(t *testing.T) {
		before := len(sess.packets())
		ptb, err := s.conn.WritePacket(echoRequest(t, s.address, testTarget, 2, 1500))
		if err != nil {
			t.Fatalf("WritePacket: %v", err)
		}
		if ptb == nil {
			t.Fatal("oversized packet was sent without a Packet Too Big")
		}
		p := parseICMPv6(t, ptb)
		body, ok := p.msg.Body.(*icmp.PacketTooBig)
		if p.msg.Type != ipv6.ICMPTypePacketTooBig || !ok {
			t.Fatalf("got ICMPv6 %v, want Packet Too Big", p.msg.Type)
		}
		if body.MTU != MinInnerMTU || p.dst != s.address || p.src != testTarget {
			t.Errorf("Packet Too Big %s -> %s MTU %d, want %s -> %s MTU %d",
				p.src, p.dst, body.MTU, testTarget, s.address, MinInnerMTU)
		}
		ping(t, s, 3, 100)
		if got := len(sess.packets()) - before; got != 1 {
			t.Errorf("backend received %d packets, want only the follow-up ping", got)
		}
	})

	t.Run("OversizedToClientYieldsPacketTooBigToBackend", func(t *testing.T) {
		sess.inject(echoRequest(t, testTarget, s.address, 4, 1500))
		deadline := time.Now().Add(testTimeout)
		for time.Now().Before(deadline) {
			for _, pkt := range sess.packets() {
				p, err := tryParseICMPv6(pkt)
				if err != nil || p.msg.Type != ipv6.ICMPTypePacketTooBig {
					continue
				}
				if p.dst != testTarget || p.src != s.address || p.msg.Body.(*icmp.PacketTooBig).MTU != MinInnerMTU {
					t.Fatalf("Packet Too Big %s -> %s, want %s -> %s MTU %d",
						p.src, p.dst, s.address, testTarget, MinInnerMTU)
				}
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatal("backend never received a Packet Too Big")
	})
}

func TestRejectsPathBelowMinimumInnerMTU(t *testing.T) {
	env := startServer(t, func(c *Config) {
		c.QUICConfig = &quic.Config{InitialPacketSize: 1200, DisablePathMTUDiscovery: true}
	})
	cc := newClientConn(t, env.dialQUIC(t))
	conn, rsp, err := cc.Dial(env.newRequest(t, authHeaders(tokenAlice, vpcBlue)))
	if err == nil {
		_ = conn.Close()
		t.Fatal("request was accepted on a path below the minimum inner MTU")
	}
	if rsp == nil || rsp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("response = %v (err %v), want 503", rsp, err)
	}
	if n := len(env.backend.all()); n != 0 {
		t.Fatalf("backend opened %d sessions", n)
	}
}

func TestNoIrohDependency(t *testing.T) {
	gobin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go toolchain not on PATH")
	}
	out, err := exec.CommandContext(t.Context(), gobin, "list", "-deps",
		"-f", "{{with .Module}}{{.Path}}{{end}}", ".").Output()
	if err != nil {
		t.Fatalf("go list -deps: %v", err)
	}
	modules := strings.Fields(string(out))
	if !slices.Contains(modules, "github.com/quic-go/connect-ip-go") {
		t.Fatal("go list -deps does not list connect-ip-go; the check is not inspecting this package")
	}
	for _, m := range modules {
		if lower := strings.ToLower(m); strings.Contains(lower, "iroh") || strings.Contains(lower, "n0-computer") {
			t.Errorf("package depends on module %s", m)
		}
	}
}

func TestRouteRanges(t *testing.T) {
	tests := []struct {
		name      string
		prefixes  []string
		want      []string
		wantError bool
	}{
		{"SortsFamiliesAndAddresses", []string{"fd00:b::/64", "192.0.2.0/24", "fd00:a::/64"},
			[]string{"192.0.2.0-192.0.2.255", "fd00:a::-fd00:a::ffff:ffff:ffff:ffff", "fd00:b::-fd00:b::ffff:ffff:ffff:ffff"},
			false},
		{"HostBitsMasked", []string{"fd00:a::1/120"}, []string{"fd00:a::-fd00:a::ff"}, false},
		{"SingleAddress", []string{"2001:db8::1/128"}, []string{"2001:db8::1-2001:db8::1"}, false},
		{"Overlap", []string{"fd00:a::/64", "fd00:a::/120"}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prefixes := make([]netip.Prefix, 0, len(tt.prefixes))
			for _, p := range tt.prefixes {
				prefixes = append(prefixes, netip.MustParsePrefix(p))
			}
			routes, err := routeRanges(prefixes)
			if (err != nil) != tt.wantError {
				t.Fatalf("routeRanges error = %v, wantError = %v", err, tt.wantError)
			}
			got := make([]string, 0, len(routes))
			for _, r := range routes {
				got = append(got, r.StartIP.String()+"-"+r.EndIP.String())
			}
			if !tt.wantError && !slices.Equal(got, tt.want) {
				t.Fatalf("routes = %v, want %v", got, tt.want)
			}
		})
	}
}
