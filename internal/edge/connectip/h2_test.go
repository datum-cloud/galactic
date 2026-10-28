// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package connectip

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/quic-go/quic-go/quicvarint"
	"golang.org/x/net/http2"
	"golang.org/x/net/ipv6"
)

// TestH2ExtendedConnectRequest is the reproduction from #981: a CONNECT-IP
// request as net/http's HTTP/2 server delivers it used to get 501 from the
// HTTP/3-only request path, and opened no session.
func TestH2ExtendedConnectRequest(t *testing.T) {
	env := startServer(t, nil)
	r := httptest.NewRequestWithContext(t.Context(), http.MethodConnect, "https://"+env.addr+TemplatePath, nil)
	// httptest parses a CONNECT target as authority-form; set what
	// net/http's HTTP/2 server sets from :authority and :path.
	r.Host, r.URL.Path = env.addr, TemplatePath
	r.Proto, r.ProtoMajor, r.ProtoMinor = "HTTP/2.0", 2, 0
	r.Header.Set(protocolPseudoHeader, connectIPProtocol)
	r.Header.Set("Authorization", "Bearer "+tokenAlice)
	r.Header.Set(VPCHeader, vpcBlue)
	// The request body is empty, so the session ends as soon as it starts.
	w := httptest.NewRecorder()
	env.server.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if n := len(env.backend.all()); n != 1 {
		t.Fatalf("backend opened %d sessions, want 1", n)
	}
}

func TestH2RoundTrip(t *testing.T) {
	env := startServer(t, nil)
	c := env.dialH2(t)
	s, prefix := env.openH2(t, c, tokenAlice, vpcBlue)
	if prefix != firstPrefix {
		t.Fatalf("assigned %s, want %s", prefix, firstPrefix)
	}
	sess := env.backend.nextOpened(t)

	// 1280-byte packets cross in both directions; the reply's hop limit is
	// decremented on encapsulation.
	s.sendDatagram(t, echoRequest(t, firstClient, testTarget, 1, MinInnerMTU))
	reply := s.readDatagram(t)
	if len(reply) != MinInnerMTU {
		t.Fatalf("reply has %d bytes, want %d", len(reply), MinInnerMTU)
	}
	p := parseICMPv6(t, reply)
	if p.msg.Type != ipv6.ICMPTypeEchoReply || p.src != testTarget || p.dst != firstClient {
		t.Fatalf("reply %v %s -> %s, want echo reply %s -> %s", p.msg.Type, p.src, p.dst, testTarget, firstClient)
	}
	if want := echoRequest(t, testTarget, firstClient, 1, MinInnerMTU)[7] - 1; p.hopLimit != int(want) {
		t.Fatalf("reply hop limit %d, want %d", p.hopLimit, want)
	}
	pkts := sess.packets()
	if len(pkts) != 1 || len(pkts[0]) != MinInnerMTU {
		t.Fatalf("backend received %d packets, want one of %d bytes", len(pkts), MinInnerMTU)
	}
	if pkts[0][7] != echoRequest(t, firstClient, testTarget, 1, MinInnerMTU)[7] {
		t.Fatal("a client packet's hop limit changed")
	}
}

func TestH2Settings(t *testing.T) {
	env := startServer(t, func(c *Config) { c.Limits.MaxStreamsPerConn = 3 })
	c := env.dialH2(t)
	s := <-c.settings
	if got := s[http2.SettingMaxConcurrentStreams]; got != 3 {
		t.Fatalf("SETTINGS_MAX_CONCURRENT_STREAMS = %d, want 3", got)
	}
}

func TestH2AdmissionRejectsWithoutBackendSession(t *testing.T) {
	env := startServer(t, nil)
	c := env.dialH2(t)
	withVPC := func(auth string, vpcs ...string) http.Header {
		h := http.Header{}
		if auth != "" {
			h.Set("Authorization", auth)
		}
		for _, v := range vpcs {
			h.Add(VPCHeader, v)
		}
		return h
	}
	tests := []struct {
		name      string
		authority string
		headers   http.Header
		want      int
	}{
		{"NoCredential", env.addr, withVPC("", vpcBlue), http.StatusUnauthorized},
		{"UnknownToken", env.addr, withVPC("Bearer test-token-unknown", vpcBlue), http.StatusUnauthorized},
		{"WrongScheme", env.addr, withVPC("Basic "+tokenAlice, vpcBlue), http.StatusUnauthorized},
		{"NoVPC", env.addr, withVPC("Bearer " + tokenAlice), http.StatusBadRequest},
		{"TwoVPCFields", env.addr, withVPC("Bearer "+tokenAlice, vpcBlue, vpcGreen), http.StatusBadRequest},
		{"BobDeniedBlue", env.addr, withVPC("Bearer "+tokenBob, vpcBlue), http.StatusForbidden},
		{"UnknownVPC", env.addr, withVPC("Bearer "+tokenAlice, "purple"), http.StatusForbidden},
		{"WrongAuthority", "proxy.invalid", withVPC("Bearer "+tokenAlice, vpcBlue), http.StatusBadRequest},
		{"CapsuleProtocolFalse", env.addr, func() http.Header {
			h := withVPC("Bearer "+tokenAlice, vpcBlue)
			h.Set(capsuleProtocolHeader, "?0")
			return h
		}(), http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, status := c.request(t, tt.authority, tt.headers)
			if status != tt.want {
				t.Fatalf("status = %d, want %d", status, tt.want)
			}
			s.waitEnded(t)
		})
	}
	if n := len(env.backend.all()); n != 0 {
		t.Fatalf("backend opened %d sessions for rejected requests", n)
	}
	// Capsule-Protocol with parameters is still true.
	h := authHeaders(tokenBob, vpcGreen)
	h.Set(capsuleProtocolHeader, "?1;x=1")
	if _, status := c.request(t, env.addr, h); status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
}

func TestCapsuleProtocolAllowed(t *testing.T) {
	for _, tt := range []struct {
		values []string
		want   bool
	}{
		{nil, true},
		{[]string{"?1"}, true},
		{[]string{" ?1 ;a=b"}, true},
		{[]string{"?0"}, false},
		{[]string{"1"}, false},
		{[]string{"?1", "?1"}, false},
	} {
		h := http.Header{}
		if tt.values != nil {
			h[capsuleProtocolHeader] = tt.values
		}
		if got := capsuleProtocolAllowed(h); got != tt.want {
			t.Errorf("capsuleProtocolAllowed(%q) = %v, want %v", tt.values, got, tt.want)
		}
	}
}

func TestH2EnforcesPacketPolicy(t *testing.T) {
	env := startServer(t, nil)
	s, _ := env.openH2(t, env.dialH2(t), tokenAlice, vpcBlue)
	sess := env.backend.nextOpened(t)

	counted := func(direction, reason string) float64 {
		return testutil.ToFloat64(packetsDenied.WithLabelValues(direction, reason))
	}
	type count struct{ direction, reason string }
	want := map[count]float64{}
	for _, c := range []count{
		{toVPC, reasonSource}, {toVPC, reasonDestination}, {toVPC, reasonTooLarge}, {toVPC, reasonFragment},
		{toClient, reasonDestination}, {toClient, reasonHopLimit},
	} {
		want[c] = counted(c.direction, c.reason) + 1
	}

	spoofed := netip.MustParseAddr("fd00:a::1ff")
	outside := netip.MustParseAddr("fd00:b::1")
	s.sendDatagram(t, echoRequest(t, spoofed, testTarget, 10, 100))
	s.sendDatagram(t, echoRequest(t, firstClient, outside, 11, 100))
	s.sendDatagram(t, withExtension(echoRequest(t, firstClient, testTarget, 12, 100), protoFragment, make([]byte, 8)))
	// Over maxH2Packet: discarded without ending the request.
	s.sendDatagram(t, echoRequest(t, firstClient, testTarget, 13, maxH2Packet+8))
	// A datagram in an unregistered context is ignored.
	other := quicvarint.Append(appendCapsuleHeader(nil, capsuleDatagram, 1+100), 5)
	if err := s.send(append(other, echoRequest(t, firstClient, testTarget, 14, 100)...), 16384); err != nil {
		t.Fatal(err)
	}
	// A hop limit of 1 from the client reaches the backend unchanged.
	low := echoRequest(t, firstClient, testTarget, 15, 100)
	low[7] = 1
	s.sendDatagram(t, low)
	s.sendDatagram(t, echoRequest(t, firstClient, testTarget, 16, 100))

	// Toward the client: another /96, then a hop limit that would reach 0.
	sess.inject(echoRequest(t, testTarget, sibling, 20, 100))
	expiring := echoRequest(t, testTarget, firstClient, 21, 100)
	expiring[7] = 1
	sess.inject(expiring)

	var got []int
	for len(got) < 2 {
		got = append(got, echoID(t, parseICMPv6(t, s.readDatagram(t))))
	}
	slices.Sort(got)
	if !slices.Equal(got, []int{15, 16}) {
		t.Fatalf("client received echo ids %v, want 15 and 16", got)
	}
	pkts := sess.packets()
	ids := make([]int, 0, len(pkts))
	for _, p := range pkts {
		ids = append(ids, echoID(t, parseICMPv6(t, p)))
	}
	if !slices.Equal(ids, []int{15, 16}) {
		t.Fatalf("backend received echo ids %v, want 15 and 16", ids)
	}
	for c, n := range want {
		pollUntil(t, c.direction+"/"+c.reason+" is counted", func() bool { return counted(c.direction, c.reason) == n })
	}
}

// TestH2ReturnsPacketTooBig injects a gVPC packet over maxH2Packet and
// checks that its Packet Too Big passes the policy and reaches the sender.
func TestH2ReturnsPacketTooBig(t *testing.T) {
	env := startServer(t, nil)
	s, _ := env.openH2(t, env.dialH2(t), tokenAlice, vpcBlue)
	sess := env.backend.nextOpened(t)
	sess.inject(echoRequest(t, testTarget, firstClient, 30, maxH2Packet+8))
	pollUntil(t, "a Packet Too Big reaches the backend", func() bool {
		for _, pkt := range sess.packets() {
			if p, err := tryParseICMPv6(pkt); err == nil && p.msg.Type == ipv6.ICMPTypePacketTooBig {
				if p.src != firstClient || p.dst != testTarget {
					t.Fatalf("Packet Too Big from %s to %s, want %s to %s", p.src, p.dst, firstClient, testTarget)
				}
				if len(pkt) != MinInnerMTU {
					t.Fatalf("Packet Too Big has %d bytes, want %d", len(pkt), MinInnerMTU)
				}
				return true
			}
		}
		return false
	})
	// The session still works.
	s.sendDatagram(t, echoRequest(t, firstClient, testTarget, 31, 100))
	if id := echoID(t, parseICMPv6(t, s.readDatagram(t))); id != 31 {
		t.Fatalf("reply id %d, want 31", id)
	}
}

// TestH2CapsuleFraming sends capsules one byte per DATA frame, and several
// capsules in one DATA frame, including unknown and oversized ones.
func TestH2CapsuleFraming(t *testing.T) {
	env := startServer(t, nil)
	s, _ := env.openH2(t, env.dialH2(t), tokenAlice, vpcBlue)
	var split []byte
	split = appendDatagram(split, echoRequest(t, firstClient, testTarget, 40, 300))
	split = append(appendCapsuleHeader(split, 0x29, 3), "abc"...)
	if err := s.send(split, 1); err != nil {
		t.Fatal(err)
	}
	if id := echoID(t, parseICMPv6(t, s.readDatagram(t))); id != 40 {
		t.Fatalf("reply id %d, want 40", id)
	}

	var coalesced []byte
	coalesced = append(appendCapsuleHeader(coalesced, 0x29, 70000), make([]byte, 70000)...)
	coalesced = appendDatagram(coalesced, echoRequest(t, firstClient, testTarget, 41, 4000))
	coalesced = appendDatagram(coalesced, echoRequest(t, firstClient, testTarget, 42, 200))
	coalesced = appendDatagram(coalesced, echoRequest(t, firstClient, testTarget, 43, 200))
	if err := s.send(coalesced, 16384); err != nil {
		t.Fatal(err)
	}
	for _, want := range []int{42, 43} {
		if id := echoID(t, parseICMPv6(t, s.readDatagram(t))); id != want {
			t.Fatalf("reply id %d, want %d", id, want)
		}
	}
}

func TestH2AddressRequest(t *testing.T) {
	env := startServer(t, nil)
	s, prefix := env.openH2(t, env.dialH2(t), tokenAlice, vpcBlue)
	var v []byte
	v = quicvarint.Append(v, 7)
	v = appendPrefix(v, netip.MustParsePrefix("192.0.2.0/24"))
	v = quicvarint.Append(v, 8)
	v = appendPrefix(v, netip.MustParsePrefix("::/0"))
	if err := s.send(append(appendCapsuleHeader(nil, capsuleAddressRequest, len(v)), v...), 16384); err != nil {
		t.Fatal(err)
	}
	c := s.nextCapsule(t)
	if c.typ != capsuleAddressAssign {
		t.Fatalf("capsule type %#x, want ADDRESS_ASSIGN", c.typ)
	}
	got := parseAssignments(t, c.value)
	want := []assignment{
		{requestID: 7, prefix: netip.MustParsePrefix("0.0.0.0/32")},
		{requestID: 8, prefix: prefix},
	}
	if !slices.Equal(got, want) {
		t.Fatalf("ADDRESS_ASSIGN %v, want %v", got, want)
	}
}

// TestH2MalformedInputEndsOnlyItsRequest sends each malformed input on its
// own request while a sibling request on the same connection keeps
// forwarding.
func TestH2MalformedInputEndsOnlyItsRequest(t *testing.T) {
	addressRequest := func(v []byte) []byte {
		return append(appendCapsuleHeader(nil, capsuleAddressRequest, len(v)), v...)
	}
	zeroID := appendPrefix(quicvarint.Append(nil, 0), netip.MustParsePrefix("::/0"))
	hostBits := appendPrefix(quicvarint.Append(nil, 1), netip.MustParsePrefix("::/0"))
	hostBits[len(hostBits)-2] = 1
	tests := []struct {
		name  string
		input []byte
		// finish ends the client's side after input.
		finish bool
	}{
		{"TruncatedByFIN", append(appendCapsuleHeader(nil, capsuleDatagram, 200), make([]byte, 50)...), true},
		{"TruncatedLength", []byte{0x00, 0x40}, true},
		{"EmptyDatagram", appendCapsuleHeader(nil, capsuleDatagram, 0), false},
		{"AddressRequestZeroID", addressRequest(zeroID), false},
		{"AddressRequestHostBits", addressRequest(hostBits), false},
		{"AddressRequestEmpty", addressRequest(nil), false},
		{"AddressRequestTooLarge", addressRequest(make([]byte, maxAddressRequestCapsule+1)), false},
	}
	env := startServer(t, nil)
	c := env.dialH2(t)
	sibling, _ := env.openH2(t, c, tokenBob, vpcGreen)
	siblingSess := env.backend.nextOpened(t)
	siblingAddr := siblingSess.info.Prefix.Addr().Next()
	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, _ := env.openH2(t, c, tokenAlice, vpcBlue)
			sess := env.backend.nextOpened(t)
			if err := s.send(tt.input, 16384); err != nil {
				t.Fatal(err)
			}
			if tt.finish {
				s.finish()
			}
			sess.waitClosed(t)
			s.waitEnded(t)
			sibling.sendDatagram(t, echoRequest(t, siblingAddr, testTarget, 100+i, MinInnerMTU))
			if id := echoID(t, parseICMPv6(t, sibling.readDatagram(t))); id != 100+i {
				t.Fatalf("sibling reply id %d, want %d", id, 100+i)
			}
		})
	}
}

func TestH2CancelledRequestLeavesSiblingRunning(t *testing.T) {
	adm := newTestAdmission()
	env := startServer(t, func(c *Config) { c.Admission = adm })
	c := env.dialH2(t)
	a, _ := env.openH2(t, c, tokenAlice, vpcBlue)
	aSess := env.backend.nextOpened(t)
	b, _ := env.openH2(t, c, tokenBob, vpcGreen)
	bSess := env.backend.nextOpened(t)
	a.cancel()
	aSess.waitClosed(t)
	adm.waitReleased(t, aSess.info)
	b.sendDatagram(t, echoRequest(t, bSess.info.Prefix.Addr().Next(), testTarget, 50, 200))
	if id := echoID(t, parseICMPv6(t, b.readDatagram(t))); id != 50 {
		t.Fatalf("reply id %d, want 50", id)
	}
	if bSess.isClosed() {
		t.Fatal("sibling's backend session closed")
	}
}

// TestH2SlowReaderEndsOnlyItsRequest stops granting one request flow-control
// window. Its session ends once a capsule write blocks for h2WriteTimeout,
// and a request on another connection keeps forwarding.
func TestH2SlowReaderEndsOnlyItsRequest(t *testing.T) {
	old := h2WriteTimeout
	h2WriteTimeout = 300 * time.Millisecond
	t.Cleanup(func() { h2WriteTimeout = old })
	adm := newTestAdmission()
	env := startServer(t, func(c *Config) { c.Admission = adm })
	slow, _ := env.openH2(t, env.dialH2(t), tokenAlice, vpcBlue)
	slowSess := env.backend.nextOpened(t)
	fast, _ := env.openH2(t, env.dialH2(t), tokenBob, vpcGreen)
	fastSess := env.backend.nextOpened(t)
	slow.pause()

	// The default 64 KiB stream window holds about 50 of these; the rest
	// block, or wait in the backend's bounded queue.
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() {
		for i := 0; ; i++ {
			select {
			case slowSess.toClient <- echoRequest(t, testTarget, firstClient, i%60000, MinInnerMTU):
			case <-stop:
				return
			case <-slowSess.closed:
				return
			}
		}
	})
	defer func() { close(stop); wg.Wait() }()
	slowSess.waitClosed(t)
	adm.waitReleased(t, slowSess.info)

	fast.sendDatagram(t, echoRequest(t, fastSess.info.Prefix.Addr().Next(), testTarget, 60, MinInnerMTU))
	if id := echoID(t, parseICMPv6(t, fast.readDatagram(t))); id != 60 {
		t.Fatalf("reply id %d, want 60", id)
	}
}

// TestH2IdleSessionOutlivesWriteTimeout keeps a session idle for longer
// than h2WriteTimeout after the server's last write. HTTP/2 resets a stream
// whose write deadline passes even with no write pending.
func TestH2IdleSessionOutlivesWriteTimeout(t *testing.T) {
	old := h2WriteTimeout
	h2WriteTimeout = 100 * time.Millisecond
	t.Cleanup(func() { h2WriteTimeout = old })
	env := startServer(t, nil)
	s, _ := env.openH2(t, env.dialH2(t), tokenAlice, vpcBlue)
	for i := range 2 {
		time.Sleep(3 * h2WriteTimeout)
		s.sendDatagram(t, echoRequest(t, firstClient, testTarget, 90+i, 200))
		if id := echoID(t, parseICMPv6(t, s.readDatagram(t))); id != 90+i {
			t.Fatalf("reply id %d, want %d", id, 90+i)
		}
	}
}

func TestH2LeaseRevocationEndsSession(t *testing.T) {
	adm := newTestAdmission()
	env := startServer(t, func(c *Config) { c.Admission = adm })
	s, _ := env.openH2(t, env.dialH2(t), tokenAlice, vpcBlue)
	sess := env.backend.nextOpened(t)
	adm.mu.Lock()
	lease := adm.leases[vpcBlue][firstPrefix]
	adm.mu.Unlock()
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	sess.waitClosed(t)
	s.waitEnded(t)
}

// TestH2SharesSessionLimitWithH3 holds the only session over HTTP/3, so an
// HTTP/2 request gets 503 before Admit runs.
func TestH2SharesSessionLimitWithH3(t *testing.T) {
	adm := newTestAdmission()
	var mu sync.Mutex
	calls := 0
	env := startServer(t, func(c *Config) {
		c.Admission = admissionFunc(func(ctx context.Context, token, vpc string) (Lease, error) {
			mu.Lock()
			calls++
			mu.Unlock()
			return adm.Admit(ctx, token, vpc)
		})
		c.Limits.MaxSessions = 1
	})
	open(t, newClientConn(t, env.dialQUIC(t)), env.newRequest(t, authHeaders(tokenAlice, vpcBlue)))
	env.backend.nextOpened(t)
	_, status := env.dialH2(t).request(t, env.addr, authHeaders(tokenBob, vpcGreen))
	if status != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", status)
	}
	mu.Lock()
	defer mu.Unlock()
	if calls != 1 {
		t.Fatalf("Admit ran %d times, want 1", calls)
	}
}

func TestH2ConnectionLimits(t *testing.T) {
	t.Run("Total", func(t *testing.T) {
		env := startServer(t, func(c *Config) { c.Limits.MaxConnections = 1 })
		// A QUIC connection with an accepted request holds the one slot.
		open(t, newClientConn(t, env.dialQUIC(t)), env.newRequest(t, authHeaders(tokenAlice, vpcBlue)))
		if _, err := env.tryDialH2(t); err == nil {
			t.Fatal("TCP connection over the total cap was served")
		}
	})
	t.Run("PerSource", func(t *testing.T) {
		env := startServer(t, func(c *Config) { c.Limits.MaxConnectionsPerSource = 1 })
		first := env.dialH2(t)
		if _, err := env.tryDialH2(t); err == nil {
			t.Fatal("second TCP connection from one source was served")
		}
		// Closing the first frees the slot.
		_ = first.conn.Close()
		pollUntil(t, "a new TCP connection is served", func() bool {
			_, err := env.tryDialH2(t)
			return err == nil
		})
	})
}

func TestH2HandshakeTimeout(t *testing.T) {
	env := startServer(t, func(c *Config) { c.Limits.HandshakeTimeout = 200 * time.Millisecond })
	conn, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", env.tcpAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	// Send nothing: the server must close the connection.
	_ = conn.SetReadDeadline(time.Now().Add(testTimeout))
	if _, err := io.ReadAll(conn); err != nil {
		if ne, ok := errors.AsType[net.Error](err); ok && ne.Timeout() {
			t.Fatal("server kept a connection open without a TLS handshake")
		}
	}

	// A session outlives the handshake timeout.
	s, _ := env.openH2(t, env.dialH2(t), tokenAlice, vpcBlue)
	time.Sleep(500 * time.Millisecond)
	s.sendDatagram(t, echoRequest(t, firstClient, testTarget, 70, 200))
	if id := echoID(t, parseICMPv6(t, s.readDatagram(t))); id != 70 {
		t.Fatalf("reply id %d, want 70", id)
	}
}

func TestServeTLSRequiresExtendedConnect(t *testing.T) {
	t.Setenv("GODEBUG", "")
	cert, _ := selfSignedCert(t)
	srv, err := NewServer(Config{
		Authority: "proxy.example", TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}},
		Admission: newTestAdmission(), Backend: newMemoryBackend(),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	if err := srv.ServeTLS(ln); !errors.Is(err, ErrExtendedConnectDisabled) {
		t.Fatalf("ServeTLS = %v, want ErrExtendedConnectDisabled", err)
	}
}

// singleOwnerAdmission gives each credential one forwarding owner. Admitting
// it again revokes the previous lease and waits for the server to release
// it, as a provider that replaces a connector's owner does.
type singleOwnerAdmission struct {
	*testAdmission
	mu    sync.Mutex
	owner map[string]*ownedLease
}

// ownedLease is revoked by closing done and released by Close.
type ownedLease struct {
	Lease
	done     chan struct{}
	revoke   sync.Once
	released chan struct{}
	release  sync.Once
}

func (l *ownedLease) Done() <-chan struct{} { return l.done }

func (l *ownedLease) Close() error {
	l.revoke.Do(func() { close(l.done) })
	l.release.Do(func() { close(l.released) })
	return l.Lease.Close()
}

func (a *singleOwnerAdmission) Admit(ctx context.Context, token, vpc string) (Lease, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if old := a.owner[token]; old != nil {
		old.revoke.Do(func() { close(old.done) })
		select {
		case <-old.released:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	l, err := a.testAdmission.Admit(ctx, token, vpc)
	if err != nil {
		return nil, err
	}
	owned := &ownedLease{Lease: l, done: make(chan struct{}), released: make(chan struct{})}
	a.owner[token] = owned
	return owned, nil
}

// TestReplaceQUICTunnelWithH2 replaces a connector's HTTP/3 tunnel with an
// HTTP/2 one through the same admission. The old session ends, and the
// backend never has both open.
func TestReplaceQUICTunnelWithH2(t *testing.T) {
	adm := &singleOwnerAdmission{testAdmission: newTestAdmission(), owner: map[string]*ownedLease{}}
	backend := &exclusiveBackend{memoryBackend: newMemoryBackend()}
	env := startServer(t, func(c *Config) {
		c.Admission = adm
		c.Backend = backend
	})
	env.backend = backend.memoryBackend
	quicSession := open(t, newClientConn(t, env.dialQUIC(t)), env.newRequest(t, authHeaders(tokenAlice, vpcBlue)))
	old := env.backend.nextOpened(t)
	ping(t, quicSession, 80, 200)

	s, _ := env.openH2(t, env.dialH2(t), tokenAlice, vpcBlue)
	old.waitClosed(t)
	sess := env.backend.nextOpened(t)
	s.sendDatagram(t, echoRequest(t, sess.info.Prefix.Addr().Next(), testTarget, 81, 200))
	if id := echoID(t, parseICMPv6(t, s.readDatagram(t))); id != 81 {
		t.Fatalf("reply id %d, want 81", id)
	}
	if backend.overlapped() {
		t.Fatal("backend had two sessions of one principal open at once")
	}
}

// exclusiveBackend waits, when it opens a session, for the principal's
// previous session to close, and records whether it had to.
type exclusiveBackend struct {
	*memoryBackend
	mu      sync.Mutex
	open    map[string]*memorySession
	overlap bool
}

func (b *exclusiveBackend) Open(ctx context.Context, info SessionInfo) (BackendSession, error) {
	b.mu.Lock()
	if b.open == nil {
		b.open = map[string]*memorySession{}
	}
	prev := b.open[info.Principal]
	b.mu.Unlock()
	if prev != nil && !prev.isClosed() {
		select {
		case <-prev.closed:
		case <-time.After(10 * time.Millisecond):
			b.mu.Lock()
			b.overlap = true
			b.mu.Unlock()
		}
	}
	s, err := b.memoryBackend.Open(ctx, info)
	if err != nil {
		return nil, err
	}
	b.mu.Lock()
	b.open[info.Principal] = s.(*memorySession)
	b.mu.Unlock()
	return s, nil
}

func (b *exclusiveBackend) overlapped() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.overlap
}

func TestCapsuleReader(t *testing.T) {
	pkt := bytes.Repeat([]byte{0x60}, MinInnerMTU)
	var stream []byte
	stream = appendDatagram(stream, pkt)
	stream = append(appendCapsuleHeader(stream, 0x29, 7), "unknown"...)
	stream = appendCapsuleHeader(stream, capsuleDatagram, maxDatagramCapsule+1)
	stream = append(stream, make([]byte, maxDatagramCapsule+1)...)
	stream = appendDatagram(stream, pkt[:40])
	for name, r := range map[string]io.Reader{
		"split":     &oneByteReader{data: stream},
		"coalesced": bytes.NewReader(stream),
	} {
		t.Run(name, func(t *testing.T) {
			cr := newCapsuleReader(r)
			type got struct {
				typ     uint64
				n       int
				skipped bool
			}
			var all []got
			for {
				c, err := cr.next()
				if errors.Is(err, io.EOF) {
					break
				}
				if err != nil {
					t.Fatalf("next: %v", err)
				}
				all = append(all, got{c.typ, len(c.value), c.skipped})
			}
			want := []got{
				{capsuleDatagram, 1 + MinInnerMTU, false}, {0x29, 0, true},
				{capsuleDatagram, 0, true}, {capsuleDatagram, 41, false},
			}
			if !slices.Equal(all, want) {
				t.Fatalf("capsules %v, want %v", all, want)
			}
		})
	}
	for name, in := range map[string][]byte{
		"type only":    {0x00},
		"short value":  appendCapsuleHeader(nil, capsuleDatagram, 10),
		"short length": {0x00, 0x40},
	} {
		if _, err := newCapsuleReader(bytes.NewReader(in)).next(); !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Errorf("%s: err = %v, want io.ErrUnexpectedEOF", name, err)
		}
	}
	big := appendCapsuleHeader(nil, capsuleAddressRequest, maxAddressRequestCapsule+1)
	if _, err := newCapsuleReader(bytes.NewReader(big)).next(); !errors.Is(err, errCapsuleTooLarge) {
		t.Errorf("oversized ADDRESS_REQUEST: err = %v, want errCapsuleTooLarge", err)
	}
}

type oneByteReader struct{ data []byte }

func (r *oneByteReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	if len(p) == 0 {
		return 0, nil
	}
	p[0] = r.data[0]
	r.data = r.data[1:]
	return 1, nil
}
