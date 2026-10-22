// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package connectip

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"testing"
	"time"

	connectip "github.com/quic-go/connect-ip-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv6"
)

const (
	testTimeout = 5 * time.Second

	testServerName = "localhost"

	vpcBlue  = "blue"
	vpcGreen = "green"
	vpcRed   = "red"

	principalAlice = "alice"
	tokenAlice     = "test-token-alice"
	tokenBob       = "test-token-bob"
)

var (
	firstPrefix = netip.MustParsePrefix("fd00:a::1:0:0/96")
	testRoute   = netip.MustParsePrefix("fd00:a::/64")
	testTarget  = netip.MustParseAddr("fd00:a::1")
	// firstClient is one address within the delegated prefix.
	firstClient = netip.MustParseAddr("fd00:a::1:0:1")
)

type testEnv struct {
	server   *Server
	backend  *memoryBackend
	addr     string
	template *uritemplate.Template
	roots    *x509.CertPool
}

// startServer runs a Server on a loopback UDP socket with a fresh self-signed
// certificate. mutate may adjust the config before the server is built.
func startServer(t *testing.T, mutate func(*Config)) *testEnv {
	t.Helper()
	pconn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	cert, roots := selfSignedCert(t)
	backend := newMemoryBackend()
	cfg := Config{
		Authority: pconn.LocalAddr().String(),
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13},
		Admission: newTestAdmission(),
		Backend:   backend,
		Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	if mutate != nil {
		mutate(&cfg)
	}
	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	served := make(chan struct{})
	go func() {
		defer close(served)
		_ = srv.Serve(pconn)
	}()
	t.Cleanup(func() {
		_ = srv.Close()
		<-served
		_ = pconn.Close()
	})
	return &testEnv{
		server:   srv,
		backend:  backend,
		addr:     pconn.LocalAddr().String(),
		template: uritemplate.MustNew("https://" + pconn.LocalAddr().String() + TemplatePath),
		roots:    roots,
	}
}

func selfSignedCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: testServerName},
		DNSNames:     []string{testServerName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, roots
}

func (e *testEnv) clientTLS() *tls.Config {
	return &tls.Config{
		ServerName: testServerName,
		RootCAs:    e.roots,
		NextProtos: []string{http3.NextProtoH3},
		MinVersion: tls.VersionTLS13,
	}
}

// dialQUIC opens one client QUIC connection to the server.
func (e *testEnv) dialQUIC(t *testing.T) *quic.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), testTimeout)
	defer cancel()
	qconn, err := quic.DialAddr(ctx, e.addr, e.clientTLS(),
		&quic.Config{EnableDatagrams: true, InitialPacketSize: DefaultInitialPacketSize})
	if err != nil {
		t.Fatalf("dial QUIC: %v", err)
	}
	t.Cleanup(func() { _ = qconn.CloseWithError(0, "") })
	return qconn
}

// newRequest builds a CONNECT-IP request with the given headers, using the
// connect-ip-go client API.
func (e *testEnv) newRequest(t *testing.T, headers http.Header) *connectip.Request {
	t.Helper()
	req, err := connectip.NewRequest(t.Context(), e.template)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	for k, vs := range headers {
		for _, v := range vs {
			req.Header().Add(k, v)
		}
	}
	return req
}

func authHeaders(token, vpc string) http.Header {
	h := http.Header{}
	h.Set("Authorization", "Bearer "+token)
	h.Set(VPCHeader, vpc)
	return h
}

// session is an accepted client-side CONNECT-IP request.
type session struct {
	conn    *connectip.Conn
	address netip.Addr
	routes  []connectip.IPRoute
}

// open dials a request on cc and returns it once accepted.
func open(t *testing.T, cc *connectip.ClientConn, req *connectip.Request) *session {
	t.Helper()
	conn, rsp, err := cc.Dial(req)
	return accepted(t, conn, rsp, err)
}

// accepted requires a dialed request to be accepted and waits for its address
// assignment and route advertisement.
func accepted(t *testing.T, conn *connectip.Conn, rsp *http.Response, err error) *session {
	t.Helper()
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if rsp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", rsp.StatusCode)
	}
	ctx, cancel := context.WithTimeout(t.Context(), testTimeout)
	defer cancel()
	assigned, err := conn.ReceiveAddressAssignment(ctx)
	if err != nil {
		t.Fatalf("ReceiveAddressAssignment: %v", err)
	}
	if len(assigned) != 1 || assigned[0].IPPrefix.Bits() != 96 {
		t.Fatalf("assignment = %v, want one /96", assigned)
	}
	routes, err := conn.Routes(ctx)
	if err != nil {
		t.Fatalf("Routes: %v", err)
	}
	return &session{conn: conn, address: assigned[0].IPPrefix.Addr().Next(), routes: routes}
}

func newClientConn(t *testing.T, qconn *quic.Conn) *connectip.ClientConn {
	t.Helper()
	cc, err := (&connectip.Transport{}).NewClientConn(qconn)
	if err != nil {
		t.Fatalf("NewClientConn: %v", err)
	}
	return cc
}

// readPacket reads one packet from conn or fails the test after testTimeout.
func readPacket(t *testing.T, conn *connectip.Conn) []byte {
	t.Helper()
	type result struct {
		pkt []byte
		err error
	}
	ch := make(chan result, 1)
	go func() {
		buf := make([]byte, maxPacketSize)
		n, err := conn.ReadPacket(buf)
		ch <- result{buf[:n], err}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			t.Fatalf("ReadPacket: %v", r.err)
		}
		return r.pkt
	case <-time.After(testTimeout):
		t.Fatal("timed out waiting for a packet")
		return nil
	}
}

// echoRequest builds an IPv6 ICMPv6 echo request of exactly size bytes.
func echoRequest(t *testing.T, src, dst netip.Addr, id, size int) []byte {
	t.Helper()
	data := make([]byte, size-ipv6.HeaderLen-8)
	for i := range data {
		data[i] = byte(i)
	}
	msg := icmp.Message{Type: ipv6.ICMPTypeEchoRequest, Body: &icmp.Echo{ID: id, Seq: 1, Data: data}}
	return ipv6Packet(t, src, dst, &msg)
}

func ipv6Packet(t *testing.T, src, dst netip.Addr, msg *icmp.Message) []byte {
	t.Helper()
	pkt, err := buildICMPv6(src, dst, msg)
	if err != nil {
		t.Fatalf("build ICMPv6 packet: %v", err)
	}
	return pkt
}

// buildICMPv6 returns an IPv6 packet with hop limit 64 carrying msg.
func buildICMPv6(src, dst netip.Addr, msg *icmp.Message) ([]byte, error) {
	s, d := src.As16(), dst.As16()
	body, err := msg.Marshal(icmp.IPv6PseudoHeader(s[:], d[:]))
	if err != nil {
		return nil, err
	}
	hdr := make([]byte, ipv6.HeaderLen, ipv6.HeaderLen+len(body))
	hdr[0] = 6 << 4
	binary.BigEndian.PutUint16(hdr[4:6], uint16(len(body)))
	hdr[6] = 58
	hdr[7] = 64
	copy(hdr[8:24], s[:])
	copy(hdr[24:40], d[:])
	return append(hdr, body...), nil
}

// parsedICMPv6 is the outer header and message of an ICMPv6 packet.
type parsedICMPv6 struct {
	src, dst netip.Addr
	hopLimit int
	msg      *icmp.Message
}

func parseICMPv6(t *testing.T, pkt []byte) parsedICMPv6 {
	t.Helper()
	p, err := tryParseICMPv6(pkt)
	if err != nil {
		t.Fatalf("parse ICMPv6: %v", err)
	}
	return p
}

func tryParseICMPv6(pkt []byte) (parsedICMPv6, error) {
	if len(pkt) < ipv6.HeaderLen || pkt[0]>>4 != 6 || pkt[6] != 58 {
		return parsedICMPv6{}, errors.New("not an ICMPv6 packet without extension headers")
	}
	msg, err := icmp.ParseMessage(58, pkt[ipv6.HeaderLen:])
	if err != nil {
		return parsedICMPv6{}, err
	}
	return parsedICMPv6{
		src:      netip.AddrFrom16([16]byte(pkt[8:24])),
		dst:      netip.AddrFrom16([16]byte(pkt[24:40])),
		hopLimit: int(pkt[7]),
		msg:      msg,
	}, nil
}

// sessionKey identifies one backend session.
type sessionKey struct {
	vpc string
	id  uint64
}

// memoryBackend is a PacketBackend that records every packet per session and
// answers ICMPv6 echo requests.
type memoryBackend struct {
	mu       sync.Mutex
	sessions map[sessionKey]*memorySession
	opened   chan *memorySession
}

func newMemoryBackend() *memoryBackend {
	return &memoryBackend{sessions: map[sessionKey]*memorySession{}, opened: make(chan *memorySession, 16)}
}

func (b *memoryBackend) Open(_ context.Context, info SessionInfo) (BackendSession, error) {
	s := &memorySession{info: info, toClient: make(chan []byte, 16), closed: make(chan struct{})}
	b.mu.Lock()
	b.sessions[sessionKey{info.VPC, info.ID}] = s
	b.mu.Unlock()
	b.opened <- s
	return s, nil
}

func (b *memoryBackend) all() []*memorySession {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]*memorySession, 0, len(b.sessions))
	for _, s := range b.sessions {
		out = append(out, s)
	}
	return out
}

// nextOpened returns the next session the server opened.
func (b *memoryBackend) nextOpened(t *testing.T) *memorySession {
	t.Helper()
	select {
	case s := <-b.opened:
		return s
	case <-time.After(testTimeout):
		t.Fatal("timed out waiting for a backend session")
		return nil
	}
}

type memorySession struct {
	info     SessionInfo
	toClient chan []byte

	mu       sync.Mutex
	received [][]byte

	closeOnce sync.Once
	closed    chan struct{}
}

func (s *memorySession) WritePacket(pkt []byte) error {
	pkt = append([]byte(nil), pkt...)
	s.mu.Lock()
	s.received = append(s.received, pkt)
	s.mu.Unlock()
	if p, err := tryParseICMPv6(pkt); err == nil && p.msg.Type == ipv6.ICMPTypeEchoRequest {
		reply := echoReply(p)
		select {
		case s.toClient <- reply:
		default:
		}
	}
	return nil
}

func (s *memorySession) ReadPacket(ctx context.Context, buf []byte) (int, error) {
	select {
	case pkt := <-s.toClient:
		return copy(buf, pkt), nil
	case <-s.closed:
		return 0, errors.New("session closed")
	case <-ctx.Done():
		return 0, ctx.Err()
	}
}

func (s *memorySession) Close() error {
	s.closeOnce.Do(func() { close(s.closed) })
	return nil
}

// inject queues pkt for delivery to the client.
func (s *memorySession) inject(pkt []byte) { s.toClient <- pkt }

func (s *memorySession) packets() [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([][]byte(nil), s.received...)
}

func (s *memorySession) isClosed() bool {
	select {
	case <-s.closed:
		return true
	default:
		return false
	}
}

func (s *memorySession) waitClosed(t *testing.T) {
	t.Helper()
	select {
	case <-s.closed:
	case <-time.After(testTimeout):
		t.Fatalf("backend session %d (%s) was not closed", s.info.ID, s.info.VPC)
	}
}

// echoReply answers an echo request with the same identifier, sequence and
// data.
func echoReply(req parsedICMPv6) []byte {
	echo := req.msg.Body.(*icmp.Echo)
	msg := icmp.Message{Type: ipv6.ICMPTypeEchoReply, Body: &icmp.Echo{ID: echo.ID, Seq: echo.Seq, Data: echo.Data}}
	reply, err := buildICMPv6(req.dst, req.src, &msg)
	if err != nil {
		panic(err)
	}
	return reply
}
