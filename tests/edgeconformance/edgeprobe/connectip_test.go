// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv6"

	"go.datum.net/galactic/internal/edge/connectip"
)

const (
	testToken   = "test-token"
	testVPC     = "blue"
	testTimeout = 5 * time.Second
)

var (
	testPrefix = netip.MustParsePrefix("fd00:a::1:0:0/96")
	testRoute  = netip.MustParsePrefix("fd00:a::/64")
	testTarget = netip.MustParseAddr("fd00:a::1")
)

// TestMain re-runs the test binary with GODEBUG=http2xconnect=1 when it is
// missing: net/http reads it once at init, and without it the server's
// HTTP/2 listener does not offer Extended CONNECT.
func TestMain(m *testing.M) {
	if connectip.ExtendedConnectEnabled() {
		os.Exit(m.Run())
	}
	cmd := exec.CommandContext(context.Background(), os.Args[0], os.Args[1:]...)
	cmd.Env = append(os.Environ(), "GODEBUG="+strings.TrimPrefix(os.Getenv("GODEBUG")+",http2xconnect=1", ","))
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		if exit, ok := errors.AsType[*exec.ExitError](err); ok {
			os.Exit(exit.ExitCode())
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Exit(0)
}

// TestConnectIP runs the probe's client against the production CONNECT-IP
// server on both transports: it connects, exchanges 1280-byte echo packets
// both ways and disconnects, and a request with a bad credential prints its
// refusal.
func TestConnectIP(t *testing.T) {
	env := startServer(t)
	for _, tc := range []struct {
		transport string
		server    string
	}{
		{"h3", env.udpAddr},
		{"h2", env.tcpAddr},
	} {
		t.Run(tc.transport, func(t *testing.T) {
			events := env.run(t, tc.transport, tc.server, testToken, "-size", "1280")
			if len(events) == 0 || events[0].Status != 200 || events[0].Proto != tc.transport {
				t.Fatalf("first event = %+v, want status 200 over %s", first(events), tc.transport)
			}
			if events[1].Assigned != testPrefix.String() {
				t.Fatalf("second event = %+v, want assignment of %s", events[1], testPrefix)
			}
			client := testPrefix.Addr().Next()
			replies := 0
			for _, e := range events {
				if e.Reply == replyOther {
					t.Errorf("unexpected packet %+v", e)
				}
				if e.Reply != replyEcho {
					continue
				}
				replies++
				if e.From != testTarget.String() || e.Dst != client.String() || e.Len != 1280 {
					t.Errorf("echo reply %+v, want 1280 bytes from %s to %s", e, testTarget, client)
				}
			}
			last := events[len(events)-1]
			if replies == 0 || last.Sent < replies {
				t.Fatalf("%d echo replies for %d sent, want at least one", replies, last.Sent)
			}
			s := env.backend.session(t)
			if n := s.requests(); n < replies {
				t.Fatalf("backend received %d echo requests, want at least %d", n, replies)
			}
			for _, size := range s.sizes() {
				if size != 1280 {
					t.Fatalf("backend received a %d-byte packet, want 1280", size)
				}
			}
			s.waitClosed(t)
		})
		t.Run(tc.transport+"/refused", func(t *testing.T) {
			events := env.run(t, tc.transport, tc.server, "wrong-token")
			if len(events) != 1 || events[0].Status != 401 || events[0].Proto != tc.transport {
				t.Fatalf("events = %+v, want only status 401 over %s", events, tc.transport)
			}
		})
	}
}

func first(events []cipEvent) cipEvent {
	if len(events) == 0 {
		return cipEvent{}
	}
	return events[0]
}

type testEnv struct {
	udpAddr   string
	tcpAddr   string
	authority string
	caFile    string
	backend   *echoBackend
}

// startServer runs a connectip.Server on loopback for HTTP/3 and HTTP/2 with
// a fresh self-signed certificate, admitting testToken to testVPC.
func startServer(t *testing.T) *testEnv {
	t.Helper()
	pconn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	tcp, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cert, caFile := selfSignedCert(t)
	backend := &echoBackend{opened: make(chan *echoSession, 4)}
	authority := net.JoinHostPort("localhost", strconv.Itoa(pconn.LocalAddr().(*net.UDPAddr).Port))
	srv, err := connectip.NewServer(connectip.Config{
		Authority: authority,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13},
		Admission: &testAdmission{},
		Backend:   backend,
		Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	served := make(chan struct{}, 2)
	go func() {
		defer func() { served <- struct{}{} }()
		_ = srv.Serve(pconn)
	}()
	go func() {
		defer func() { served <- struct{}{} }()
		_ = srv.ServeTLS(tcp)
	}()
	t.Cleanup(func() {
		_ = srv.Close()
		<-served
		<-served
		_ = pconn.Close()
		_ = tcp.Close()
	})
	return &testEnv{
		udpAddr: pconn.LocalAddr().String(), tcpAddr: tcp.Addr().String(),
		authority: authority, caFile: caFile, backend: backend,
	}
}

// run runs the probe's connectip command and returns the events it printed.
func (e *testEnv) run(t *testing.T, transport, server, token string, extra ...string) []cipEvent {
	t.Helper()
	var buf bytes.Buffer
	saved := out
	out = json.NewEncoder(&buf)
	defer func() { out = saved }()
	args := append([]string{"-transport", transport, "-server", server, "-authority", e.authority,
		"-ca", e.caFile, "-token", token, "-vpc", testVPC, "-to", testTarget.String(), "-id", "7",
		"-interval", "50ms", "-duration", "300ms"}, extra...)
	if err := connectIP(args); err != nil {
		t.Fatalf("connectip: %v", err)
	}
	var events []cipEvent
	dec := json.NewDecoder(&buf)
	for {
		var ev cipEvent
		if err := dec.Decode(&ev); errors.Is(err, io.EOF) {
			return events
		} else if err != nil {
			t.Fatalf("decode event: %v", err)
		}
		events = append(events, ev)
	}
}

// selfSignedCert returns a certificate for localhost and the path of a PEM
// file holding it as the CA.
func selfSignedCert(t *testing.T) (tls.Certificate, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, caFile
}

// testAdmission admits testToken to testVPC with testPrefix, one request at
// a time.
type testAdmission struct {
	mu   sync.Mutex
	next uint64
}

func (a *testAdmission) Admit(_ context.Context, token, vpc string) (connectip.Lease, error) {
	if token != testToken {
		return nil, connectip.ErrUnauthenticated
	}
	if vpc != testVPC {
		return nil, connectip.ErrForbidden
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.next++
	return &testLease{done: make(chan struct{}), info: connectip.SessionInfo{
		ID: a.next, Principal: "probe", VPC: vpc, Prefix: testPrefix,
		Connector: "connector", Attachment: "attachment", Claim: fmt.Sprintf("claim-%d", a.next), Epoch: 1,
	}}, nil
}

type testLease struct {
	info connectip.SessionInfo
	done chan struct{}
	once sync.Once
}

func (l *testLease) Info() connectip.SessionInfo { return l.info }
func (*testLease) Routes() []netip.Prefix        { return []netip.Prefix{testRoute} }
func (l *testLease) Done() <-chan struct{}       { return l.done }
func (l *testLease) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}

// echoBackend answers every ICMPv6 echo request a session receives.
type echoBackend struct {
	opened chan *echoSession
}

func (b *echoBackend) Open(context.Context, connectip.SessionInfo) (connectip.BackendSession, error) {
	s := &echoSession{toClient: make(chan []byte, 64), closed: make(chan struct{})}
	b.opened <- s
	return s, nil
}

// session returns the next session the server opened.
func (b *echoBackend) session(t *testing.T) *echoSession {
	t.Helper()
	select {
	case s := <-b.opened:
		return s
	case <-time.After(testTimeout):
		t.Fatal("no backend session")
		return nil
	}
}

type echoSession struct {
	toClient chan []byte

	mu       sync.Mutex
	received []int
	echoes   int

	closeOnce sync.Once
	closed    chan struct{}
}

func (s *echoSession) WritePacket(pkt []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.received = append(s.received, len(pkt))
	if len(pkt) < ipv6.HeaderLen || pkt[6] != 58 {
		return nil
	}
	m, err := icmp.ParseMessage(58, pkt[ipv6.HeaderLen:])
	if err != nil || m.Type != ipv6.ICMPTypeEchoRequest {
		return nil
	}
	s.echoes++
	src, dst := netip.AddrFrom16([16]byte(pkt[24:40])), netip.AddrFrom16([16]byte(pkt[8:24]))
	reply, err := buildICMPv6(src, dst, &icmp.Message{Type: ipv6.ICMPTypeEchoReply, Body: m.Body})
	if err != nil {
		return err
	}
	select {
	case s.toClient <- reply:
	default:
	}
	return nil
}

func (s *echoSession) ReadPacket(ctx context.Context, buf []byte) (int, error) {
	select {
	case pkt := <-s.toClient:
		return copy(buf, pkt), nil
	case <-s.closed:
		return 0, net.ErrClosed
	case <-ctx.Done():
		return 0, ctx.Err()
	}
}

func (s *echoSession) Close() error {
	s.closeOnce.Do(func() { close(s.closed) })
	return nil
}

func (s *echoSession) requests() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.echoes
}

func (s *echoSession) sizes() []int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]int(nil), s.received...)
}

// waitClosed waits for the server to close the session after the probe
// disconnects.
func (s *echoSession) waitClosed(t *testing.T) {
	t.Helper()
	select {
	case <-s.closed:
	case <-time.After(testTimeout):
		t.Fatal("backend session was not closed after the probe disconnected")
	}
}

// buildICMPv6 returns an IPv6 packet with hop limit 64 carrying msg.
func buildICMPv6(src, dst netip.Addr, msg *icmp.Message) ([]byte, error) {
	s, d := src.As16(), dst.As16()
	body, err := msg.Marshal(icmp.IPv6PseudoHeader(s[:], d[:]))
	if err != nil {
		return nil, err
	}
	pkt := make([]byte, ipv6.HeaderLen, ipv6.HeaderLen+len(body))
	pkt[0] = 6 << 4
	binary.BigEndian.PutUint16(pkt[4:6], uint16(len(body)))
	pkt[6], pkt[7] = 58, 64
	copy(pkt[8:24], s[:])
	copy(pkt[24:40], d[:])
	return append(pkt, body...), nil
}
