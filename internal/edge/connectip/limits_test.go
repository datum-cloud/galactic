// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package connectip

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	connectip "github.com/quic-go/connect-ip-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// rawRequest sends a CONNECT-IP request with headers over a raw HTTP/3
// request stream, so the test sees every datagram the server sends on it.
func rawRequest(t *testing.T, env *testEnv, headers http.Header) (*http3.RequestStream, *http.Response) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), testTimeout)
	defer cancel()
	cc := (&http3.Transport{EnableDatagrams: true}).NewClientConn(env.dialQUIC(t))
	select {
	case <-cc.ReceivedSettings():
	case <-ctx.Done():
		t.Fatal("no HTTP/3 settings from server")
	}
	rstr, err := cc.OpenRequestStream(t.Context())
	if err != nil {
		t.Fatalf("OpenRequestStream: %v", err)
	}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodConnect, env.template.Raw(), nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Proto = connectIPProtocol
	req.Host = req.URL.Host
	req.Header = headers
	if err := rstr.SendRequestHeader(req); err != nil {
		t.Fatalf("SendRequestHeader: %v", err)
	}
	rsp, err := rstr.ReadResponse()
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	return rstr, rsp
}

func TestNoProbeBeforeAdmission(t *testing.T) {
	env := startServer(t, nil)
	tests := []struct {
		name    string
		headers http.Header
		want    int
	}{
		{"UnknownCredential", authHeaders("test-token-unknown", vpcBlue), http.StatusUnauthorized},
		{"VPCNotGranted", authHeaders(tokenBob, vpcBlue), http.StatusForbidden},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rstr, rsp := rawRequest(t, env, tt.headers)
			if rsp.StatusCode != tt.want {
				t.Fatalf("status = %d, want %d", rsp.StatusCode, tt.want)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 500*time.Millisecond)
			defer cancel()
			if data, err := rstr.ReceiveDatagram(ctx); err == nil {
				t.Fatalf("rejected request received a %d-byte datagram", len(data))
			}
		})
	}
}

// blockingAdmission admits through testAdmission once unblock is closed, and
// counts its calls.
type blockingAdmission struct {
	inner   *testAdmission
	calls   atomic.Int32
	entered chan struct{}
	unblock chan struct{}
}

func newBlockingAdmission() *blockingAdmission {
	return &blockingAdmission{inner: newTestAdmission(), entered: make(chan struct{}, 16), unblock: make(chan struct{})}
}

func (a *blockingAdmission) Admit(ctx context.Context, token, vpc string) (Lease, error) {
	a.calls.Add(1)
	a.entered <- struct{}{}
	select {
	case <-a.unblock:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return a.inner.Admit(ctx, token, vpc)
}

func TestAdmissionLimit(t *testing.T) {
	adm := newBlockingAdmission()
	env := startServer(t, func(c *Config) {
		c.Admission = adm
		c.Limits.MaxAdmissions = 1
	})

	// The first request holds the only admission slot.
	first := make(chan *http.Response, 1)
	go func() {
		cc := newClientConn(t, env.dialQUIC(t))
		_, rsp, _ := cc.Dial(env.newRequest(t, authHeaders(tokenAlice, vpcBlue)))
		first <- rsp
	}()
	select {
	case <-adm.entered:
	case <-time.After(testTimeout):
		t.Fatal("first request never reached Admit")
	}

	_, rsp := rawRequest(t, env, authHeaders(tokenAlice, vpcBlue))
	if rsp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rsp.StatusCode)
	}
	if n := adm.calls.Load(); n != 1 {
		t.Fatalf("Admit ran %d times, want 1", n)
	}

	close(adm.unblock)
	select {
	case rsp := <-first:
		if rsp == nil || rsp.StatusCode != http.StatusOK {
			t.Fatalf("first request response = %v, want 200", rsp)
		}
	case <-time.After(testTimeout):
		t.Fatal("first request was never answered")
	}
	// The released slot admits the next request.
	cc := newClientConn(t, env.dialQUIC(t))
	open(t, cc, env.newRequest(t, authHeaders(tokenAlice, vpcBlue)))
}

func TestSessionLimit(t *testing.T) {
	var calls atomic.Int32
	adm := newTestAdmission()
	env := startServer(t, func(c *Config) {
		c.Admission = admissionFunc(func(ctx context.Context, token, vpc string) (Lease, error) {
			calls.Add(1)
			return adm.Admit(ctx, token, vpc)
		})
		c.Limits.MaxSessions = 1
	})
	cc := newClientConn(t, env.dialQUIC(t))
	s := open(t, cc, env.newRequest(t, authHeaders(tokenAlice, vpcBlue)))
	sess := env.backend.nextOpened(t)

	_, rsp := rawRequest(t, env, authHeaders(tokenBob, vpcGreen))
	if rsp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rsp.StatusCode)
	}
	if n := calls.Load(); n != 1 {
		t.Fatalf("Admit ran %d times, want 1", n)
	}

	_ = s.conn.Close()
	sess.waitClosed(t)
	adm.waitReleased(t, sess.info)
	deadline := time.Now().Add(testTimeout)
	for {
		conn, rsp, err := cc.Dial(env.newRequest(t, authHeaders(tokenBob, vpcGreen)))
		if err == nil {
			accepted(t, conn, rsp, err)
			return
		}
		if rsp == nil || rsp.StatusCode != http.StatusServiceUnavailable || time.Now().After(deadline) {
			t.Fatalf("request after release: response %v, error %v", rsp, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestConnectionLimit(t *testing.T) {
	env := startServer(t, func(c *Config) { c.Limits.MaxConnections = 1 })
	// An accepted request proves the server counted this connection first.
	cc := newClientConn(t, env.dialQUIC(t))
	open(t, cc, env.newRequest(t, authHeaders(tokenAlice, vpcBlue)))

	wantRefusedConnection(t, env)

	// The connection under the cap still serves requests.
	open(t, cc, env.newRequest(t, authHeaders(tokenBob, vpcGreen)))
}

func TestConnectionsPerSourceLimit(t *testing.T) {
	env := startServer(t, func(c *Config) { c.Limits.MaxConnectionsPerSource = 1 })
	qconn := env.dialQUIC(t)
	cc := newClientConn(t, qconn)
	open(t, cc, env.newRequest(t, authHeaders(tokenAlice, vpcBlue)))

	wantRefusedConnection(t, env)

	open(t, cc, env.newRequest(t, authHeaders(tokenBob, vpcGreen)))
	// The source's count drops when its connection closes, so a new
	// connection from it is served.
	_ = qconn.CloseWithError(0, "")
	deadline := time.Now().Add(testTimeout)
	for {
		ctx, cancel := context.WithTimeout(t.Context(), testTimeout)
		cc2, rsp, err := func() (*connectip.Conn, *http.Response, error) {
			defer cancel()
			qconn, err := quic.DialAddr(ctx, env.addr, env.clientTLS(),
				&quic.Config{EnableDatagrams: true, InitialPacketSize: DefaultInitialPacketSize})
			if err != nil {
				return nil, nil, err
			}
			t.Cleanup(func() { _ = qconn.CloseWithError(0, "") })
			return newClientConn(t, qconn).Dial(env.newRequest(t, authHeaders(tokenAlice, vpcBlue)))
		}()
		if err == nil {
			accepted(t, cc2, rsp, err)
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("new connection after the source's last closed: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestUnverifiedSourceNotCounted shows that a handshake that never
// completes, as from a spoofed source address, does not take that source's
// slot.
func TestUnverifiedSourceNotCounted(t *testing.T) {
	env := startServer(t, func(c *Config) { c.Limits.MaxConnectionsPerSource = 1 })
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	stalled := env.clientTLS()
	stalled.VerifyConnection = func(tls.ConnectionState) error {
		<-release
		return errors.New("released")
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()
		if c, err := quic.DialAddr(ctx, env.addr, stalled, &quic.Config{EnableDatagrams: true,
			InitialPacketSize: DefaultInitialPacketSize}); err == nil {
			_ = c.CloseWithError(0, "")
		}
	}()
	deadline := time.Now().Add(testTimeout)
	for env.server.conns.Load() != 1 {
		if time.Now().After(deadline) {
			t.Fatal("the stalled handshake never reached the server")
		}
		time.Sleep(5 * time.Millisecond)
	}
	cc := newClientConn(t, env.dialQUIC(t))
	open(t, cc, env.newRequest(t, authHeaders(tokenAlice, vpcBlue)))
}

// wantRefusedConnection dials env and fails t unless the server closes the
// connection with H3_EXCESSIVE_LOAD. The server may refuse it before or
// after the client's handshake completes.
func wantRefusedConnection(t *testing.T, env *testEnv) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), testTimeout)
	defer cancel()
	extra, err := quic.DialAddr(ctx, env.addr, env.clientTLS(),
		&quic.Config{EnableDatagrams: true, InitialPacketSize: DefaultInitialPacketSize})
	if err == nil {
		t.Cleanup(func() { _ = extra.CloseWithError(0, "") })
		select {
		case <-extra.Context().Done():
		case <-ctx.Done():
			t.Fatal("connection over the cap stayed open")
		}
		err = context.Cause(extra.Context())
	}
	// A close sent during the handshake reaches the client as a transport
	// APPLICATION_ERROR without the HTTP/3 code (RFC 9000, section 10.2.3).
	var appErr *quic.ApplicationError
	var transErr *quic.TransportError
	switch {
	case errors.As(err, &appErr) && appErr.Remote && appErr.ErrorCode == errExcessiveLoad:
	case errors.As(err, &transErr) && transErr.Remote && transErr.ErrorCode == quic.ApplicationErrorErrorCode:
	default:
		t.Fatalf("close cause = %v, want a server close with H3_EXCESSIVE_LOAD", err)
	}
}

func TestCredentialAdmissionLimit(t *testing.T) {
	adm := newBlockingAdmission()
	env := startServer(t, func(c *Config) {
		c.Admission = adm
		c.Limits.MaxAdmissionsPerCredential = 1
	})

	// The first request with tokenAlice holds that credential's only slot.
	first := make(chan *http.Response, 1)
	go func() {
		cc := newClientConn(t, env.dialQUIC(t))
		_, rsp, _ := cc.Dial(env.newRequest(t, authHeaders(tokenAlice, vpcBlue)))
		first <- rsp
	}()
	select {
	case <-adm.entered:
	case <-time.After(testTimeout):
		t.Fatal("first request never reached Admit")
	}

	_, rsp := rawRequest(t, env, authHeaders(tokenAlice, vpcBlue))
	if rsp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rsp.StatusCode)
	}
	if n := adm.calls.Load(); n != 1 {
		t.Fatalf("Admit ran %d times, want 1", n)
	}

	// Another credential still reaches admission.
	second := make(chan *http.Response, 1)
	go func() {
		cc := newClientConn(t, env.dialQUIC(t))
		_, rsp, _ := cc.Dial(env.newRequest(t, authHeaders(tokenBob, vpcGreen)))
		second <- rsp
	}()
	select {
	case <-adm.entered:
	case <-time.After(testTimeout):
		t.Fatal("another credential's request never reached Admit")
	}

	close(adm.unblock)
	for name, ch := range map[string]chan *http.Response{"first": first, "second": second} {
		select {
		case rsp := <-ch:
			if rsp == nil || rsp.StatusCode != http.StatusOK {
				t.Fatalf("%s request response = %v, want 200", name, rsp)
			}
		case <-time.After(testTimeout):
			t.Fatalf("%s request was never answered", name)
		}
	}
}

func TestHeaderLimit(t *testing.T) {
	var calls atomic.Int32
	adm := newTestAdmission()
	env := startServer(t, func(c *Config) {
		c.Admission = admissionFunc(func(ctx context.Context, token, vpc string) (Lease, error) {
			calls.Add(1)
			return adm.Admit(ctx, token, vpc)
		})
	})
	h := authHeaders(tokenAlice, vpcBlue)
	h.Set("X-Padding", strings.Repeat("a", 2*DefaultMaxHeaderBytes))
	cc := newClientConn(t, env.dialQUIC(t))
	if _, rsp, err := cc.Dial(env.newRequest(t, h)); err == nil {
		t.Fatalf("request with a %d-byte header was accepted: %v", 2*DefaultMaxHeaderBytes, rsp.Status)
	}
	if n := calls.Load(); n != 0 {
		t.Fatalf("Admit ran %d times for an oversized header section, want 0", n)
	}
}

func TestHandshakeTimeout(t *testing.T) {
	const timeout = 400 * time.Millisecond
	env := startServer(t, func(c *Config) { c.Limits.HandshakeTimeout = timeout })
	// The client stalls before its Finished, so the server's handshake
	// never completes.
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	tlsConf := env.clientTLS()
	tlsConf.VerifyConnection = func(tls.ConnectionState) error {
		<-release
		return errors.New("released")
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()
		if c, err := quic.DialAddr(ctx, env.addr, tlsConf, &quic.Config{EnableDatagrams: true,
			InitialPacketSize: DefaultInitialPacketSize}); err == nil {
			_ = c.CloseWithError(0, "")
		}
	}()
	waitConns := func(want int64, within time.Duration) {
		start := time.Now()
		for env.server.conns.Load() != want {
			if time.Since(start) > within {
				t.Fatalf("open connections = %d, want %d within %v", env.server.conns.Load(), want, within)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	waitConns(1, testTimeout)
	waitConns(0, 2*timeout)
}

func TestStreamLimit(t *testing.T) {
	env := startServer(t, func(c *Config) { c.Limits.MaxStreamsPerConn = 2 })
	qconn := env.dialQUIC(t)
	cc := newClientConn(t, qconn)
	open(t, cc, env.newRequest(t, authHeaders(tokenAlice, vpcBlue)))
	open(t, cc, env.newRequest(t, authHeaders(tokenBob, vpcGreen)))
	if _, err := qconn.OpenStream(); err == nil {
		t.Fatal("opened a third stream past MaxStreamsPerConn")
	}
}
