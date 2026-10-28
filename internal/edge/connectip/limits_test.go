// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package connectip

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

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

	// The server may refuse the extra connection before or after the
	// client's handshake completes.
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

	// The connection under the cap still serves requests.
	open(t, cc, env.newRequest(t, authHeaders(tokenBob, vpcGreen)))
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
