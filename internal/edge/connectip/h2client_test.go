// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package connectip

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go/quicvarint"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// TestMain re-runs the test binary with GODEBUG=http2xconnect=1 when it is
// missing: net/http reads it once at init, and without it the HTTP/2 server
// does not offer Extended CONNECT.
func TestMain(m *testing.M) {
	if ExtendedConnectEnabled() {
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

// h2Client is one TLS connection speaking HTTP/2 through x/net/http2's
// framer: net/http's client refuses the :protocol pseudo-header that
// Extended CONNECT needs.
type h2Client struct {
	conn     *tls.Conn
	fr       *http2.Framer
	wmu      sync.Mutex
	hbuf     bytes.Buffer
	henc     *hpack.Encoder
	mu       sync.Mutex
	next     uint32
	settings chan map[http2.SettingID]uint32
	streams  map[uint32]*h2Stream
	done     chan struct{}
}

// h2Stream is one client request. Its response body is read from body;
// while paused, the client grants the stream no more flow-control window.
type h2Stream struct {
	c       *h2Client
	id      uint32
	headers chan []hpack.HeaderField
	body    *io.PipeReader
	pw      *io.PipeWriter
	once    sync.Once
	paused  bool
	// queue carries DATA payloads in order to pw. Only the read loop sends
	// on it and closes it; queueClosed, guarded by c.mu, records that.
	queue       chan []byte
	queueClosed bool
	// cr reads capsules from body.
	cr *capsuleReader
}

func (s *h2Stream) end(err error) { s.once.Do(func() { _ = s.pw.CloseWithError(err) }) }

// dialH2 opens an HTTP/2 connection to the server's TCP listener and waits
// for its SETTINGS.
func (e *testEnv) dialH2(t *testing.T) *h2Client {
	t.Helper()
	c, err := e.tryDialH2(t)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func (e *testEnv) tryDialH2(t *testing.T) (*h2Client, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), testTimeout)
	defer cancel()
	c, err := e.dialH2From(ctx, nil)
	if c != nil {
		t.Cleanup(func() { _ = c.conn.Close() })
	}
	return c, err
}

// dialH2From is tryDialH2 from local, or any address when local is nil. The
// caller closes the connection, which it gets back with any error after the
// TLS handshake.
func (e *testEnv) dialH2From(ctx context.Context, local net.IP) (*h2Client, error) {
	cfg := e.clientTLS()
	cfg.NextProtos = []string{"h2"}
	d := &tls.Dialer{Config: cfg}
	if local != nil {
		d.NetDialer = &net.Dialer{LocalAddr: &net.TCPAddr{IP: local}}
	}
	conn, err := d.DialContext(ctx, "tcp", e.tcpAddr)
	if err != nil {
		return nil, fmt.Errorf("dial TLS: %w", err)
	}
	tc := conn.(*tls.Conn)
	if p := tc.ConnectionState().NegotiatedProtocol; p != "h2" {
		_ = tc.Close()
		return nil, fmt.Errorf("ALPN %q, want h2", p)
	}
	c := &h2Client{
		conn: tc, fr: http2.NewFramer(tc, tc), next: 1,
		settings: make(chan map[http2.SettingID]uint32, 1), streams: map[uint32]*h2Stream{},
		done: make(chan struct{}),
	}
	c.fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	c.henc = hpack.NewEncoder(&c.hbuf)
	if _, err := io.WriteString(tc, http2.ClientPreface); err != nil {
		_ = tc.Close()
		return nil, err
	}
	if err := c.fr.WriteSettings(); err != nil {
		_ = tc.Close()
		return nil, err
	}
	// Open the connection window wide, so only stream windows limit the
	// server.
	if err := c.fr.WriteWindowUpdate(0, 1<<30); err != nil {
		_ = tc.Close()
		return nil, err
	}
	go c.readLoop()
	select {
	case s := <-c.settings:
		if s[http2.SettingEnableConnectProtocol] != 1 {
			return nil, errors.New("server did not offer SETTINGS_ENABLE_CONNECT_PROTOCOL")
		}
		c.settings <- s
		return c, nil
	case <-c.done:
		_ = tc.Close()
		return nil, errors.New("connection closed before SETTINGS")
	case <-ctx.Done():
		_ = tc.Close()
		return nil, errors.New("no SETTINGS from the server")
	}
}

func (c *h2Client) readLoop() {
	defer func() {
		close(c.done)
		c.mu.Lock()
		defer c.mu.Unlock()
		for _, s := range c.streams {
			s.end(io.ErrUnexpectedEOF)
			if !s.queueClosed {
				s.queueClosed = true
				close(s.queue)
			}
		}
	}()
	for {
		f, err := c.fr.ReadFrame()
		if err != nil {
			return
		}
		switch f := f.(type) {
		case *http2.SettingsFrame:
			if f.IsAck() {
				continue
			}
			s := map[http2.SettingID]uint32{}
			_ = f.ForeachSetting(func(st http2.Setting) error { s[st.ID] = st.Val; return nil })
			select {
			case c.settings <- s:
			default:
			}
			c.write(func() error { return c.fr.WriteSettingsAck() })
		case *http2.PingFrame:
			if !f.IsAck() {
				c.write(func() error { return c.fr.WritePing(true, f.Data) })
			}
		case *http2.MetaHeadersFrame:
			if s := c.get(f.StreamID); s != nil {
				select {
				case s.headers <- f.Fields:
				default:
				}
				if f.StreamEnded() {
					s.end(io.EOF)
				}
			}
		case *http2.DataFrame:
			s := c.get(f.StreamID)
			if s == nil {
				continue
			}
			if n := len(f.Data()); n > 0 {
				// The queue holds at most one stream window, so the read
				// loop never blocks on a stream nobody reads.
				s.queue <- bytes.Clone(f.Data())
				c.mu.Lock()
				paused := s.paused
				c.mu.Unlock()
				if !paused {
					c.write(func() error { return c.fr.WriteWindowUpdate(f.StreamID, uint32(n)) })
				}
			}
			if f.StreamEnded() {
				c.mu.Lock()
				s.queueClosed = true
				c.mu.Unlock()
				close(s.queue)
			}
		case *http2.RSTStreamFrame:
			if s := c.get(f.StreamID); s != nil {
				s.end(fmt.Errorf("stream reset: %v", f.ErrCode))
			}
		}
	}
}

func (c *h2Client) write(fn func() error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	_ = fn()
}

func (c *h2Client) get(id uint32) *h2Stream {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.streams[id]
}

// request sends an Extended CONNECT for connect-ip with authority and extra
// headers, and returns the stream and its response status.
func (c *h2Client) request(t *testing.T, authority string, headers http.Header) (*h2Stream, int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), testTimeout)
	defer cancel()
	s, status, err := c.tryRequest(ctx, authority, headers)
	if err != nil {
		t.Fatal(err)
	}
	return s, status
}

// tryRequest is request returning an error rather than failing a test.
func (c *h2Client) tryRequest(ctx context.Context, authority string, headers http.Header) (*h2Stream, int, error) {
	pr, pw := io.Pipe()
	s := &h2Stream{c: c, headers: make(chan []hpack.HeaderField, 1), body: pr, pw: pw, queue: make(chan []byte, 1024)}
	s.cr = newCapsuleReader(pr)
	s.cr.readAll = true
	go func() {
		for b := range s.queue {
			if _, err := pw.Write(b); err != nil {
				return
			}
		}
		s.end(io.EOF)
	}()
	c.mu.Lock()
	s.id = c.next
	c.next += 2
	c.streams[s.id] = s
	c.mu.Unlock()

	fields := [][2]string{
		{":method", "CONNECT"}, {":protocol", connectIPProtocol}, {":scheme", "https"},
		{":authority", authority}, {":path", TemplatePath},
	}
	for k, vs := range headers {
		for _, v := range vs {
			fields = append(fields, [2]string{strings.ToLower(k), v})
		}
	}
	var err error
	c.write(func() error {
		c.hbuf.Reset()
		for _, f := range fields {
			_ = c.henc.WriteField(hpack.HeaderField{Name: f[0], Value: f[1]})
		}
		err = c.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: s.id, BlockFragment: c.hbuf.Bytes(), EndHeaders: true})
		return err
	})
	if err != nil {
		return nil, 0, fmt.Errorf("write HEADERS: %w", err)
	}
	select {
	case got := <-s.headers:
		for _, f := range got {
			if f.Name == ":status" {
				var status int
				_, _ = fmt.Sscan(f.Value, &status)
				return s, status, nil
			}
		}
		return nil, 0, errors.New("response has no :status")
	case <-c.done:
		return nil, 0, errors.New("connection closed before response HEADERS")
	case <-ctx.Done():
		return nil, 0, errors.New("no response HEADERS")
	}
}

// open sends a valid request with token and vpc and requires 200 plus the
// ADDRESS_ASSIGN and ROUTE_ADVERTISEMENT that follow it.
func (e *testEnv) openH2(t *testing.T, c *h2Client, token, vpc string) (*h2Stream, netip.Prefix) {
	t.Helper()
	s, status := c.request(t, e.addr, authHeaders(token, vpc))
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	assign := s.nextCapsule(t)
	if assign.typ != capsuleAddressAssign {
		t.Fatalf("first capsule type %#x, want ADDRESS_ASSIGN", assign.typ)
	}
	got := parseAssignments(t, assign.value)
	if len(got) != 1 || got[0].requestID != 0 || got[0].prefix.Bits() != 96 {
		t.Fatalf("assignment = %v, want one unsolicited /96", got)
	}
	if routes := s.nextCapsule(t); routes.typ != capsuleRouteAdvertisement {
		t.Fatalf("second capsule type %#x, want ROUTE_ADVERTISEMENT", routes.typ)
	}
	return s, got[0].prefix
}

// send writes b on the stream as DATA frames of at most chunk bytes.
func (s *h2Stream) send(b []byte, chunk int) error {
	var err error
	s.c.write(func() error {
		for len(b) > 0 && err == nil {
			n := min(len(b), chunk)
			err = s.c.fr.WriteData(s.id, false, b[:n])
			b = b[n:]
		}
		return err
	})
	return err
}

func (s *h2Stream) sendDatagram(t *testing.T, pkt []byte) {
	t.Helper()
	if err := s.send(appendDatagram(nil, pkt), 16384); err != nil {
		t.Fatalf("send datagram: %v", err)
	}
}

// finish ends the client's side of the stream.
func (s *h2Stream) finish() {
	s.c.write(func() error { return s.c.fr.WriteData(s.id, true, nil) })
}

// cancel resets the stream.
func (s *h2Stream) cancel() {
	s.c.write(func() error { return s.c.fr.WriteRSTStream(s.id, http2.ErrCodeCancel) })
	s.end(errors.New("cancelled"))
}

// pause stops granting the stream flow-control window.
func (s *h2Stream) pause() {
	s.c.mu.Lock()
	s.paused = true
	s.c.mu.Unlock()
}

type capsuleResult struct {
	c   capsule
	err error
}

// tryNextCapsule returns the next capsule from the server, or an error when
// the stream ends or nothing arrives within wait.
func (s *h2Stream) tryNextCapsule(wait time.Duration) (capsule, error) {
	ch := make(chan capsuleResult, 1)
	go func() {
		c, err := s.cr.next()
		c.value = bytes.Clone(c.value)
		ch <- capsuleResult{c, err}
	}()
	select {
	case r := <-ch:
		return r.c, r.err
	case <-time.After(wait):
		return capsule{}, errors.New("timed out waiting for a capsule")
	}
}

func (s *h2Stream) nextCapsule(t *testing.T) capsule {
	t.Helper()
	c, err := s.tryNextCapsule(testTimeout)
	if err != nil {
		t.Fatalf("read capsule: %v", err)
	}
	return c
}

// readDatagram returns the next IP packet the server sends in context 0,
// skipping other capsules.
func (s *h2Stream) readDatagram(t *testing.T) []byte {
	t.Helper()
	for {
		c := s.nextCapsule(t)
		if c.typ != capsuleDatagram {
			continue
		}
		id, n, err := quicvarint.Parse(c.value)
		if err != nil || id != 0 {
			t.Fatalf("datagram context %d, err %v", id, err)
		}
		return c.value[n:]
	}
}

// waitEnded waits for the server to end or reset the stream.
func (s *h2Stream) waitEnded(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(testTimeout)
	for time.Now().Before(deadline) {
		if _, err := s.tryNextCapsule(time.Until(deadline)); err != nil {
			return
		}
	}
	t.Fatal("stream did not end")
}

// parseAssignments parses ADDRESS_ASSIGN entries, which share the
// ADDRESS_REQUEST layout but allow request ID 0.
func parseAssignments(t *testing.T, v []byte) []assignment {
	t.Helper()
	out, err := parseAssignmentsErr(v)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func parseAssignmentsErr(v []byte) ([]assignment, error) {
	var out []assignment
	for len(v) > 0 {
		id, n, err := quicvarint.Parse(v)
		if err != nil {
			return nil, fmt.Errorf("parse request ID: %w", err)
		}
		size := 4
		if len(v) > n && v[n] == 6 {
			size = 16
		}
		if len(v) < n+2+size {
			return nil, errors.New("truncated ADDRESS_ASSIGN")
		}
		addr, _ := netip.AddrFromSlice(v[n+1 : n+1+size])
		out = append(out, assignment{requestID: id, prefix: netip.PrefixFrom(addr, int(v[n+1+size]))})
		v = v[n+2+size:]
	}
	return out, nil
}

// pollUntil retries cond until it holds or testTimeout passes.
func pollUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(testTimeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting until %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

var _ net.Conn = (*countedConn)(nil)
