// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package connectipinterop

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"go.datum.net/galactic/internal/edge/connectip"
)

// The raw clients drive the negative checks that need control over framing:
// several requests on one connection, malformed capsules and cancellation of
// one request. Interoperability itself is proven by Xray, not by these.

// rawConn is one HTTP/3 or HTTP/2 connection to the server's namespace.
type rawConn interface {
	open(t *testing.T, c connector) *rawRequest
}

// rawRequest is one accepted CONNECT-IP request.
type rawRequest struct {
	prefix netip.Prefix
	// sendDatagram, recvDatagram exchange context-0 IP packets.
	sendDatagram func(pkt []byte) error
	recvDatagram func(ctx context.Context) ([]byte, error)
	// writeStream writes raw bytes on the request stream.
	writeStream func(b []byte) error
	// closeWrite ends the client's side of the request stream.
	closeWrite func() error
	cancel     func()
	// ended closes once the server ends or resets the request stream.
	ended chan struct{}
}

func (h *harness) tlsClient(proto string) *tls.Config {
	pemBytes, err := os.ReadFile(h.caFile)
	if err != nil {
		panic(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(pemBytes)
	return &tls.Config{ServerName: serverName, RootCAs: roots, NextProtos: []string{proto}, MinVersion: tls.VersionTLS13}
}

func requestURL() string { return "https://" + serverName + connectip.TemplatePath }

// readSetup reads capsules until the request's ADDRESS_ASSIGN and returns
// the assigned prefix; it keeps draining capsules until the stream ends.
func readSetup(t *testing.T, body io.Reader, ended chan struct{}) netip.Prefix {
	t.Helper()
	assigned := make(chan netip.Prefix, 1)
	go func() {
		defer close(ended)
		cr := newCapsuleReader(body)
		for {
			c, err := cr.next()
			if err != nil {
				return
			}
			if c.typ != capsuleAddressAssign {
				continue
			}
			entries, err := parseAddressEntries(c.value)
			if err == nil && len(entries) > 0 {
				select {
				case assigned <- entries[0].prefix:
				default:
				}
			}
		}
	}()
	select {
	case p := <-assigned:
		return p
	case <-ended:
		t.Fatal("request ended before ADDRESS_ASSIGN")
	case <-time.After(10 * time.Second):
		t.Fatal("no ADDRESS_ASSIGN")
	}
	return netip.Prefix{}
}

// h3Conn is one QUIC connection.
type h3Conn struct {
	cc *http3.ClientConn
}

func (h *harness) dialH3(t *testing.T) rawConn {
	t.Helper()
	var pc net.PacketConn
	if err := h.client.Do(func(ns.NetNS) error {
		var err error
		pc, err = (&net.ListenConfig{}).ListenPacket(t.Context(), "udp6", "[::]:0")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	qconn, err := quic.Dial(ctx, pc, net.UDPAddrFromAddrPort(netip.AddrPortFrom(serverAddr, 443)),
		h.tlsClient(http3.NextProtoH3),
		&quic.Config{EnableDatagrams: true, InitialPacketSize: connectip.DefaultInitialPacketSize})
	if err != nil {
		t.Fatalf("QUIC dial: %v", err)
	}
	t.Cleanup(func() { _ = qconn.CloseWithError(0, ""); _ = pc.Close() })
	cc := (&http3.Transport{EnableDatagrams: true}).NewClientConn(qconn)
	select {
	case <-cc.ReceivedSettings():
	case <-ctx.Done():
		t.Fatal("no HTTP/3 SETTINGS")
	}
	if s := cc.Settings(); !s.EnableExtendedConnect || !s.EnableDatagrams {
		t.Fatalf("server SETTINGS: extended CONNECT %v, datagrams %v", s.EnableExtendedConnect, s.EnableDatagrams)
	}
	return &h3Conn{cc: cc}
}

func (c *h3Conn) open(t *testing.T, conn connector) *rawRequest {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	str, err := c.cc.OpenRequestStream(ctx)
	if err != nil {
		t.Fatalf("open request stream: %v", err)
	}
	u, _ := url.Parse(requestURL())
	req := (&http.Request{
		Method: http.MethodConnect, Proto: protocolConnectIP, URL: u, Host: serverName, Header: http.Header{},
	}).WithContext(ctx)
	req.Header.Set("Capsule-Protocol", "?1")
	req.Header.Set("Authorization", "Bearer "+conn.token)
	req.Header.Set(connectip.VPCHeader, vpcName)
	if err := str.SendRequestHeader(req); err != nil {
		t.Fatalf("send request: %v", err)
	}
	rsp, err := str.ReadResponse()
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if rsp.StatusCode != http.StatusOK {
		t.Fatalf("status %d, want 200", rsp.StatusCode)
	}
	r := &rawRequest{ended: make(chan struct{})}
	r.prefix = readSetup(t, str, r.ended)
	r.sendDatagram = func(pkt []byte) error { return str.SendDatagram(append([]byte{0}, pkt...)) }
	r.recvDatagram = func(ctx context.Context) ([]byte, error) {
		for {
			d, err := str.ReceiveDatagram(ctx)
			if err != nil {
				return nil, err
			}
			id, n, err := quicvarint.Parse(d)
			if err == nil && id == 0 {
				return d[n:], nil
			}
		}
	}
	r.writeStream = func(b []byte) error { _, err := str.Write(b); return err }
	r.closeWrite = str.Close
	r.cancel = func() {
		str.CancelRead(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
		str.CancelWrite(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
	}
	return r
}

// h2Conn is one TLS connection speaking HTTP/2 through x/net/http2's framer;
// net/http's client refuses the :protocol pseudo-header Extended CONNECT needs.
type h2Conn struct {
	conn   *tls.Conn
	fr     *http2.Framer
	wmu    sync.Mutex
	hbuf   bytes.Buffer
	henc   *hpack.Encoder
	mu     sync.Mutex
	next   uint32
	ext    chan struct{}
	stream map[uint32]*h2Stream
}

type h2Stream struct {
	headers chan []hpack.HeaderField
	body    *io.PipeWriter
	once    sync.Once
}

func (s *h2Stream) end(err error) {
	s.once.Do(func() { _ = s.body.CloseWithError(err) })
}

func (h *harness) dialH2(t *testing.T) rawConn {
	t.Helper()
	var tcp net.Conn
	if err := h.client.Do(func(ns.NetNS) error {
		var err error
		d := net.Dialer{Timeout: 10 * time.Second}
		tcp, err = d.DialContext(t.Context(), "tcp6", net.JoinHostPort(serverAddr.String(), "443"))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	conn := tls.Client(tcp, h.tlsClient("h2"))
	if err := conn.HandshakeContext(t.Context()); err != nil {
		t.Fatalf("TLS handshake: %v", err)
	}
	if p := conn.ConnectionState().NegotiatedProtocol; p != "h2" {
		t.Fatalf("ALPN %q, want h2", p)
	}
	t.Cleanup(func() { _ = conn.Close() })
	c := &h2Conn{
		conn: conn, fr: http2.NewFramer(conn, conn), next: 1,
		ext: make(chan struct{}), stream: map[uint32]*h2Stream{},
	}
	c.fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	c.henc = hpack.NewEncoder(&c.hbuf)
	if _, err := io.WriteString(conn, http2.ClientPreface); err != nil {
		t.Fatal(err)
	}
	if err := c.fr.WriteSettings(); err != nil {
		t.Fatal(err)
	}
	// Open the connection window far enough that flow control never limits
	// these small exchanges.
	if err := c.fr.WriteWindowUpdate(0, 1<<30); err != nil {
		t.Fatal(err)
	}
	go c.readLoop()
	select {
	case <-c.ext:
	case <-time.After(10 * time.Second):
		t.Fatal("server did not offer SETTINGS_ENABLE_CONNECT_PROTOCOL")
	}
	return c
}

func (c *h2Conn) readLoop() {
	defer func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		for _, s := range c.stream {
			s.end(io.ErrUnexpectedEOF)
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
			if v, ok := f.Value(http2.SettingEnableConnectProtocol); ok && v == 1 {
				select {
				case <-c.ext:
				default:
					close(c.ext)
				}
			}
			c.wmu.Lock()
			_ = c.fr.WriteSettingsAck()
			c.wmu.Unlock()
		case *http2.PingFrame:
			if !f.IsAck() {
				c.wmu.Lock()
				_ = c.fr.WritePing(true, f.Data)
				c.wmu.Unlock()
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
				_, _ = s.body.Write(f.Data())
				c.wmu.Lock()
				_ = c.fr.WriteWindowUpdate(f.StreamID, uint32(n))
				c.wmu.Unlock()
			}
			if f.StreamEnded() {
				s.end(io.EOF)
			}
		case *http2.RSTStreamFrame:
			if s := c.get(f.StreamID); s != nil {
				s.end(fmt.Errorf("stream reset: %v", f.ErrCode))
			}
		}
	}
}

func (c *h2Conn) get(id uint32) *h2Stream {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.stream[id]
}

func (c *h2Conn) open(t *testing.T, conn connector) *rawRequest {
	t.Helper()
	pr, pw := io.Pipe()
	s := &h2Stream{headers: make(chan []hpack.HeaderField, 1), body: pw}
	c.mu.Lock()
	id := c.next
	c.next += 2
	c.stream[id] = s
	c.mu.Unlock()

	c.wmu.Lock()
	c.hbuf.Reset()
	for _, f := range [][2]string{
		{":method", "CONNECT"}, {":protocol", protocolConnectIP}, {":scheme", "https"},
		{":authority", serverName}, {":path", connectip.TemplatePath},
		{"capsule-protocol", "?1"}, {"authorization", "Bearer " + conn.token},
		{"galactic-vpc", vpcName},
	} {
		_ = c.henc.WriteField(hpack.HeaderField{Name: f[0], Value: f[1]})
	}
	err := c.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: id, BlockFragment: c.hbuf.Bytes(), EndHeaders: true})
	c.wmu.Unlock()
	if err != nil {
		t.Fatalf("write HEADERS: %v", err)
	}
	select {
	case fields := <-s.headers:
		for _, f := range fields {
			if f.Name == ":status" && f.Value != "200" {
				t.Fatalf("status %s, want 200", f.Value)
			}
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no response HEADERS")
	}
	write := func(b []byte) error {
		c.wmu.Lock()
		defer c.wmu.Unlock()
		for len(b) > 0 {
			n := min(len(b), 16384)
			if err := c.fr.WriteData(id, false, b[:n]); err != nil {
				return err
			}
			b = b[n:]
		}
		return nil
	}
	r := &rawRequest{ended: make(chan struct{})}
	datagrams := make(chan []byte, 64)
	tee, tw := io.Pipe()
	go func() {
		// Split the stream: DATAGRAM capsules go to recvDatagram, the
		// rest to readSetup, which also reports the stream's end.
		defer func() { _ = tw.Close() }()
		cr := newCapsuleReader(pr)
		for {
			c, err := cr.next()
			if err != nil {
				return
			}
			if c.typ == capsuleDatagram && len(c.value) > 0 && c.value[0] == 0 {
				select {
				case datagrams <- bytes.Clone(c.value[1:]):
				default:
				}
				continue
			}
			if _, err := tw.Write(appendCapsule(nil, c.typ, c.value)); err != nil {
				return
			}
		}
	}()
	r.prefix = readSetup(t, tee, r.ended)
	r.sendDatagram = func(pkt []byte) error { return write(appendDatagram(nil, pkt)) }
	r.recvDatagram = func(ctx context.Context) ([]byte, error) {
		select {
		case d := <-datagrams:
			return d, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	r.writeStream = write
	r.closeWrite = func() error {
		c.wmu.Lock()
		defer c.wmu.Unlock()
		return c.fr.WriteData(id, true, nil)
	}
	r.cancel = func() {
		c.wmu.Lock()
		_ = c.fr.WriteRSTStream(id, http2.ErrCodeCancel)
		c.wmu.Unlock()
		s.end(errors.New("cancelled"))
	}
	return r
}

// outsideRoute is an address outside every route advertised to connectors.
var outsideRoute = netip.MustParseAddr("fd00:973:c::1")

// udpEcho builds an IPv6 UDP packet from src to the echo server carrying
// payload.
func udpEcho(src netip.Addr, srcPort uint16, payload []byte) []byte {
	pkt := udpPacket(src, echoAddr, 64, payload)
	binary.BigEndian.PutUint16(pkt[40:42], srcPort)
	binary.BigEndian.PutUint16(pkt[46:48], udpChecksum(pkt))
	return pkt
}

// udpPacket builds an IPv6 UDP packet from src to dst's echo port with the
// given hop limit.
func udpPacket(src, dst netip.Addr, hopLimit byte, payload []byte) []byte {
	pkt := make([]byte, 48+len(payload))
	pkt[0] = 6 << 4
	binary.BigEndian.PutUint16(pkt[4:6], uint16(8+len(payload)))
	pkt[6] = 17
	pkt[7] = hopLimit
	s, d := src.As16(), dst.As16()
	copy(pkt[8:24], s[:])
	copy(pkt[24:40], d[:])
	binary.BigEndian.PutUint16(pkt[40:42], 40000)
	binary.BigEndian.PutUint16(pkt[42:44], echoPort)
	binary.BigEndian.PutUint16(pkt[44:46], uint16(8+len(payload)))
	copy(pkt[48:], payload)
	binary.BigEndian.PutUint16(pkt[46:48], udpChecksum(pkt))
	return pkt
}

func udpChecksum(pkt []byte) uint16 {
	var sum uint32
	add := func(b []byte) {
		for i := 0; i+1 < len(b); i += 2 {
			sum += uint32(b[i])<<8 | uint32(b[i+1])
		}
		if len(b)%2 == 1 {
			sum += uint32(b[len(b)-1]) << 8
		}
	}
	add(pkt[8:40])
	sum += uint32(len(pkt) - 40)
	sum += 17
	add(pkt[40:46])
	add(pkt[48:])
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	if c := ^uint16(sum); c != 0 {
		return c
	}
	return 0xffff
}

// roundTrip sends one innerPacketSize echo request and waits for the reply,
// returning its size.
func (r *rawRequest) roundTrip(t *testing.T, seq byte) int {
	t.Helper()
	payload := bytes.Repeat([]byte{seq}, echoPayload)
	src := r.prefix.Addr().Next()
	if err := r.sendDatagram(udpEcho(src, 40000+uint16(seq), payload)); err != nil {
		t.Fatalf("send: %v", err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	for {
		pkt, err := r.recvDatagram(ctx)
		if err != nil {
			t.Fatalf("no echo reply for %d: %v", seq, err)
		}
		if len(pkt) >= 48 && pkt[6] == 17 && bytes.Equal(pkt[48:], payload) {
			return len(pkt)
		}
	}
}
