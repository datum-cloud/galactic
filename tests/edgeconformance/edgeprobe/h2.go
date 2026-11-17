// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"

	"github.com/quic-go/quic-go/quicvarint"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// Capsule types from RFC 9297 and RFC 9484. The probe frames them itself
// rather than share the server's codec, so it stays an independent client
// of the server under test.
const (
	capsuleDatagram      = 0x00
	capsuleAddressAssign = 0x01

	// maxCapsule bounds a capsule value the probe reads into memory: an
	// IPv6 packet of the largest size a 16-bit payload length allows, plus
	// its context ID. Larger capsules are skipped.
	maxCapsule = 65535 + 8
)

// dialH2 opens the request as an HTTP/2 Extended CONNECT (RFC 8441) for
// connect-ip on a TLS connection that negotiated ALPN h2. Packets travel as
// DATAGRAM capsules on the request stream (RFC 9297). The probe speaks the
// frames itself because net/http's client rejects the :protocol
// pseudo-header from Go 1.27.
func dialH2(ctx context.Context, r cipRequest) (cipTunnel, cipResponse, error) {
	cfg := r.tls.Clone()
	cfg.NextProtos = []string{http2.NextProtoTLS}
	nc, err := (&tls.Dialer{Config: cfg}).DialContext(ctx, "tcp", r.server)
	if err != nil {
		return nil, cipResponse{}, fmt.Errorf("dial %s: %w", r.server, err)
	}
	conn := nc.(*tls.Conn)
	rsp := cipResponse{Proto: conn.ConnectionState().NegotiatedProtocol}
	if rsp.Proto != http2.NextProtoTLS {
		_ = conn.Close()
		return nil, rsp, fmt.Errorf("ALPN %q, want %s", rsp.Proto, http2.NextProtoTLS)
	}
	target, err := r.template.Expand(nil)
	if err != nil {
		_ = conn.Close()
		return nil, rsp, err
	}
	u, err := url.Parse(target)
	if err != nil {
		_ = conn.Close()
		return nil, rsp, err
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	s, err := openH2Stream(conn, u, r.header)
	if err != nil {
		_ = conn.Close()
		if ctx.Err() != nil {
			return nil, rsp, ctx.Err()
		}
		return nil, rsp, err
	}
	rsp.Status = s.status
	if s.status != http.StatusOK {
		_ = conn.Close()
		return nil, rsp, fmt.Errorf("status %d", s.status)
	}
	return &h2Tunnel{s: s, cr: newCapsuleReader(s.body)}, rsp, nil
}

const (
	h2StreamID       = 1
	h2DefaultWindow  = 65535
	h2DefaultMaxData = 16384
	h2ReadWindow     = 1 << 20
)

// h2Stream is one client-initiated HTTP/2 stream on a connection of its own.
type h2Stream struct {
	conn   net.Conn
	fr     *http2.Framer
	status int
	body   *io.PipeReader

	wmu sync.Mutex

	mu         sync.Mutex
	cond       *sync.Cond
	connWindow int64
	strWindow  int64
	initWindow int64
	maxData    int64
	err        error
}

func openH2Stream(conn net.Conn, u *url.URL, header http.Header) (*h2Stream, error) {
	fr := http2.NewFramer(conn, conn)
	fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	if _, err := io.WriteString(conn, http2.ClientPreface); err != nil {
		return nil, err
	}
	if err := fr.WriteSettings(
		http2.Setting{ID: http2.SettingEnablePush, Val: 0},
		http2.Setting{ID: http2.SettingInitialWindowSize, Val: h2ReadWindow},
	); err != nil {
		return nil, err
	}
	if err := fr.WriteWindowUpdate(0, h2ReadWindow-h2DefaultWindow); err != nil {
		return nil, err
	}
	s := &h2Stream{
		conn:       conn,
		fr:         fr,
		connWindow: h2DefaultWindow,
		initWindow: h2DefaultWindow,
		strWindow:  h2DefaultWindow,
		maxData:    h2DefaultMaxData,
	}
	s.cond = sync.NewCond(&s.mu)
	extended := false
	for !extended {
		f, err := fr.ReadFrame()
		if err != nil {
			return nil, err
		}
		sf, ok := f.(*http2.SettingsFrame)
		if !ok || sf.IsAck() {
			continue
		}
		if v, ok := sf.Value(http2.SettingEnableConnectProtocol); ok && v == 1 {
			extended = true
		}
		s.applySettings(sf)
		if err := s.write(func() error { return fr.WriteSettingsAck() }); err != nil {
			return nil, err
		}
		if !extended {
			return nil, errors.New("server does not offer Extended CONNECT")
		}
	}
	var block bytes.Buffer
	enc := hpack.NewEncoder(&block)
	field := func(k, v string) error { return enc.WriteField(hpack.HeaderField{Name: k, Value: v}) }
	path := u.RequestURI()
	for _, kv := range [][2]string{
		{":method", http.MethodConnect},
		{":scheme", "https"},
		{":authority", u.Host},
		{":path", path},
		{":protocol", "connect-ip"},
	} {
		if err := field(kv[0], kv[1]); err != nil {
			return nil, err
		}
	}
	for k, vv := range header {
		for _, v := range vv {
			if err := field(strings.ToLower(k), v); err != nil {
				return nil, err
			}
		}
	}
	if err := field("capsule-protocol", "?1"); err != nil {
		return nil, err
	}
	if err := s.write(func() error {
		return fr.WriteHeaders(http2.HeadersFrameParam{
			StreamID:      h2StreamID,
			BlockFragment: block.Bytes(),
			EndHeaders:    true,
		})
	}); err != nil {
		return nil, err
	}
	pr, pw := io.Pipe()
	s.body = pr
	statusc := make(chan int, 1)
	go s.readLoop(pw, statusc)
	status, ok := <-statusc
	if !ok {
		s.mu.Lock()
		defer s.mu.Unlock()
		return nil, s.err
	}
	s.status = status
	return s, nil
}

func (s *h2Stream) write(f func() error) error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	return f()
}

func (s *h2Stream) applySettings(sf *http2.SettingsFrame) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = sf.ForeachSetting(func(st http2.Setting) error {
		switch st.ID {
		case http2.SettingInitialWindowSize:
			s.strWindow += int64(st.Val) - s.initWindow
			s.initWindow = int64(st.Val)
		case http2.SettingMaxFrameSize:
			s.maxData = int64(st.Val)
		}
		return nil
	})
	s.cond.Broadcast()
}

func (s *h2Stream) fail(err error) {
	s.mu.Lock()
	if s.err == nil {
		s.err = err
	}
	s.cond.Broadcast()
	s.mu.Unlock()
}

// readLoop delivers the response status once, then the response body until
// the stream or the connection ends.
func (s *h2Stream) readLoop(pw *io.PipeWriter, statusc chan<- int) {
	var unacked uint32
	sentStatus := false
	finish := func(err error) {
		s.fail(err)
		if !sentStatus {
			close(statusc)
		}
		_ = pw.CloseWithError(err)
	}
	for {
		f, err := s.fr.ReadFrame()
		if err != nil {
			finish(err)
			return
		}
		switch f := f.(type) {
		case *http2.MetaHeadersFrame:
			if f.StreamID != h2StreamID {
				continue
			}
			if !sentStatus {
				code, err := strconv.Atoi(f.PseudoValue("status"))
				if err != nil {
					finish(fmt.Errorf("response has no :status: %w", err))
					return
				}
				sentStatus = true
				statusc <- code
				if code != http.StatusOK {
					return
				}
			}
			if f.StreamEnded() {
				finish(io.EOF)
				return
			}
		case *http2.DataFrame:
			if f.StreamID != h2StreamID {
				continue
			}
			if data := f.Data(); len(data) > 0 {
				if _, err := pw.Write(data); err != nil {
					s.fail(err)
					return
				}
				unacked += uint32(len(data))
				if unacked >= h2ReadWindow/4 {
					n := unacked
					unacked = 0
					if err := s.write(func() error {
						if err := s.fr.WriteWindowUpdate(0, n); err != nil {
							return err
						}
						return s.fr.WriteWindowUpdate(h2StreamID, n)
					}); err != nil {
						finish(err)
						return
					}
				}
			}
			if f.StreamEnded() {
				finish(io.EOF)
				return
			}
		case *http2.WindowUpdateFrame:
			s.mu.Lock()
			switch f.StreamID {
			case 0:
				s.connWindow += int64(f.Increment)
			case h2StreamID:
				s.strWindow += int64(f.Increment)
			}
			s.cond.Broadcast()
			s.mu.Unlock()
		case *http2.SettingsFrame:
			if f.IsAck() {
				continue
			}
			s.applySettings(f)
			if err := s.write(func() error { return s.fr.WriteSettingsAck() }); err != nil {
				finish(err)
				return
			}
		case *http2.PingFrame:
			if f.IsAck() {
				continue
			}
			if err := s.write(func() error { return s.fr.WritePing(true, f.Data) }); err != nil {
				finish(err)
				return
			}
		case *http2.RSTStreamFrame:
			if f.StreamID == h2StreamID {
				finish(fmt.Errorf("stream reset: %v", f.ErrCode))
				return
			}
		case *http2.GoAwayFrame:
			finish(fmt.Errorf("GOAWAY: %v", f.ErrCode))
			return
		}
	}
}

// send writes b as DATA frames, waiting for flow-control credit.
func (s *h2Stream) send(b []byte) error {
	for len(b) > 0 {
		s.mu.Lock()
		for s.err == nil && (s.connWindow <= 0 || s.strWindow <= 0) {
			s.cond.Wait()
		}
		if s.err != nil {
			err := s.err
			s.mu.Unlock()
			return err
		}
		n := min(int64(len(b)), s.connWindow, s.strWindow, s.maxData)
		s.connWindow -= n
		s.strWindow -= n
		s.mu.Unlock()
		chunk := b[:n]
		b = b[n:]
		if err := s.write(func() error { return s.fr.WriteData(h2StreamID, false, chunk) }); err != nil {
			return err
		}
	}
	return nil
}

// h2Tunnel carries packets as capsules on one HTTP/2 stream: the request
// body toward the server, the response body back.
type h2Tunnel struct {
	s  *h2Stream
	cr *capsuleReader
	// wbuf is only used by WritePacket.
	wbuf []byte
}

// assigned reads capsules until the first ADDRESS_ASSIGN and returns its
// prefixes. A packet that arrives before it is dropped.
func (t *h2Tunnel) assigned(ctx context.Context) ([]netip.Prefix, error) {
	stop := context.AfterFunc(ctx, func() { _ = t.s.body.Close() })
	defer stop()
	for {
		typ, v, err := t.cr.next()
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, err
		}
		if typ == capsuleAddressAssign {
			return parseAddressAssign(v)
		}
	}
}

// ReadPacket returns the next IP packet in context 0 and skips every other
// capsule, including later ADDRESS_ASSIGN and ROUTE_ADVERTISEMENT.
func (t *h2Tunnel) ReadPacket(b []byte) (int, error) {
	for {
		typ, v, err := t.cr.next()
		if err != nil {
			return 0, err
		}
		if typ != capsuleDatagram || v == nil {
			continue
		}
		id, n, err := quicvarint.Parse(v)
		if err != nil {
			return 0, errors.New("DATAGRAM capsule has no context ID")
		}
		if id == 0 {
			return copy(b, v[n:]), nil
		}
	}
}

func (t *h2Tunnel) WritePacket(pkt []byte) error {
	b := quicvarint.Append(t.wbuf[:0], capsuleDatagram)
	b = quicvarint.Append(b, uint64(1+len(pkt)))
	b = quicvarint.Append(b, 0)
	t.wbuf = append(b, pkt...)
	err := t.s.send(t.wbuf)
	return err
}

// Close ends the request body, cancels the stream and closes the
// connection, which ends a ReadPacket in progress.
func (t *h2Tunnel) Close() error {
	_ = t.s.write(func() error { return t.s.fr.WriteData(h2StreamID, true, nil) })
	_ = t.s.body.Close()
	return t.s.conn.Close()
}

// capsuleReader parses capsules from a stream. A capsule may be split across
// reads or share one with others.
type capsuleReader struct {
	r   *bufio.Reader
	buf []byte
}

func newCapsuleReader(r io.Reader) *capsuleReader {
	return &capsuleReader{r: bufio.NewReader(r)}
}

// next returns the type and value of the next capsule. The value is only
// valid until the next call, and is nil for a capsule over maxCapsule, which
// is discarded. A capsule cut off by the end of the stream returns
// io.ErrUnexpectedEOF.
func (c *capsuleReader) next() (uint64, []byte, error) {
	typ, err := quicvarint.Read(c.r)
	if err != nil {
		return 0, nil, err
	}
	n, err := quicvarint.Read(c.r)
	if err != nil {
		return 0, nil, unexpectedEOF(err)
	}
	if n > maxCapsule {
		if _, err := io.CopyN(io.Discard, c.r, int64(n)); err != nil {
			return 0, nil, unexpectedEOF(err)
		}
		return typ, nil, nil
	}
	if uint64(cap(c.buf)) < n {
		c.buf = make([]byte, n)
	}
	v := c.buf[:n]
	if _, err := io.ReadFull(c.r, v); err != nil {
		return 0, nil, unexpectedEOF(err)
	}
	return typ, v, nil
}

func unexpectedEOF(err error) error {
	if errors.Is(err, io.EOF) {
		return io.ErrUnexpectedEOF
	}
	return err
}

// parseAddressAssign returns the prefixes of an ADDRESS_ASSIGN capsule's
// Assigned Address entries (RFC 9484, Section 4.7.2): a request ID, an IP
// version, an address and a prefix length.
func parseAddressAssign(v []byte) ([]netip.Prefix, error) {
	var out []netip.Prefix
	r := bytes.NewReader(v)
	for r.Len() > 0 {
		if _, err := quicvarint.Read(r); err != nil {
			return nil, fmt.Errorf("ADDRESS_ASSIGN: %w", unexpectedEOF(err))
		}
		version, err := r.ReadByte()
		if err != nil {
			return nil, fmt.Errorf("ADDRESS_ASSIGN: %w", unexpectedEOF(err))
		}
		var raw []byte
		switch version {
		case 4:
			raw = make([]byte, 4)
		case 6:
			raw = make([]byte, 16)
		default:
			return nil, fmt.Errorf("ADDRESS_ASSIGN has unknown IP version %d", version)
		}
		if _, err := io.ReadFull(r, raw); err != nil {
			return nil, fmt.Errorf("ADDRESS_ASSIGN: %w", unexpectedEOF(err))
		}
		bits, err := r.ReadByte()
		if err != nil {
			return nil, fmt.Errorf("ADDRESS_ASSIGN: %w", unexpectedEOF(err))
		}
		addr, _ := netip.AddrFromSlice(raw)
		p := netip.PrefixFrom(addr, int(bits))
		if !p.IsValid() {
			return nil, fmt.Errorf("ADDRESS_ASSIGN prefix length %d is too long", bits)
		}
		out = append(out, p)
	}
	return out, nil
}
