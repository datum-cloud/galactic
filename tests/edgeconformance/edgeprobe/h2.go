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
	"net/http"
	"net/netip"

	"github.com/quic-go/quic-go/quicvarint"
	"golang.org/x/net/http2"
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
// DATAGRAM capsules on the request stream (RFC 9297).
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
	// net/http's ClientConn refuses the :protocol pseudo-header Extended
	// CONNECT needs, so the deprecated x/net client stays.
	cc, err := (&http2.Transport{}).NewClientConn(conn) //nolint:staticcheck // see above
	if err != nil {
		_ = conn.Close()
		return nil, rsp, err
	}
	target, err := r.template.Expand(nil)
	if err != nil {
		_ = cc.Close()
		return nil, rsp, err
	}
	pr, pw := io.Pipe()
	req, err := http.NewRequestWithContext(ctx, http.MethodConnect, target, pr)
	if err != nil {
		_ = cc.Close()
		return nil, rsp, err
	}
	req.Header = r.header.Clone()
	// x/net/http2 sends this header as the :protocol pseudo-header and
	// waits for the server's SETTINGS_ENABLE_CONNECT_PROTOCOL.
	req.Header.Set(":protocol", "connect-ip")
	req.Header.Set("Capsule-Protocol", "?1")
	hrsp, err := cc.RoundTrip(req)
	if err != nil {
		_ = pw.Close()
		_ = cc.Close()
		return nil, rsp, err
	}
	rsp.Status = hrsp.StatusCode
	if hrsp.StatusCode != http.StatusOK {
		_ = hrsp.Body.Close()
		_ = pw.Close()
		_ = cc.Close()
		return nil, rsp, fmt.Errorf("status %d", hrsp.StatusCode)
	}
	return &h2Tunnel{cc: cc, body: hrsp.Body, pw: pw, cr: newCapsuleReader(hrsp.Body)}, rsp, nil
}

// h2Tunnel carries packets as capsules on one HTTP/2 stream: the request
// body toward the server, the response body back.
type h2Tunnel struct {
	cc   *http2.ClientConn //nolint:staticcheck // dialH2 explains why
	body io.ReadCloser
	pw   *io.PipeWriter
	cr   *capsuleReader
	// wbuf is only used by WritePacket.
	wbuf []byte
}

// assigned reads capsules until the first ADDRESS_ASSIGN and returns its
// prefixes. A packet that arrives before it is dropped.
func (t *h2Tunnel) assigned(ctx context.Context) ([]netip.Prefix, error) {
	stop := context.AfterFunc(ctx, func() { _ = t.body.Close() })
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
	_, err := t.pw.Write(t.wbuf)
	return err
}

// Close ends the request body, cancels the stream and closes the
// connection, which ends a ReadPacket in progress.
func (t *h2Tunnel) Close() error {
	_ = t.pw.Close()
	_ = t.body.Close()
	return t.cc.Close()
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
