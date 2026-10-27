// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package connectipinterop

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"testing"

	"github.com/quic-go/quic-go/quicvarint"
)

// Capsule types from RFC 9297 and RFC 9484.
const (
	capsuleDatagram           = 0x00
	capsuleAddressAssign      = 0x01
	capsuleAddressRequest     = 0x02
	capsuleRouteAdvertisement = 0x03
)

// maxCapsuleLen bounds one capsule's value: a context ID and the largest IPv6
// packet the prototype forwards. Longer capsules end the request.
const maxCapsuleLen = 8 + maxPacketSize

var errCapsuleTooLarge = errors.New("capsule exceeds the size limit")

// capsule is one parsed capsule. value is only valid until the next read.
type capsule struct {
	typ   uint64
	value []byte
}

// capsuleReader parses capsules from a stream. Capsules may be split across
// reads or share one; the reader holds at most maxCapsuleLen bytes of value.
type capsuleReader struct {
	r   *bufio.Reader
	buf []byte
}

func newCapsuleReader(r io.Reader) *capsuleReader {
	return &capsuleReader{r: bufio.NewReader(r), buf: make([]byte, maxCapsuleLen)}
}

// next returns the next capsule. It returns io.EOF at a clean end of stream
// and io.ErrUnexpectedEOF for a capsule cut off by the end of the stream.
func (c *capsuleReader) next() (capsule, error) {
	typ, err := quicvarint.Read(c.r)
	if err != nil {
		return capsule{}, err
	}
	n, err := quicvarint.Read(c.r)
	if err != nil {
		return capsule{}, unexpectedEOF(err)
	}
	if n > maxCapsuleLen {
		return capsule{}, fmt.Errorf("%w: type %#x, %d bytes", errCapsuleTooLarge, typ, n)
	}
	if _, err := io.ReadFull(c.r, c.buf[:n]); err != nil {
		return capsule{}, unexpectedEOF(err)
	}
	return capsule{typ: typ, value: c.buf[:n]}, nil
}

func unexpectedEOF(err error) error {
	if errors.Is(err, io.EOF) {
		return io.ErrUnexpectedEOF
	}
	return err
}

func appendCapsule(b []byte, typ uint64, value []byte) []byte {
	b = quicvarint.Append(b, typ)
	b = quicvarint.Append(b, uint64(len(value)))
	return append(b, value...)
}

// appendDatagram appends a DATAGRAM capsule carrying pkt in context 0.
func appendDatagram(b, pkt []byte) []byte {
	b = quicvarint.Append(b, capsuleDatagram)
	b = quicvarint.Append(b, uint64(1+len(pkt)))
	b = quicvarint.Append(b, 0)
	return append(b, pkt...)
}

// assignment is one Assigned or Requested Address entry.
type assignment struct {
	requestID uint64
	prefix    netip.Prefix
}

func appendPrefixEntry(b []byte, p netip.Prefix) []byte {
	if p.Addr().Is4() {
		b = append(b, 4)
	} else {
		b = append(b, 6)
	}
	b = append(b, p.Addr().AsSlice()...)
	return append(b, byte(p.Bits()))
}

func appendAddressAssign(b []byte, entries []assignment) []byte {
	var v []byte
	for _, e := range entries {
		v = quicvarint.Append(v, e.requestID)
		v = appendPrefixEntry(v, e.prefix)
	}
	return appendCapsule(b, capsuleAddressAssign, v)
}

// parseAddressEntries parses the entries of an ADDRESS_ASSIGN or
// ADDRESS_REQUEST capsule.
func parseAddressEntries(v []byte) ([]assignment, error) {
	var out []assignment
	r := bytes.NewReader(v)
	for r.Len() > 0 {
		id, err := quicvarint.Read(r)
		if err != nil {
			return nil, err
		}
		version, err := r.ReadByte()
		if err != nil {
			return nil, err
		}
		var size int
		switch version {
		case 4:
			size = 4
		case 6:
			size = 16
		default:
			return nil, fmt.Errorf("unknown IP version %d", version)
		}
		raw := make([]byte, size+1)
		if _, err := io.ReadFull(r, raw); err != nil {
			return nil, unexpectedEOF(err)
		}
		addr, _ := netip.AddrFromSlice(raw[:size])
		p, err := addr.Prefix(int(raw[size]))
		if err != nil || int(raw[size]) > addr.BitLen() || p.Addr() != addr {
			return nil, fmt.Errorf("invalid prefix %s/%d", addr, raw[size])
		}
		out = append(out, assignment{requestID: id, prefix: p})
	}
	return out, nil
}

// appendRouteAdvertisement advertises each prefix for every IP protocol.
func appendRouteAdvertisement(b []byte, prefixes []netip.Prefix) []byte {
	var v []byte
	for _, p := range prefixes {
		if p.Addr().Is4() {
			v = append(v, 4)
		} else {
			v = append(v, 6)
		}
		v = append(v, p.Masked().Addr().AsSlice()...)
		v = append(v, lastAddr(p).AsSlice()...)
		v = append(v, 0)
	}
	return appendCapsule(b, capsuleRouteAdvertisement, v)
}

// lastAddr returns the highest address in p.
func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Masked().Addr().AsSlice()
	for bit := p.Bits(); bit < len(b)*8; bit++ {
		b[bit/8] |= 0x80 >> (bit % 8)
	}
	addr, _ := netip.AddrFromSlice(b)
	return addr
}

func TestCapsuleReaderSplitAndCoalesced(t *testing.T) {
	pkt := bytes.Repeat([]byte{0x60}, 1280)
	var stream []byte
	stream = appendDatagram(stream, pkt)
	stream = appendCapsule(stream, 0x29, []byte("unknown"))
	stream = appendDatagram(stream, pkt[:40])

	// One byte per read exercises every split point; a single read holds
	// all three capsules.
	for name, r := range map[string]io.Reader{
		"split":     &oneByteReader{data: stream},
		"coalesced": bytes.NewReader(stream),
	} {
		t.Run(name, func(t *testing.T) {
			cr := newCapsuleReader(r)
			var lens []int
			for {
				c, err := cr.next()
				if errors.Is(err, io.EOF) {
					break
				}
				if err != nil {
					t.Fatalf("next: %v", err)
				}
				lens = append(lens, len(c.value))
			}
			if want := []int{1281, 7, 41}; fmt.Sprint(lens) != fmt.Sprint(want) {
				t.Fatalf("capsule lengths = %v, want %v", lens, want)
			}
		})
	}
}

func TestCapsuleReaderRejectsMalformed(t *testing.T) {
	full := appendDatagram(nil, make([]byte, 100))
	oversized := quicvarint.Append(nil, capsuleDatagram)
	oversized = quicvarint.Append(oversized, maxCapsuleLen+1)
	for name, tc := range map[string]struct {
		in   []byte
		want error
	}{
		"truncated value":  {full[:len(full)-1], io.ErrUnexpectedEOF},
		"truncated length": {[]byte{0x00, 0x40}, io.ErrUnexpectedEOF},
		"oversized":        {oversized, errCapsuleTooLarge},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := newCapsuleReader(bytes.NewReader(tc.in)).next()
			if !errors.Is(err, tc.want) {
				t.Fatalf("next = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestAddressEntriesRoundTrip(t *testing.T) {
	in := []assignment{
		{requestID: 0, prefix: netip.MustParsePrefix("fd00:973:a:0:1::/96")},
		{requestID: 7, prefix: netip.MustParsePrefix("0.0.0.0/32")},
	}
	c, err := newCapsuleReader(bytes.NewReader(appendAddressAssign(nil, in))).next()
	if err != nil {
		t.Fatalf("next: %v", err)
	}
	out, err := parseAddressEntries(c.value)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if fmt.Sprint(out) != fmt.Sprint(in) {
		t.Fatalf("entries = %v, want %v", out, in)
	}
	for name, v := range map[string][]byte{
		"bad version":     {0x01, 0x05, 1, 2, 3, 4, 32},
		"long prefix":     append(append([]byte{0x01, 0x04}, 10, 0, 0, 1), 33),
		"host bits set":   append(append([]byte{0x01, 0x04}, 10, 0, 0, 1), 24),
		"truncated entry": {0x01, 0x06, 0xfd},
	} {
		if _, err := parseAddressEntries(v); err == nil {
			t.Errorf("%s: parse succeeded", name)
		}
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
