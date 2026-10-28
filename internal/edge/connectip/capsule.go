// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package connectip

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/netip"

	connectip "github.com/quic-go/connect-ip-go"
	"github.com/quic-go/quic-go/quicvarint"
)

// Capsule types from RFC 9297 and RFC 9484.
const (
	capsuleDatagram           = 0x00
	capsuleAddressAssign      = 0x01
	capsuleAddressRequest     = 0x02
	capsuleRouteAdvertisement = 0x03
)

const (
	// maxH2Packet is the largest IP packet the HTTP/2 transport carries in
	// either direction. A larger packet toward the client gets a Packet Too
	// Big; a larger one from the client is dropped.
	maxH2Packet = 1500
	// maxDatagramCapsule is the largest DATAGRAM capsule value read into
	// memory: a context ID of at most 8 bytes and a maxH2Packet packet.
	maxDatagramCapsule = 8 + maxH2Packet
	// maxAddressRequestCapsule bounds one ADDRESS_REQUEST, enough for 46
	// IPv6 entries with 8-byte request IDs. A longer one ends the request.
	maxAddressRequestCapsule = 1024
)

var errCapsuleTooLarge = errors.New("capsule exceeds the size limit")

// capsule is one capsule read from a stream. value is only valid until the
// next read. A DATAGRAM capsule larger than maxDatagramCapsule, and every
// capsule of a type the server does not read, is discarded as it arrives:
// skipped is then set and value is nil.
type capsule struct {
	typ     uint64
	value   []byte
	skipped bool
}

// capsuleReader parses capsules from a stream incrementally. A capsule may
// be split across reads or share one with others. It holds at most
// maxDatagramCapsule bytes of capsule value, whatever the client sends.
type capsuleReader struct {
	r   *bufio.Reader
	buf []byte
	// readAll reads every capsule type up to maxDatagramCapsule, as a
	// client must. The server leaves it false.
	readAll bool
}

func newCapsuleReader(r io.Reader) *capsuleReader {
	return &capsuleReader{r: bufio.NewReader(r), buf: make([]byte, maxDatagramCapsule)}
}

// next returns the next capsule. It returns io.EOF at a clean end of stream,
// io.ErrUnexpectedEOF for a capsule cut off by the end of the stream and
// errCapsuleTooLarge for an ADDRESS_REQUEST over maxAddressRequestCapsule.
func (c *capsuleReader) next() (capsule, error) {
	typ, err := quicvarint.Read(c.r)
	if err != nil {
		return capsule{}, err
	}
	n, err := quicvarint.Read(c.r)
	if err != nil {
		return capsule{}, unexpectedEOF(err)
	}
	limit := uint64(0)
	switch {
	case c.readAll || typ == capsuleDatagram:
		limit = maxDatagramCapsule
	case typ == capsuleAddressRequest:
		if n > maxAddressRequestCapsule {
			return capsule{}, fmt.Errorf("%w: ADDRESS_REQUEST of %d bytes", errCapsuleTooLarge, n)
		}
		limit = maxAddressRequestCapsule
	}
	if n > limit {
		if _, err := io.CopyN(io.Discard, c.r, int64(n)); err != nil {
			return capsule{}, unexpectedEOF(err)
		}
		return capsule{typ: typ, skipped: true}, nil
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

func appendCapsuleHeader(b []byte, typ uint64, n int) []byte {
	b = quicvarint.Append(b, typ)
	return quicvarint.Append(b, uint64(n))
}

// appendDatagram appends a DATAGRAM capsule carrying pkt in context 0.
func appendDatagram(b, pkt []byte) []byte {
	b = appendCapsuleHeader(b, capsuleDatagram, 1+len(pkt))
	b = quicvarint.Append(b, 0)
	return append(b, pkt...)
}

// assignment is one Assigned Address entry; request ID 0 is unsolicited.
type assignment struct {
	requestID uint64
	prefix    netip.Prefix
}

func appendPrefix(b []byte, p netip.Prefix) []byte {
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
		v = appendPrefix(v, e.prefix)
	}
	b = appendCapsuleHeader(b, capsuleAddressAssign, len(v))
	return append(b, v...)
}

// appendRouteAdvertisement appends a ROUTE_ADVERTISEMENT capsule. routes
// must already be sorted and disjoint, as routeRanges returns them.
func appendRouteAdvertisement(b []byte, routes []connectip.IPRoute) []byte {
	var v []byte
	for _, r := range routes {
		if r.StartIP.Is4() {
			v = append(v, 4)
		} else {
			v = append(v, 6)
		}
		v = append(v, r.StartIP.AsSlice()...)
		v = append(v, r.EndIP.AsSlice()...)
		v = append(v, r.IPProtocol)
	}
	b = appendCapsuleHeader(b, capsuleRouteAdvertisement, len(v))
	return append(b, v...)
}

// parseAddressRequest parses the entries of an ADDRESS_REQUEST capsule as
// RFC 9484 requires: at least one entry, nonzero request IDs, and prefixes
// with no bits set past their length.
func parseAddressRequest(v []byte) ([]assignment, error) {
	if len(v) == 0 {
		return nil, errors.New("ADDRESS_REQUEST has no entries")
	}
	var out []assignment
	r := bytes.NewReader(v)
	for r.Len() > 0 {
		id, err := quicvarint.Read(r)
		if err != nil {
			return nil, unexpectedEOF(err)
		}
		if id == 0 {
			return nil, errors.New("ADDRESS_REQUEST has a zero request ID")
		}
		version, err := r.ReadByte()
		if err != nil {
			return nil, unexpectedEOF(err)
		}
		var raw []byte
		switch version {
		case 4:
			raw = make([]byte, 4)
		case 6:
			raw = make([]byte, 16)
		default:
			return nil, fmt.Errorf("ADDRESS_REQUEST has unknown IP version %d", version)
		}
		if _, err := io.ReadFull(r, raw); err != nil {
			return nil, unexpectedEOF(err)
		}
		bits, err := r.ReadByte()
		if err != nil {
			return nil, unexpectedEOF(err)
		}
		addr, _ := netip.AddrFromSlice(raw)
		if int(bits) > addr.BitLen() {
			return nil, fmt.Errorf("ADDRESS_REQUEST prefix length %d is too long", bits)
		}
		p := netip.PrefixFrom(addr, int(bits))
		if p != p.Masked() {
			return nil, fmt.Errorf("ADDRESS_REQUEST prefix %s has host bits set", p)
		}
		out = append(out, assignment{requestID: id, prefix: p})
	}
	return out, nil
}
