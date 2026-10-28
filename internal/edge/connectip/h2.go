// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package connectip

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	connectip "github.com/quic-go/connect-ip-go"
	"github.com/quic-go/quic-go/quicvarint"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv6"
)

// h2WriteTimeout bounds one capsule write toward an HTTP/2 client. A client
// that stops reading for longer ends its own request. Tests shorten it.
var h2WriteTimeout = 5 * time.Second

const (
	// h2IdleTimeout closes an HTTP/2 connection with no open request.
	h2IdleTimeout = 30 * time.Second
	// h2PingTimeout bounds a silent HTTP/2 connection: the server pings it
	// after this long without a frame and closes it if no answer comes in
	// the same time.
	h2PingTimeout = 15 * time.Second

	capsuleProtocolHeader = "Capsule-Protocol"
	protocolPseudoHeader  = ":protocol"
)

// ErrExtendedConnectDisabled is returned by ServeTLS when net/http's HTTP/2
// server does not offer Extended CONNECT.
var ErrExtendedConnectDisabled = errors.New(
	"HTTP/2 Extended CONNECT is disabled: start the process with GODEBUG containing http2xconnect=1")

// ExtendedConnectEnabled reports whether net/http's HTTP/2 server offers
// Extended CONNECT (RFC 8441). net/http reads GODEBUG once, when it
// initializes, and offers it only when GODEBUG contains http2xconnect=1
// (golang/go#71128). This repeats that check, so it is only accurate while
// GODEBUG is unchanged since the process started.
func ExtendedConnectEnabled() bool {
	return strings.Contains(os.Getenv("GODEBUG"), "http2xconnect=1")
}

// ServeTLS serves CONNECT-IP over HTTP/2 with TLS on ln until the server is
// closed. It returns ErrExtendedConnectDisabled at once when the process
// does not offer Extended CONNECT.
func (s *Server) ServeTLS(ln net.Listener) error {
	if !ExtendedConnectEnabled() {
		return ErrExtendedConnectDisabled
	}
	return s.h2.ServeTLS(&limitListener{Listener: ln, s: s}, "", "")
}

// limitListener applies Limits.MaxConnections, which QUIC and TCP
// connections share, and Limits.MaxConnectionsPerSource to accepted TCP
// connections. TCP's own handshake proves the source address, so a
// connection counts from the moment it is accepted.
type limitListener struct {
	net.Listener
	s *Server
}

func (l *limitListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if counted, ok := l.s.countTCP(c); ok {
			return counted, nil
		}
	}
}

// countTCP counts c until it is closed. It closes c and returns false when c
// would exceed a connection cap.
func (s *Server) countTCP(c net.Conn) (net.Conn, bool) {
	src := sourceAddr(c.RemoteAddr())
	n := s.conns.Add(1)
	s.countMu.Lock()
	s.sources[src]++
	fromSrc := s.sources[src]
	s.countMu.Unlock()
	counted := &countedConn{Conn: c, done: func() {
		s.conns.Add(-1)
		s.countMu.Lock()
		defer s.countMu.Unlock()
		if s.sources[src]--; s.sources[src] == 0 {
			delete(s.sources, src)
		}
	}}
	reason := ""
	switch {
	case n > int64(s.limits.MaxConnections):
		reason = "too many connections"
	case fromSrc > s.limits.MaxConnectionsPerSource:
		reason = "too many connections from one source"
	default:
		return counted, true
	}
	s.log.Info("TCP connection rejected", "reason", reason, "remote", c.RemoteAddr())
	_ = counted.Close()
	return nil, false
}

// countedConn runs done once, when it is first closed.
type countedConn struct {
	net.Conn
	once sync.Once
	done func()
}

func (c *countedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.done)
	return err
}

// serveH2 parses an Extended CONNECT request (RFC 8441) for connect-ip.
func (s *Server) serveH2(w http.ResponseWriter, r *http.Request) {
	// net/http exposes the :protocol pseudo-header as a request header.
	if r.Method != http.MethodConnect || r.Header.Get(protocolPseudoHeader) != connectIPProtocol {
		s.reject(w, http.StatusBadRequest, "invalid CONNECT-IP request", errors.New("not an Extended CONNECT for connect-ip"))
		return
	}
	if r.Host != s.authority {
		s.reject(w, http.StatusBadRequest, "invalid CONNECT-IP request", errors.New("unknown authority"))
		return
	}
	if r.URL.Path != TemplatePath {
		s.reject(w, http.StatusNotFound, "unknown path", nil)
		return
	}
	if !capsuleProtocolAllowed(r.Header) {
		s.reject(w, http.StatusBadRequest, "invalid CONNECT-IP request", errors.New("invalid Capsule-Protocol header"))
		return
	}
	s.serve(w, r, &h2Request{r: r})
}

// capsuleProtocolAllowed reports whether a Capsule-Protocol header is absent,
// which connect-ip implies, or is one structured-field boolean true (RFC
// 9297), with any parameters.
func capsuleProtocolAllowed(h http.Header) bool {
	values, ok := h[capsuleProtocolHeader]
	if !ok {
		return true
	}
	if len(values) != 1 {
		return false
	}
	item, _, _ := strings.Cut(values[0], ";")
	return strings.TrimSpace(item) == "?1"
}

// h2Request is a CONNECT-IP request over HTTP/2.
type h2Request struct {
	r *http.Request
}

// probe accepts every path: a TCP stream carries a capsule of any size, and
// the tunnel itself sends Packet Too Big above maxH2Packet.
func (*h2Request) probe() error { return nil }

func (h *h2Request) accept(w http.ResponseWriter) (tunnel, error) {
	w.Header().Set(capsuleProtocolHeader, "?1")
	w.WriteHeader(http.StatusOK)
	rc := http.NewResponseController(w)
	if err := rc.Flush(); err != nil {
		return nil, err
	}
	return &h2Tunnel{
		body:     h.r.Body,
		w:        w,
		rc:       rc,
		cr:       newCapsuleReader(h.r.Body),
		addrReqs: make(chan []assignment, 1),
		closed:   make(chan struct{}),
	}, nil
}

// h2Tunnel carries one request's capsules on its HTTP/2 stream. It applies
// the checks connect-ip-go applies to HTTP/3 datagrams that the session's
// packetPolicy does not: toward the client it drops a packet whose hop
// limit would reach zero and decrements the rest (RFC 9484, Section 4.3),
// and it answers a packet over maxH2Packet with Packet Too Big.
type h2Tunnel struct {
	body io.ReadCloser
	w    io.Writer
	rc   *http.ResponseController
	// cr is only read by ReadPacket.
	cr *capsuleReader

	// writeMu serializes capsule writes and guards out.
	writeMu sync.Mutex
	out     []byte

	// addrReqs passes ADDRESS_REQUEST entries from ReadPacket to
	// receiveAddressRequest, so a client that floods them stalls its own
	// stream.
	addrReqs  chan []assignment
	closed    chan struct{}
	closeOnce sync.Once
	closeErr  error
}

// ReadPacket returns the next IP packet the client sends in context 0. It
// discards datagrams in other contexts and ones over maxH2Packet, and
// queues address requests. A malformed capsule ends the request.
func (t *h2Tunnel) ReadPacket(b []byte) (int, error) {
	for {
		c, err := t.cr.next()
		if err != nil {
			return 0, err
		}
		switch c.typ {
		case capsuleDatagram:
			if c.skipped {
				deny(toVPC, reasonTooLarge)
				continue
			}
			id, n, err := quicvarint.Parse(c.value)
			if err != nil {
				return 0, errors.New("DATAGRAM capsule has no context ID")
			}
			// Context 0, IP packets, is the only registered context.
			if id != 0 {
				continue
			}
			return copy(b, c.value[n:]), nil
		case capsuleAddressRequest:
			reqs, err := parseAddressRequest(c.value)
			if err != nil {
				return 0, err
			}
			select {
			case t.addrReqs <- reqs:
			case <-t.closed:
				return 0, net.ErrClosed
			}
		default:
			// The client's ADDRESS_ASSIGN and ROUTE_ADVERTISEMENT do not
			// change what it may send, and unknown capsules are skipped.
		}
	}
}

// WritePacket sends one IPv6 packet to the client. It returns a Packet Too
// Big for the backend when the packet is over maxH2Packet.
func (t *h2Tunnel) WritePacket(b []byte) ([]byte, error) {
	if len(b) < ipv6HeaderLen || b[0]>>4 != 6 {
		deny(toClient, reasonMalformed)
		return nil, nil
	}
	if b[7] <= 1 {
		deny(toClient, reasonHopLimit)
		return nil, nil
	}
	if len(b) > maxH2Packet {
		ptb, err := packetTooBig(b, maxH2Packet)
		return ptb, err
	}
	b[7]--
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	t.out = appendDatagram(t.out[:0], b)
	return nil, t.writeLocked(t.out)
}

// AssignAddresses sends an unsolicited ADDRESS_ASSIGN of prefixes.
func (t *h2Tunnel) AssignAddresses(prefixes []netip.Prefix) error {
	entries := make([]assignment, len(prefixes))
	for i, p := range prefixes {
		entries[i] = assignment{prefix: p}
	}
	return t.write(appendAddressAssign(nil, entries))
}

// AdvertiseRoute sends a ROUTE_ADVERTISEMENT of routes, which must be sorted
// and disjoint as routeRanges returns them.
func (t *h2Tunnel) AdvertiseRoute(routes []connectip.IPRoute) error {
	return t.write(appendRouteAdvertisement(nil, routes))
}

func (t *h2Tunnel) receiveAddressRequest(ctx context.Context) (addressRequest, error) {
	var reqs []assignment
	select {
	case reqs = <-t.addrReqs:
	case <-ctx.Done():
		return addressRequest{}, ctx.Err()
	case <-t.closed:
		return addressRequest{}, net.ErrClosed
	}
	prefixes := make([]netip.Prefix, len(reqs))
	for i, r := range reqs {
		prefixes[i] = r.prefix
	}
	respond := func(assigned, additional []netip.Prefix) error {
		if len(assigned) != len(reqs) {
			return errors.New("address request needs one assignment per requested prefix")
		}
		entries := make([]assignment, 0, len(reqs)+len(additional))
		for i, p := range assigned {
			if p == (netip.Prefix{}) {
				p = rejectedPrefix(reqs[i].prefix)
			}
			entries = append(entries, assignment{requestID: reqs[i].requestID, prefix: p})
		}
		for _, p := range additional {
			entries = append(entries, assignment{prefix: p})
		}
		return t.write(appendAddressAssign(nil, entries))
	}
	return addressRequest{prefixes: prefixes, respond: respond}, nil
}

// rejectedPrefix is the assignment that rejects a request for p: the
// unspecified address of p's family as a full-length prefix (RFC 9484,
// Section 4.7.1).
func rejectedPrefix(p netip.Prefix) netip.Prefix {
	if p.Addr().Is4() {
		return netip.PrefixFrom(netip.IPv4Unspecified(), 32)
	}
	return netip.PrefixFrom(netip.IPv6Unspecified(), 128)
}

func (t *h2Tunnel) write(b []byte) error {
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	return t.writeLocked(b)
}

// writeLocked writes b within h2WriteTimeout. It sets the deadline before
// checking for Close, so Close's own deadline wins over a write in
// progress. HTTP/2 resets a stream whose write deadline passes even with no
// write pending, so a completed write clears it.
func (t *h2Tunnel) writeLocked(b []byte) error {
	_ = t.rc.SetWriteDeadline(time.Now().Add(h2WriteTimeout))
	select {
	case <-t.closed:
		return net.ErrClosed
	default:
	}
	_, err := t.w.Write(b)
	if err == nil {
		err = t.rc.Flush()
	}
	if err != nil {
		return err
	}
	_ = t.rc.SetWriteDeadline(time.Time{})
	return nil
}

// Close stops every read and write on the stream. The handler's return
// then ends the stream.
func (t *h2Tunnel) Close() error {
	t.closeOnce.Do(func() {
		close(t.closed)
		_ = t.rc.SetWriteDeadline(time.Now())
		t.closeErr = t.body.Close()
	})
	return t.closeErr
}

// packetTooBig returns an ICMPv6 Packet Too Big for pkt, from pkt's
// destination to its source, quoting as much of pkt as fits in a 1280-byte
// packet. It is what connect-ip-go returns over HTTP/3.
func packetTooBig(pkt []byte, mtu int) ([]byte, error) {
	src, dst := pkt[24:40], pkt[8:24]
	const maxQuote = MinInnerMTU - ipv6HeaderLen - 8
	body, err := (&icmp.Message{
		Type: ipv6.ICMPTypePacketTooBig,
		Body: &icmp.PacketTooBig{MTU: mtu, Data: pkt[:min(len(pkt), maxQuote)]},
	}).Marshal(icmp.IPv6PseudoHeader(src, dst))
	if err != nil {
		return nil, err
	}
	out := make([]byte, ipv6HeaderLen, ipv6HeaderLen+len(body))
	out[0] = 6 << 4
	binary.BigEndian.PutUint16(out[4:6], uint16(len(body)))
	out[6] = protoICMPv6
	out[7] = 64
	copy(out[8:24], src)
	copy(out[24:40], dst)
	return append(out, body...), nil
}
