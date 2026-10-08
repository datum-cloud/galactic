// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package probe runs bounded ICMP ping and traceroute from a fixed source
// address in the default VRF, with structured results.
//
// It sends ICMP echo requests on a raw socket (CAP_NET_RAW) and matches every
// reply to its probe by ICMP identifier and sequence number: directly for an
// echo reply, and through the quoted original packet for time-exceeded,
// destination-unreachable, packet-too-big and parameter-problem errors. A raw
// socket sees every ICMP packet the host receives, so anything that does not
// match is dropped. A probe with no reply is a result, not an error.
//
// Destination policy is not decided here: callers check the destination
// before calling.
package probe

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"google.golang.org/protobuf/types/known/durationpb"

	fabricv1 "go.datum.net/galactic/api/fabric/v1"
	"go.datum.net/galactic/internal/fabric/query"
)

// Protocol numbers for icmp.ParseMessage.
const (
	protoICMP   = 1
	protoICMPv6 = 58
)

// ICMP type names reported in results.
const (
	TypeEchoReply      = "echo-reply"
	TypeTimeExceeded   = "time-exceeded"
	TypeUnreachable    = "destination-unreachable"
	TypePacketTooBig   = "packet-too-big"
	TypeParamProblem   = "parameter-problem"
	defaultPayloadSize = 32
)

// Conn is the raw ICMP socket a probe runs on. It exists so tests can
// simulate the network.
type Conn interface {
	// WriteTo sends one ICMP message to dst.
	WriteTo(b []byte, dst net.Addr) (int, error)
	// ReadFrom receives one ICMP message, without the IP header.
	ReadFrom(b []byte) (int, net.Addr, error)
	SetReadDeadline(t time.Time) error
	// SetHopLimit sets the TTL or hop limit of later packets.
	SetHopLimit(n int) error
	Close() error
}

// Limiter paces packets. Wait blocks until one more packet may be sent.
type Limiter interface {
	Wait(ctx context.Context) error
}

// Options bounds one probe run. Zero fields take the query package's limits;
// larger values are lowered to them.
type Options struct {
	// Count is the number of echo requests a ping sends.
	Count int
	// MaxHops bounds a traceroute.
	MaxHops int
	// Wait bounds the wait for one reply.
	Wait time.Duration
	// PayloadSize is the echo payload size in bytes.
	PayloadSize int
	// Limiter, when set, paces every packet sent.
	Limiter Limiter
}

func (o Options) clamped() Options {
	clamp := func(v, def, ceiling int) int {
		if v <= 0 {
			return def
		}
		return min(v, ceiling)
	}
	o.Count = clamp(o.Count, query.PingCount, query.PingCount)
	o.MaxHops = clamp(o.MaxHops, query.TracerouteMaxHops, query.TracerouteMaxHops)
	o.PayloadSize = clamp(o.PayloadSize, defaultPayloadSize, query.MaxProbePayload)
	if o.Wait <= 0 || o.Wait > query.ProbeWait {
		o.Wait = query.ProbeWait
	}
	return o
}

// Dialer opens raw ICMP sockets bound to a source address.
type Dialer func(src netip.Addr) (Conn, error)

// Prober runs probes. The zero value uses raw sockets.
type Prober struct {
	// Dial opens the socket; nil selects ListenRaw.
	Dial Dialer
	// now returns the current time; nil selects time.Now.
	now func() time.Time
}

// Error is a probe that could not run at all.
type Error struct {
	Code    string
	Message string
	Err     error
}

func (e *Error) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %s: %v", e.Code, e.Message, e.Err)
	}
	return e.Code + ": " + e.Message
}

func (e *Error) Unwrap() error { return e.Err }

// Probe error codes.
const (
	// CodeSourceUnavailable means the source address could not be bound.
	CodeSourceUnavailable = "ProbeSourceUnavailable"
	// CodeSocket means the socket failed while probing.
	CodeSocket = "ProbeFailed"
)

// ListenRaw opens a raw ICMP or ICMPv6 socket bound to src.
func ListenRaw(src netip.Addr) (Conn, error) {
	if src.Is4() {
		c, err := icmp.ListenPacket("ip4:icmp", src.String())
		if err != nil {
			return nil, err
		}
		return &rawConn{PacketConn: c, setHop: c.IPv4PacketConn().SetTTL}, nil
	}
	c, err := icmp.ListenPacket("ip6:ipv6-icmp", src.String())
	if err != nil {
		return nil, err
	}
	pc := c.IPv6PacketConn()
	// Only the ICMPv6 types a probe can be answered with.
	var f ipv6.ICMPFilter
	f.SetAll(true)
	for _, t := range []ipv6.ICMPType{ipv6.ICMPTypeEchoReply, ipv6.ICMPTypeTimeExceeded,
		ipv6.ICMPTypeDestinationUnreachable, ipv6.ICMPTypePacketTooBig, ipv6.ICMPTypeParameterProblem} {
		f.Accept(t)
	}
	if err := pc.SetICMPFilter(&f); err != nil {
		_ = c.Close()
		return nil, err
	}
	return &rawConn{PacketConn: c, setHop: pc.SetHopLimit}, nil
}

type rawConn struct {
	*icmp.PacketConn
	setHop func(int) error
}

func (c *rawConn) SetHopLimit(n int) error { return c.setHop(n) }

// session is one probe run's socket and correlation state.
type session struct {
	conn    Conn
	src     netip.Addr
	dst     netip.Addr
	id      uint16
	seq     uint16
	payload []byte
	now     func() time.Time
}

func (p *Prober) open(src, dst netip.Addr, opts Options) (*session, error) {
	if !src.IsValid() || src.Is4() != dst.Is4() {
		return nil, &Error{Code: CodeSourceUnavailable, Message: fmt.Sprintf("no %s source address", familyName(dst))}
	}
	dial := p.Dial
	if dial == nil {
		dial = ListenRaw
	}
	conn, err := dial(src)
	if err != nil {
		return nil, &Error{Code: CodeSourceUnavailable, Message: "open raw socket on " + src.String(), Err: err}
	}
	var b [4]byte
	_, _ = rand.Read(b[:])
	now := p.now
	if now == nil {
		now = time.Now
	}
	payload := make([]byte, opts.PayloadSize)
	copy(payload, "fabric-api")
	return &session{
		conn: conn, src: src, dst: dst, now: now, payload: payload,
		id:  binary.BigEndian.Uint16(b[:2]),
		seq: binary.BigEndian.Uint16(b[2:]),
	}, nil
}

func familyName(a netip.Addr) string {
	if a.Is4() {
		return "IPv4"
	}
	return "IPv6"
}

// reply is one matched answer to a probe.
type reply struct {
	from     netip.Addr
	typ      string
	code     int
	received time.Time
}

// send transmits one echo request with the next sequence number and returns
// that sequence number and the send time.
func (s *session) send(ctx context.Context, lim Limiter, hops int) (uint16, time.Time, error) {
	if lim != nil {
		if err := lim.Wait(ctx); err != nil {
			return 0, time.Time{}, err
		}
	}
	if err := s.conn.SetHopLimit(hops); err != nil {
		return 0, time.Time{}, &Error{Code: CodeSocket, Message: "set hop limit", Err: err}
	}
	s.seq++
	seq := s.seq
	var typ icmp.Type = ipv4.ICMPTypeEcho
	if s.dst.Is6() {
		typ = ipv6.ICMPTypeEchoRequest
	}
	msg := icmp.Message{Type: typ, Body: &icmp.Echo{ID: int(s.id), Seq: int(seq), Data: s.payload}}
	// The kernel computes the ICMPv6 checksum; Marshal fills in ICMPv4's.
	b, err := msg.Marshal(nil)
	if err != nil {
		return 0, time.Time{}, &Error{Code: CodeSocket, Message: "marshal echo", Err: err}
	}
	sent := s.now()
	if _, err := s.conn.WriteTo(b, &net.IPAddr{IP: s.dst.AsSlice()}); err != nil {
		return 0, time.Time{}, &Error{Code: CodeSocket, Message: "send echo", Err: err}
	}
	return seq, sent, nil
}

// await waits for the reply to seq until wait passes or ctx ends. It returns
// ok=false on timeout. Unmatched, late and duplicate packets are discarded.
func (s *session) await(ctx context.Context, seq uint16, wait time.Duration) (reply, bool, error) {
	deadline := s.now().Add(wait)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	if err := s.conn.SetReadDeadline(deadline); err != nil {
		return reply{}, false, &Error{Code: CodeSocket, Message: "set read deadline", Err: err}
	}
	stop := context.AfterFunc(ctx, func() { _ = s.conn.SetReadDeadline(time.Unix(1, 0)) })
	defer stop()
	buf := make([]byte, 1500)
	for {
		n, peer, err := s.conn.ReadFrom(buf)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				return reply{}, false, ctxDone(ctx)
			}
			return reply{}, false, &Error{Code: CodeSocket, Message: "read reply", Err: err}
		}
		if r, ok := s.match(buf[:n], peer, seq); ok {
			return r, true, nil
		}
	}
}

// match decides whether an ICMP message answers probe seq.
func (s *session) match(b []byte, peer net.Addr, seq uint16) (reply, bool) {
	proto := protoICMP
	if s.dst.Is6() {
		proto = protoICMPv6
	}
	msg, err := icmp.ParseMessage(proto, b)
	if err != nil {
		return reply{}, false
	}
	from := addrOf(peer)
	r := reply{from: from, received: s.now(), code: msg.Code}
	switch body := msg.Body.(type) {
	case *icmp.Echo:
		if (msg.Type != ipv4.ICMPTypeEchoReply && msg.Type != ipv6.ICMPTypeEchoReply) ||
			uint16(body.ID) != s.id || uint16(body.Seq) != seq || from != s.dst {
			return reply{}, false
		}
		r.typ = TypeEchoReply
		return r, true
	case *icmp.TimeExceeded:
		r.typ = TypeTimeExceeded
		return r, s.quoted(body.Data, seq)
	case *icmp.DstUnreach:
		r.typ = TypeUnreachable
		return r, s.quoted(body.Data, seq)
	case *icmp.PacketTooBig:
		r.typ = TypePacketTooBig
		return r, s.quoted(body.Data, seq)
	case *icmp.ParamProb:
		r.typ = TypeParamProblem
		return r, s.quoted(body.Data, seq)
	}
	return reply{}, false
}

// quoted reports whether an ICMP error's quoted packet is our echo request
// seq to our destination.
func (s *session) quoted(b []byte, seq uint16) bool {
	var dst netip.Addr
	var inner []byte
	if s.dst.Is4() {
		if len(b) < 20 || b[0]>>4 != 4 {
			return false
		}
		ihl := int(b[0]&0x0f) * 4
		if ihl < 20 || len(b) < ihl+8 || b[9] != protoICMP {
			return false
		}
		dst = netip.AddrFrom4([4]byte(b[16:20]))
		inner = b[ihl:]
		if inner[0] != byte(ipv4.ICMPTypeEcho) {
			return false
		}
	} else {
		if len(b) < 48 || b[0]>>4 != 6 || b[6] != protoICMPv6 {
			return false
		}
		dst = netip.AddrFrom16([16]byte(b[24:40]))
		inner = b[40:]
		if inner[0] != byte(ipv6.ICMPTypeEchoRequest) {
			return false
		}
	}
	return dst == s.dst &&
		binary.BigEndian.Uint16(inner[4:6]) == s.id &&
		binary.BigEndian.Uint16(inner[6:8]) == seq
}

// ctxDone is ctx.Err, except that a context whose deadline has passed counts as
// done even before its timer fires. The socket's read deadline is the
// context's deadline, so a read can time out an instant before ctx.Err
// reports it, and the probe must not send another packet in that gap.
func ctxDone(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if dl, ok := ctx.Deadline(); ok && !time.Now().Before(dl) {
		return context.DeadlineExceeded
	}
	return nil
}

func addrOf(a net.Addr) netip.Addr {
	var ip net.IP
	switch v := a.(type) {
	case *net.IPAddr:
		ip = v.IP
	case *net.UDPAddr:
		ip = v.IP
	default:
		return netip.Addr{}
	}
	out, _ := netip.AddrFromSlice(ip)
	return out.Unmap()
}

// Ping sends opts.Count echo requests from src to dst, one at a time, each
// waiting up to opts.Wait for its reply.
func (p *Prober) Ping(ctx context.Context, src, dst netip.Addr, opts Options) (*fabricv1.PingResult, error) {
	opts = opts.clamped()
	s, err := p.open(src, dst, opts)
	if err != nil {
		return nil, err
	}
	defer func() { _ = s.conn.Close() }()

	res := &fabricv1.PingResult{Source: src.String(), Destination: dst.String()}
	var minRTT, maxRTT, sum time.Duration
	for range opts.Count {
		if ctxDone(ctx) != nil {
			break
		}
		seq, sent, err := s.send(ctx, opts.Limiter, 64)
		if err != nil {
			if ctxDone(ctx) != nil {
				break
			}
			return nil, err
		}
		res.Sent++
		r, ok, err := s.await(ctx, seq, opts.Wait)
		if err != nil && ctxDone(ctx) == nil {
			return nil, err
		}
		pr := &fabricv1.ProbeReply{Sequence: uint32(seq), Timeout: !ok}
		if ok {
			rtt := r.received.Sub(sent)
			pr.Address, pr.IcmpType, pr.IcmpCode, pr.Rtt = r.from.String(), r.typ, uint32(r.code), durationpb.New(rtt)
			if r.typ == TypeEchoReply {
				res.Received++
				sum += rtt
				if minRTT == 0 || rtt < minRTT {
					minRTT = rtt
				}
				maxRTT = max(maxRTT, rtt)
			}
		}
		res.Replies = append(res.Replies, pr)
	}
	if res.Received > 0 {
		res.RttMin, res.RttMax = durationpb.New(minRTT), durationpb.New(maxRTT)
		res.RttAvg = durationpb.New(sum / time.Duration(res.Received))
	}
	return res, nil
}

// Traceroute sends one echo request per hop with increasing hop limit until
// the destination answers, a router reports it unreachable, opts.MaxHops is
// reached, or ctx ends.
func (p *Prober) Traceroute(
	ctx context.Context, src, dst netip.Addr, opts Options,
) (*fabricv1.TracerouteResult, error) {
	opts = opts.clamped()
	s, err := p.open(src, dst, opts)
	if err != nil {
		return nil, err
	}
	defer func() { _ = s.conn.Close() }()

	res := &fabricv1.TracerouteResult{Source: src.String(), Destination: dst.String()}
	for ttl := 1; ttl <= opts.MaxHops && ctxDone(ctx) == nil; ttl++ {
		hop := &fabricv1.Hop{Ttl: uint32(ttl)}
		done := false
		for range query.TracerouteProbesPerHop {
			seq, sent, err := s.send(ctx, opts.Limiter, ttl)
			if err != nil {
				if ctxDone(ctx) != nil {
					break
				}
				return nil, err
			}
			r, ok, err := s.await(ctx, seq, opts.Wait)
			if err != nil && ctxDone(ctx) == nil {
				return nil, err
			}
			pr := &fabricv1.ProbeReply{Sequence: uint32(seq), Timeout: !ok}
			if ok {
				pr.Address, pr.IcmpType, pr.IcmpCode = r.from.String(), r.typ, uint32(r.code)
				pr.Rtt = durationpb.New(r.received.Sub(sent))
				switch {
				case r.typ == TypeEchoReply:
					res.Reached, done = true, true
				case r.typ != TypeTimeExceeded:
					// Unreachable, too big or a parameter problem ends
					// the walk: later hops would answer the same.
					done = true
				}
			}
			hop.Probes = append(hop.Probes, pr)
		}
		if len(hop.Probes) > 0 {
			res.Hops = append(res.Hops, hop)
		}
		if done {
			break
		}
	}
	return res, nil
}
