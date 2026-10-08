// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// fakeNet answers probes like a path of routers: a packet whose hop limit is
// below len(routers)+1 gets a time-exceeded from routers[hop-1]; otherwise
// the destination answers, unless silent or unreachable is set. It also
// injects noise ahead of every real answer: a foreign echo reply, a
// time-exceeded quoting someone else's probe, and garbage.
type fakeNet struct {
	mu          sync.Mutex
	dst         netip.Addr
	routers     []netip.Addr
	silentHops  map[int]bool
	silent      bool
	unreachable bool
	hop         int
	queue       []packet
	deadline    time.Time
	closed      bool
	sent        int
}

type packet struct {
	b    []byte
	from netip.Addr
}

func (f *fakeNet) proto() int {
	if f.dst.Is4() {
		return protoICMP
	}
	return protoICMPv6
}

func (f *fakeNet) SetHopLimit(n int) error { f.mu.Lock(); f.hop = n; f.mu.Unlock(); return nil }
func (f *fakeNet) Close() error            { f.closed = true; return nil }
func (f *fakeNet) SetReadDeadline(t time.Time) error {
	f.mu.Lock()
	f.deadline = t
	f.mu.Unlock()
	return nil
}

func (f *fakeNet) WriteTo(b []byte, dst net.Addr) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent++
	msg, err := icmp.ParseMessage(f.proto(), b)
	if err != nil {
		return 0, err
	}
	echo := msg.Body.(*icmp.Echo)
	quote := f.quote(echo.ID, echo.Seq)

	// Noise first.
	f.queue = append(f.queue,
		packet{b: f.marshal(f.echoReplyType(), &icmp.Echo{ID: echo.ID + 1, Seq: echo.Seq}), from: f.dst},
		packet{b: f.marshal(f.timeExceededType(), &icmp.TimeExceeded{Data: f.quote(echo.ID, echo.Seq+100)}),
			from: netip.MustParseAddr("192.0.2.200")},
		packet{b: []byte{0xff, 0x01}, from: f.dst},
	)

	switch {
	case f.hop <= len(f.routers):
		if !f.silentHops[f.hop] {
			f.queue = append(f.queue, packet{
				b: f.marshal(f.timeExceededType(), &icmp.TimeExceeded{Data: quote}), from: f.routers[f.hop-1]})
		}
	case f.unreachable:
		f.queue = append(f.queue, packet{
			b: f.marshal(f.unreachType(), &icmp.DstUnreach{Data: quote}), from: f.routers[len(f.routers)-1]})
	case !f.silent:
		r := packet{b: f.marshal(f.echoReplyType(), &icmp.Echo{ID: echo.ID, Seq: echo.Seq, Data: echo.Data}), from: f.dst}
		// The reply, then a duplicate of it.
		f.queue = append(f.queue, r, r)
	}
	_ = dst
	return len(b), nil
}

func (f *fakeNet) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		f.mu.Lock()
		if len(f.queue) > 0 {
			p := f.queue[0]
			f.queue = f.queue[1:]
			f.mu.Unlock()
			return copy(b, p.b), &net.IPAddr{IP: p.from.AsSlice()}, nil
		}
		dl := f.deadline
		f.mu.Unlock()
		if !dl.IsZero() && time.Now().After(dl) {
			return 0, nil, os.ErrDeadlineExceeded
		}
		time.Sleep(time.Millisecond)
	}
}

func (f *fakeNet) echoReplyType() icmp.Type {
	if f.dst.Is4() {
		return ipv4.ICMPTypeEchoReply
	}
	return ipv6.ICMPTypeEchoReply
}

func (f *fakeNet) timeExceededType() icmp.Type {
	if f.dst.Is4() {
		return ipv4.ICMPTypeTimeExceeded
	}
	return ipv6.ICMPTypeTimeExceeded
}

func (f *fakeNet) unreachType() icmp.Type {
	if f.dst.Is4() {
		return ipv4.ICMPTypeDestinationUnreachable
	}
	return ipv6.ICMPTypeDestinationUnreachable
}

func (f *fakeNet) marshal(t icmp.Type, body icmp.MessageBody) []byte {
	b, err := (&icmp.Message{Type: t, Body: body}).Marshal(nil)
	if err != nil {
		panic(err)
	}
	return b
}

// quote builds the IP header and first 8 bytes of an echo request to dst, as
// an ICMP error quotes it.
func (f *fakeNet) quote(id, seq int) []byte {
	echo := make([]byte, 8)
	if f.dst.Is4() {
		echo[0] = byte(ipv4.ICMPTypeEcho)
		binary.BigEndian.PutUint16(echo[4:], uint16(id))
		binary.BigEndian.PutUint16(echo[6:], uint16(seq))
		h := make([]byte, 20, 20+len(echo))
		h[0] = 0x45
		h[9] = protoICMP
		d := f.dst.As4()
		copy(h[16:], d[:])
		return append(h, echo...)
	}
	echo[0] = byte(ipv6.ICMPTypeEchoRequest)
	binary.BigEndian.PutUint16(echo[4:], uint16(id))
	binary.BigEndian.PutUint16(echo[6:], uint16(seq))
	h := make([]byte, 40, 40+len(echo))
	h[0] = 0x60
	h[6] = protoICMPv6
	d := f.dst.As16()
	copy(h[24:], d[:])
	return append(h, echo...)
}

func proberFor(f *fakeNet) *Prober {
	return &Prober{Dial: func(netip.Addr) (Conn, error) { return f, nil }}
}

var (
	src4 = netip.MustParseAddr("10.255.0.1")
	dst4 = netip.MustParseAddr("1.1.1.1")
	src6 = netip.MustParseAddr("2001:db8:ff::1")
	dst6 = netip.MustParseAddr("2606:4700::1111")
)

func TestPing(t *testing.T) {
	for _, tc := range []struct{ src, dst netip.Addr }{{src4, dst4}, {src6, dst6}} {
		f := &fakeNet{dst: tc.dst}
		res, err := proberFor(f).Ping(context.Background(), tc.src, tc.dst, Options{Wait: 200 * time.Millisecond})
		if err != nil {
			t.Fatal(err)
		}
		if res.Sent != 3 || res.Received != 3 || len(res.Replies) != 3 || res.RttAvg == nil {
			t.Fatalf("%s: result = %+v", tc.dst, res)
		}
		for _, r := range res.Replies {
			if r.Timeout || r.Address != tc.dst.String() || r.IcmpType != TypeEchoReply {
				t.Errorf("%s: reply = %+v", tc.dst, r)
			}
		}
		if !f.closed {
			t.Error("socket not closed")
		}
	}
}

func TestPingLossIsData(t *testing.T) {
	f := &fakeNet{dst: dst4, silent: true}
	start := time.Now()
	res, err := proberFor(f).Ping(context.Background(), src4, dst4, Options{Wait: 30 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if res.Sent != 3 || res.Received != 0 || res.RttAvg != nil || !res.Replies[0].Timeout {
		t.Fatalf("result = %+v", res)
	}
	if time.Since(start) > time.Second {
		t.Errorf("took %v", time.Since(start))
	}
}

func TestPingClampsCount(t *testing.T) {
	f := &fakeNet{dst: dst4}
	res, err := proberFor(f).Ping(context.Background(), src4, dst4, Options{Count: 1000, Wait: 10 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if res.Sent != 3 || f.sent != 3 {
		t.Fatalf("sent %d / %d, want the ceiling of 3", res.Sent, f.sent)
	}
}

func TestPingCancel(t *testing.T) {
	f := &fakeNet{dst: dst4, silent: true}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	start := time.Now()
	res, err := proberFor(f).Ping(ctx, src4, dst4, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if time.Since(start) > 500*time.Millisecond || res.Sent > 1 {
		t.Fatalf("cancel took %v and sent %d", time.Since(start), res.Sent)
	}
}

func TestTraceroute(t *testing.T) {
	routers4 := []netip.Addr{
		netip.MustParseAddr("10.1.11.1"), netip.MustParseAddr("203.0.113.1"), netip.MustParseAddr("198.51.100.1"),
	}
	routers6 := []netip.Addr{netip.MustParseAddr("2001:db8:1::1"), netip.MustParseAddr("2001:db8:2::1")}
	for _, tc := range []struct {
		src, dst netip.Addr
		routers  []netip.Addr
	}{{src4, dst4, routers4}, {src6, dst6, routers6}} {
		f := &fakeNet{dst: tc.dst, routers: tc.routers, silentHops: map[int]bool{2: true}}
		res, err := proberFor(f).Traceroute(context.Background(), tc.src, tc.dst, Options{Wait: 30 * time.Millisecond})
		if err != nil {
			t.Fatal(err)
		}
		if !res.Reached || len(res.Hops) != len(tc.routers)+1 {
			t.Fatalf("%s: result = %+v", tc.dst, res)
		}
		for i, h := range res.Hops {
			p := h.Probes[0]
			switch {
			case i == 1:
				if !p.Timeout {
					t.Errorf("hop 2 should time out: %+v", p)
				}
			case i < len(tc.routers):
				if p.Address != tc.routers[i].String() || p.IcmpType != TypeTimeExceeded {
					t.Errorf("hop %d = %+v", i+1, p)
				}
			default:
				if p.Address != tc.dst.String() || p.IcmpType != TypeEchoReply {
					t.Errorf("last hop = %+v", p)
				}
			}
		}
	}
}

func TestTracerouteUnreachableStops(t *testing.T) {
	f := &fakeNet{dst: dst4, routers: []netip.Addr{netip.MustParseAddr("10.1.11.1")}, unreachable: true}
	res, err := proberFor(f).Traceroute(context.Background(), src4, dst4, Options{Wait: 30 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if res.Reached || len(res.Hops) != 2 || res.Hops[1].Probes[0].IcmpType != TypeUnreachable {
		t.Fatalf("result = %+v", res)
	}
}

func TestTracerouteMaxHops(t *testing.T) {
	f := &fakeNet{dst: dst4, silent: true}
	res, err := proberFor(f).Traceroute(context.Background(), src4, dst4, Options{MaxHops: 4, Wait: 5 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if res.Reached || len(res.Hops) != 4 {
		t.Fatalf("hops = %d", len(res.Hops))
	}
}

func TestSourceUnavailable(t *testing.T) {
	p := &Prober{Dial: func(netip.Addr) (Conn, error) { return nil, errors.New("cannot assign requested address") }}
	_, err := p.Ping(context.Background(), src4, dst4, Options{})
	if e, ok := errors.AsType[*Error](err); !ok || e.Code != CodeSourceUnavailable {
		t.Fatalf("err = %v", err)
	}
	// No source of the destination's family.
	_, err = proberFor(&fakeNet{dst: dst6}).Ping(context.Background(), src4, dst6, Options{})
	if e, ok := errors.AsType[*Error](err); !ok || e.Code != CodeSourceUnavailable {
		t.Fatalf("family mismatch err = %v", err)
	}
	_, err = proberFor(&fakeNet{dst: dst6}).Ping(context.Background(), netip.Addr{}, dst6, Options{})
	if e, ok := errors.AsType[*Error](err); !ok || e.Code != CodeSourceUnavailable {
		t.Fatalf("no source err = %v", err)
	}
}

type countLimiter struct{ n int }

func (c *countLimiter) Wait(context.Context) error { c.n++; return nil }

func TestLimiterPacesEveryPacket(t *testing.T) {
	lim := &countLimiter{}
	f := &fakeNet{dst: dst4, routers: []netip.Addr{netip.MustParseAddr("10.1.11.1")}}
	opts := Options{Wait: 10 * time.Millisecond, Limiter: lim}
	if _, err := proberFor(f).Traceroute(context.Background(), src4, dst4, opts); err != nil {
		t.Fatal(err)
	}
	if lim.n != f.sent || lim.n != 2 {
		t.Fatalf("limiter saw %d packets, sent %d", lim.n, f.sent)
	}
}
