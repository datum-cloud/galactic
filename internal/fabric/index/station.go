// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package index

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/osrg/gobgp/v4/pkg/packet/bmp"

	"go.datum.net/galactic/internal/fabric/frr"
)

// DefaultStationAddress is where the station listens: the node's loopback,
// which bgpd reaches with `bmp connect 127.0.0.1 port 9348` in a
// `bmp targets` block monitoring ipv4 and ipv6 unicast loc-rib.
const DefaultStationAddress = "127.0.0.1:9348"

// maxBMPMessage bounds one BMP message; a BGP UPDATE with extended message
// support is at most 65535 bytes, plus BMP headers.
const maxBMPMessage = 1 << 17

// Station is a BMP (RFC 7854) station that feeds an Index from bgpd's Loc-RIB
// route monitoring (RFC 9069). It serves one session at a time, accepts only
// loopback peers, and ignores every other kind of message.
type Station struct {
	Addr  string
	Index *Index
	// SettleWindow and SettleRate decide when bgpd's initial table dump is
	// over. FRR 10.7 sends no End-of-RIB for Loc-RIB monitoring, so the
	// index counts as synced once the session has carried routes and the
	// update rate over the last SettleWindow has fallen to SettleRate per
	// second, or to 1% of the session's peak rate if that is higher. The
	// dump arrives orders of magnitude faster than steady churn, so this
	// holds under continuous churn, where a quiet period never comes. Zero
	// values select 5s and 50/s. An explicit End-of-RIB also syncs.
	SettleWindow time.Duration
	SettleRate   float64
	// OnMessage, when set, is called for each route monitoring message
	// applied; it backs the station's metrics.
	OnMessage func()

	mu     sync.Mutex
	active bool
}

// Run listens until ctx ends.
func (s *Station) Run(ctx context.Context) error {
	addr := s.Addr
	if addr == "" {
		addr = DefaultStationAddress
	}
	l, err := (&net.ListenConfig{}).Listen(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("listen for BMP on %s: %w", addr, err)
	}
	stop := context.AfterFunc(ctx, func() { _ = l.Close() })
	defer stop()
	slog.Info("BMP station listening for bgpd's Loc-RIB", "address", addr)
	for {
		c, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			slog.Warn("BMP accept failed", "error", err)
			continue
		}
		if !s.admit(c) {
			_ = c.Close()
			continue
		}
		go s.serve(ctx, c)
	}
}

// admit accepts one loopback session at a time.
func (s *Station) admit(c net.Conn) bool {
	ap, err := netip.ParseAddrPort(c.RemoteAddr().String())
	if err != nil || !ap.Addr().Unmap().IsLoopback() {
		slog.Warn("refusing BMP session from a non-loopback peer", "peer", c.RemoteAddr().String())
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active {
		slog.Warn("refusing a second BMP session", "peer", c.RemoteAddr().String())
		return false
	}
	s.active = true
	return true
}

func (s *Station) serve(ctx context.Context, c net.Conn) {
	defer func() {
		_ = c.Close()
		s.Index.EndSession()
		s.mu.Lock()
		s.active = false
		s.mu.Unlock()
		slog.Info("BMP session ended; search index unsynced until bgpd reconnects")
	}()
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	defer stop()
	s.Index.BeginSession()
	slog.Info("BMP session from bgpd; rebuilding the search index", "peer", c.RemoteAddr().String())

	msgs := make(chan []byte, 1024)
	readErr := make(chan error, 1)
	go func() {
		sc := bufio.NewScanner(c)
		sc.Buffer(make([]byte, 0, 1<<16), maxBMPMessage)
		sc.Split(bmp.SplitBMP)
		for sc.Scan() {
			msgs <- append([]byte(nil), sc.Bytes()...)
		}
		readErr <- sc.Err()
		close(msgs)
	}()

	window := s.SettleWindow
	if window <= 0 {
		window = 5 * time.Second
	}
	floor := s.SettleRate
	if floor <= 0 {
		floor = 50
	}
	settle := newSettler(window, floor)
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	synced := false
	for {
		select {
		case b, ok := <-msgs:
			if !ok {
				if err := <-readErr; err != nil && !errors.Is(err, net.ErrClosed) {
					slog.Warn("BMP session read failed", "error", err)
				}
				return
			}
			if s.apply(b) {
				settle.add(time.Now())
			}
		case now := <-tick.C:
			if !synced && settle.settled(now) {
				synced = true
				s.Index.EndOfRIB(true)
				s.Index.EndOfRIB(false)
				st := s.Index.State()
				slog.Info("search index synced with bgpd's Loc-RIB", "routes", st.Routes)
			}
		}
	}
}

// settler tracks a session's route update rate in one-second buckets.
type settler struct {
	window  time.Duration
	floor   float64
	buckets map[int64]int
	peak    float64
	seen    bool
}

func newSettler(window time.Duration, floor float64) *settler {
	return &settler{window: window, floor: floor, buckets: map[int64]int{}}
}

func (st *settler) add(now time.Time) {
	st.seen = true
	sec := now.Unix()
	st.buckets[sec]++
	st.peak = max(st.peak, float64(st.buckets[sec]))
}

// settled reports whether routes have been seen and the rate over the
// last window, excluding the current partial second, is at or below the
// threshold.
func (st *settler) settled(now time.Time) bool {
	cur := now.Unix()
	secs := int64(st.window / time.Second)
	total := 0
	for sec := range st.buckets {
		switch {
		case sec <= cur-secs-1:
			delete(st.buckets, sec)
		case sec < cur:
			total += st.buckets[sec]
		}
	}
	if !st.seen || st.peak == 0 {
		return false
	}
	return float64(total)/float64(secs) <= max(st.floor, st.peak/100)
}

// apply decodes one BMP message and applies its route updates, reporting
// whether it carried any.
func (s *Station) apply(b []byte) bool {
	msg, err := bmp.ParseBMPMessage(b)
	if err != nil {
		slog.Debug("undecodable BMP message", "error", err)
		return false
	}
	if msg.Header.Type != bmp.BMP_MSG_ROUTE_MONITORING {
		return false
	}
	rm, ok := msg.Body.(*bmp.BMPRouteMonitoring)
	if !ok || rm.BGPUpdate == nil {
		return false
	}
	u, ok := rm.BGPUpdate.Body.(*bgp.BGPUpdate)
	if !ok {
		return false
	}
	// The target monitors only Loc-RIB, so an End-of-RIB on this session is
	// Loc-RIB's, whatever peer header carries it.
	if eor, fam := u.IsEndOfRib(); eor {
		switch fam {
		case bgp.RF_IPv4_UC:
			s.Index.EndOfRIB(true)
		case bgp.RF_IPv6_UC:
			s.Index.EndOfRIB(false)
		}
		return false
	}
	if msg.PeerHeader.PeerType != bmp.BMP_PEER_TYPE_LOCAL_RIB {
		return false
	}
	ApplyUpdate(s.Index, u)
	if s.OnMessage != nil {
		s.OnMessage()
	}
	return true
}

// ApplyUpdate applies one BGP UPDATE from the Loc-RIB to ix.
func ApplyUpdate(ix *Index, u *bgp.BGPUpdate) {
	for _, w := range u.WithdrawnRoutes {
		if p, ok := prefixOf(w.NLRI); ok {
			ix.Withdraw(p)
		}
	}
	attrs := Attrs{}
	var reach []bgp.PathNLRI
	for _, pa := range u.PathAttributes {
		switch a := pa.(type) {
		case *bgp.PathAttributeOrigin:
			attrs.Origin = originName(a.Value)
		case *bgp.PathAttributeAsPath:
			attrs.ASPath, attrs.OriginASN = asPathOf(a)
		case *bgp.PathAttributeNextHop:
			attrs.NextHop = a.Value
		case *bgp.PathAttributeMultiExitDisc:
			v := a.Value
			attrs.MED = &v
		case *bgp.PathAttributeLocalPref:
			v := a.Value
			attrs.LocalPref = &v
		case *bgp.PathAttributeCommunities:
			attrs.Community = append([]uint32(nil), a.Value...)
		case *bgp.PathAttributeLargeCommunities:
			for _, l := range a.Values {
				attrs.Large = append(attrs.Large, LargeCommunity{l.ASN, l.LocalData1, l.LocalData2})
			}
		case *bgp.PathAttributeMpReachNLRI:
			attrs.NextHop = a.Nexthop
			reach = append(reach, a.Value...)
		case *bgp.PathAttributeMpUnreachNLRI:
			for _, w := range a.Value {
				if p, ok := prefixOf(w.NLRI); ok {
					ix.Withdraw(p)
				}
			}
		}
	}
	for _, n := range append(reach, u.NLRI...) {
		if p, ok := prefixOf(n.NLRI); ok {
			ix.Update(p, attrs)
		}
	}
}

func prefixOf(n bgp.NLRI) (netip.Prefix, bool) {
	if p, ok := n.(*bgp.IPAddrPrefix); ok && p.Prefix.IsValid() {
		return p.Prefix.Masked(), true
	}
	return netip.Prefix{}, false
}

func originName(v uint8) string {
	switch v {
	case bgp.BGP_ORIGIN_ATTR_TYPE_IGP:
		return originIGP
	case bgp.BGP_ORIGIN_ATTR_TYPE_EGP:
		return originEGP
	}
	return originIncomplete
}

// asPathOf converts an AS_PATH into segments, FRR's rendering of them and the
// origin ASN.
func asPathOf(a *bgp.PathAttributeAsPath) (frr.ASPath, uint32) {
	var out frr.ASPath
	var parts []string
	for _, p := range a.Value {
		seg := frr.ASSegment{ASNs: append([]uint32(nil), p.GetAS()...)}
		strs := make([]string, len(seg.ASNs))
		for i, n := range seg.ASNs {
			strs[i] = strconv.FormatUint(uint64(n), 10)
		}
		switch p.GetType() {
		case bgp.BGP_ASPATH_ATTR_TYPE_SET:
			seg.Type = frr.SegmentSet
			parts = append(parts, "{"+join(strs, ",")+"}")
		case bgp.BGP_ASPATH_ATTR_TYPE_CONFED_SEQ:
			seg.Type = frr.SegmentConfedSequence
			parts = append(parts, "("+join(strs, " ")+")")
		case bgp.BGP_ASPATH_ATTR_TYPE_CONFED_SET:
			seg.Type = frr.SegmentConfedSet
			parts = append(parts, "["+join(strs, ",")+"]")
		default:
			seg.Type = frr.SegmentSequence
			parts = append(parts, join(strs, " "))
		}
		out.Segments = append(out.Segments, seg)
	}
	out.String = join(parts, " ")
	return out, frr.OriginASN(out.Segments)
}

func join(ss []string, sep string) string {
	n := 0
	for _, s := range ss {
		n += len(s) + len(sep)
	}
	b := make([]byte, 0, n)
	for i, s := range ss {
		if i > 0 {
			b = append(b, sep...)
		}
		b = append(b, s...)
	}
	return string(b)
}
