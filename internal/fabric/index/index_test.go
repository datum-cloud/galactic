// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package index

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/osrg/gobgp/v4/pkg/packet/bmp"

	"go.datum.net/galactic/internal/fabric/frr"
	"go.datum.net/galactic/internal/fabric/query"
)

func mustQ(t *testing.T, q query.Query) query.Query {
	t.Helper()
	c, err := query.Canonicalize(q)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// update builds a Loc-RIB BGP UPDATE announcing prefixes with the given AS
// path segments and communities.
func update(t *testing.T, prefixes []string, segs []bgp.AsPathParamInterface, communities []uint32,
	large []*bgp.LargeCommunity) *bgp.BGPMessage {
	t.Helper()
	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_IGP),
		bgp.NewPathAttributeAsPath(segs),
	}
	if len(communities) > 0 {
		attrs = append(attrs, bgp.NewPathAttributeCommunities(communities))
	}
	if len(large) > 0 {
		attrs = append(attrs, bgp.NewPathAttributeLargeCommunities(large))
	}
	var v4, v6 []bgp.PathNLRI
	for _, s := range prefixes {
		p := netip.MustParsePrefix(s)
		n, err := bgp.NewIPAddrPrefix(p)
		if err != nil {
			t.Fatal(err)
		}
		if p.Addr().Is4() {
			v4 = append(v4, bgp.PathNLRI{NLRI: n})
		} else {
			v6 = append(v6, bgp.PathNLRI{NLRI: n})
		}
	}
	if len(v4) > 0 {
		nh, _ := bgp.NewPathAttributeNextHop(netip.MustParseAddr("10.1.11.1"))
		attrs = append(attrs, nh)
	}
	if len(v6) > 0 {
		mp, err := bgp.NewPathAttributeMpReachNLRI(bgp.RF_IPv6_UC, v6, netip.MustParseAddr("2001:db8:1:11::1"))
		if err != nil {
			t.Fatal(err)
		}
		attrs = append(attrs, mp)
	}
	return bgp.NewBGPUpdateMessage(nil, attrs, v4)
}

func seq(asns ...uint32) bgp.AsPathParamInterface {
	return bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, asns)
}

func set(asns ...uint32) bgp.AsPathParamInterface {
	return bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SET, asns)
}

func withdraw(t *testing.T, prefix string) *bgp.BGPMessage {
	t.Helper()
	p := netip.MustParsePrefix(prefix)
	n, _ := bgp.NewIPAddrPrefix(p)
	if p.Addr().Is4() {
		return bgp.NewBGPUpdateMessage([]bgp.PathNLRI{{NLRI: n}}, nil, nil)
	}
	mp, err := bgp.NewPathAttributeMpUnreachNLRI(bgp.RF_IPv6_UC, []bgp.PathNLRI{{NLRI: n}})
	if err != nil {
		t.Fatal(err)
	}
	return bgp.NewBGPUpdateMessage(nil, []bgp.PathAttributeInterface{mp}, nil)
}

func eor(t *testing.T, ipv4 bool) *bgp.BGPMessage {
	t.Helper()
	if ipv4 {
		return bgp.NewBGPUpdateMessage(nil, nil, nil)
	}
	mp, err := bgp.NewPathAttributeMpUnreachNLRI(bgp.RF_IPv6_UC, nil)
	if err != nil {
		t.Fatal(err)
	}
	return bgp.NewBGPUpdateMessage(nil, []bgp.PathAttributeInterface{mp}, nil)
}

// locRIB wraps an UPDATE as a Loc-RIB route monitoring message.
func locRIB(t *testing.T, u *bgp.BGPMessage) []byte {
	t.Helper()
	ph := bmp.NewBMPPeerHeader(bmp.BMP_PEER_TYPE_LOCAL_RIB, 0, 0, netip.IPv4Unspecified(), 65000,
		netip.MustParseAddr("10.255.255.2"), 0)
	b, err := bmp.NewBMPRouteMonitoring(*ph, u).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

const (
	cloudflare = "_13335$"
	oneZero    = "1.0.0.0/24"
)

// searchFixture is a synced index holding a handful of IPv4 and IPv6 routes.
func searchFixture(t *testing.T) *Index {
	t.Helper()
	ix := New()
	ix.BeginSession()
	for _, u := range []*bgp.BGPMessage{
		update(t, []string{"1.1.1.0/24", oneZero}, []bgp.AsPathParamInterface{seq(174, 13335)},
			[]uint32{174<<16 | 21000}, nil),
		update(t, []string{"8.8.8.0/24"}, []bgp.AsPathParamInterface{seq(3356, 15169)}, []uint32{0xFFFFFF01},
			[]*bgp.LargeCommunity{{ASN: 6695, LocalData1: 1000, LocalData2: 1}}),
		update(t, []string{"198.51.0.0/16"}, []bgp.AsPathParamInterface{seq(64500), set(64501, 64502)}, nil, nil),
		update(t, []string{"2606:4700::/32"}, []bgp.AsPathParamInterface{seq(174, 13335)}, nil, nil),
	} {
		ApplyUpdate(ix, u.Body.(*bgp.BGPUpdate))
	}
	_, err := ix.Search(mustQ(t, query.Query{Type: query.TypeASPath, Target: cloudflare}), 10)
	if !errors.Is(err, ErrNotSynced) {
		t.Fatalf("search before End-of-RIB: %v", err)
	}
	ix.EndOfRIB(true)
	ix.EndOfRIB(false)
	return ix
}

func TestApplyAndSearch(t *testing.T) {
	ix := searchFixture(t)

	res, err := ix.Search(mustQ(t, query.Query{Type: query.TypeASPath, Target: cloudflare}), 10)
	if err != nil {
		t.Fatal(err)
	}
	if res.Matched != 2 || len(res.Routes) != 2 || res.Routes[0].Prefix != oneZero ||
		res.Routes[1].Prefix != "1.1.1.0/24" {
		t.Fatalf("IPv4 _13335$ = %d %+v", res.Matched, res.Routes)
	}
	p := res.Routes[0].Paths[0]
	if p.ASPath.String != "174 13335" || p.OriginASN != 13335 || !p.Best || p.Origin != "IGP" ||
		p.Communities[0] != "174:21000" || p.NextHops[0].Address != "10.1.11.1" {
		t.Errorf("path = %+v", p)
	}
	v6, err := ix.Search(mustQ(t, query.Query{Type: query.TypeASPath, Target: cloudflare, AddressFamily: query.IPv6}), 10)
	if err != nil || v6.Matched != 1 || v6.Routes[0].Paths[0].NextHops[0].Address != "2001:db8:1:11::1" {
		t.Fatalf("IPv6 = %+v, %v", v6, err)
	}

	// The limit keeps the first prefixes and the exact total.
	lim, _ := ix.Search(mustQ(t, query.Query{Type: query.TypeASPath, Target: cloudflare}), 1)
	if lim.Matched != 2 || len(lim.Routes) != 1 || lim.Routes[0].Prefix != oneZero {
		t.Errorf("limited = %d %+v", lim.Matched, lim.Routes)
	}

	set, _ := ix.Search(mustQ(t, query.Query{Type: query.TypeASPath, Target: "_64502_"}), 10)
	if set.Matched != 1 || set.Routes[0].Paths[0].ASPath.String != "64500 {64501,64502}" ||
		set.Routes[0].Paths[0].OriginASN != 0 {
		t.Errorf("AS_SET = %+v", set.Routes)
	}

	for _, tc := range []struct {
		q    query.Query
		want int
	}{
		{query.Query{Type: query.TypeCommunity, Target: "174:21000"}, 2},
		{query.Query{Type: query.TypeCommunity, Target: communityNoExport}, 1},
		{query.Query{Type: query.TypeCommunity, Target: "1:1"}, 0},
		{query.Query{Type: query.TypeLargeCommunity, Target: "6695:1000:1"}, 1},
		{query.Query{Type: query.TypeASPath, Target: "^174_"}, 2},
		{query.Query{Type: query.TypeASPath, Target: "^$"}, 0},
	} {
		r, err := ix.Search(mustQ(t, tc.q), 10)
		if err != nil || r.Matched != tc.want {
			t.Errorf("%+v: matched %d, %v; want %d", tc.q, r.Matched, err, tc.want)
		}
	}
	r, _ := ix.Search(mustQ(t, query.Query{Type: query.TypeCommunity, Target: communityNoExport}), 10)
	if r.Routes[0].Paths[0].Communities[0] != "noExport" {
		t.Errorf("well-known community rendering = %v", r.Routes[0].Paths[0].Communities)
	}

}

func TestWithdrawReleasesAttributes(t *testing.T) {
	ix := searchFixture(t)
	// Withdrawals and attribute interning.
	_, _, attrsBefore, _ := ix.Stats()
	ApplyUpdate(ix, withdraw(t, "8.8.8.0/24").Body.(*bgp.BGPUpdate))
	ApplyUpdate(ix, withdraw(t, "2606:4700::/32").Body.(*bgp.BGPUpdate))
	v4n, v6n, attrsAfter, _ := ix.Stats()
	if v4n != 3 || v6n != 0 || attrsAfter != attrsBefore-2 {
		t.Errorf("after withdrawals: v4=%d v6=%d attrs %d -> %d", v4n, v6n, attrsBefore, attrsAfter)
	}
	if st := ix.State(); st.Version == 0 || st.Routes != 3 || !st.Synced {
		t.Errorf("state = %+v", st)
	}
}

func TestMaxRoutes(t *testing.T) {
	ix := New()
	ix.MaxRoutes = 2
	ix.BeginSession()
	ApplyUpdate(ix, update(t, []string{"10.0.0.0/8", "11.0.0.0/8", "12.0.0.0/8"},
		[]bgp.AsPathParamInterface{seq(1)}, nil, nil).Body.(*bgp.BGPUpdate))
	v4, _, _, overflow := ix.Stats()
	if v4 != 2 || overflow != 1 {
		t.Errorf("v4=%d overflow=%d", v4, overflow)
	}
}

func TestStation(t *testing.T) {
	ix := New()
	l, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	applied := 0
	st := &Station{Addr: addr, Index: ix, OnMessage: func() { applied++ }}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go func() { _ = st.Run(ctx) }()

	var conn net.Conn
	for range 100 {
		if conn, err = (&net.Dialer{}).DialContext(ctx, "tcp", addr); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if conn == nil {
		t.Fatal(err)
	}
	send := func(b []byte) {
		if _, err := conn.Write(b); err != nil {
			t.Fatal(err)
		}
	}
	// A second session is refused while the first is up.
	waitFor(t, func() bool { return ix.State().Connected })
	second, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	if err == nil {
		_ = second.SetReadDeadline(time.Now().Add(time.Second))
		if _, err := second.Read(make([]byte, 1)); err == nil {
			t.Error("second BMP session was not closed")
		}
		_ = second.Close()
	}

	for i := range 50 {
		send(locRIB(t, update(t, []string{fmt.Sprintf("10.%d.0.0/16", i)},
			[]bgp.AsPathParamInterface{seq(64500, uint32(64600+i))}, nil, nil)))
	}
	send(locRIB(t, update(t, []string{"2001:db8::/32"}, []bgp.AsPathParamInterface{seq(64500)}, nil, nil)))
	send(locRIB(t, eor(t, true)))
	send(locRIB(t, eor(t, false)))
	waitFor(t, func() bool { return ix.State().Synced })
	if st := ix.State(); st.Routes != 51 || applied != 51 {
		t.Fatalf("state = %+v applied = %d", st, applied)
	}
	res, err := ix.Search(mustQ(t, query.Query{Type: query.TypeASPath, Target: "_64649$"}), 10)
	if err != nil || res.Matched != 1 || res.Routes[0].Prefix != "10.49.0.0/16" {
		t.Fatalf("search = %+v, %v", res, err)
	}

	// Losing the session makes searches unavailable rather than stale.
	_ = conn.Close()
	waitFor(t, func() bool { return !ix.State().Connected })
	_, err = ix.Search(mustQ(t, query.Query{Type: query.TypeASPath, Target: "_64649$"}), 10)
	if !errors.Is(err, ErrNotSynced) {
		t.Errorf("after session loss: %v", err)
	}
}

func TestSettler(t *testing.T) {
	st := newSettler(5*time.Second, 50)
	base := time.Unix(1_000_000, 0)
	if st.settled(base) {
		t.Fatal("settled before any route")
	}
	// A dump of 100k routes per second for three seconds.
	for sec := range 3 {
		for range 100_000 {
			st.add(base.Add(time.Duration(sec) * time.Second))
		}
	}
	if st.settled(base.Add(3 * time.Second)) {
		t.Fatal("settled during the dump")
	}
	// Then steady churn of 200 per second: above the 50/s floor but under
	// 1% of the peak, so it settles once the dump leaves the window.
	for sec := 3; sec < 12; sec++ {
		for range 200 {
			st.add(base.Add(time.Duration(sec) * time.Second))
		}
	}
	if st.settled(base.Add(5 * time.Second)) {
		t.Error("settled while the dump is still in the window")
	}
	if !st.settled(base.Add(9 * time.Second)) {
		t.Error("did not settle under low churn")
	}
}

func TestStationSettlesWithoutEndOfRIB(t *testing.T) {
	ix := New()
	l, _ := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	addr := l.Addr().String()
	_ = l.Close()
	st := &Station{Addr: addr, Index: ix, SettleWindow: time.Second}
	go func() { _ = st.Run(t.Context()) }()
	var conn net.Conn
	var err error
	for range 100 {
		if conn, err = (&net.Dialer{}).DialContext(t.Context(), "tcp", addr); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if conn == nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	msg := locRIB(t, update(t, []string{"10.0.0.0/8"}, []bgp.AsPathParamInterface{seq(1)}, nil, nil))
	if _, err := conn.Write(msg); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return ix.State().Synced })
}

func TestCommunityValue(t *testing.T) {
	for in, want := range map[string]uint32{
		communityNoExport: 0xFFFFFF01, "65001:100": 65001<<16 | 100, communityBlackhole: 0xFFFF029A,
	} {
		got, err := communityValue(in)
		if err != nil || got != want {
			t.Errorf("%s = %x, %v", in, got, err)
		}
	}
	if CommunityString(65001<<16|100) != "65001:100" || CommunityString(0xFFFFFF02) != "noAdvertise" {
		t.Error("rendering")
	}
	_ = frr.Path{}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not reached")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
