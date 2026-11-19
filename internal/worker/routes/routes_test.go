// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package routes

import (
	"net/netip"
	"slices"
	"testing"
	"time"
)

var (
	p1   = netip.MustParsePrefix("2001:db8:a::1/128")
	p64  = netip.MustParsePrefix("2001:db8:a::/64")
	sid1 = netip.MustParseAddr("2001:db8:0:2:e000:1::")
	sid2 = netip.MustParseAddr("2001:db8:0:3:e000:1::")
)

func TestApplyAndWithdraw(t *testing.T) {
	tab := New()
	r1 := Route{Key: Key{VPC: "a", Prefix: p1}, TableID: 10, SID: sid1}
	if got := tab.Apply([]Route{r1, {Key: Key{VPC: "b", Prefix: p1}, TableID: 20, SID: sid2}}, nil); !slices.Equal(
		got, []string{"a", "b"}) {
		t.Fatalf("changed = %v", got)
	}
	if got := tab.Apply([]Route{r1}, nil); len(got) != 0 {
		t.Errorf("repeating an upsert changed %v", got)
	}
	if got := tab.Apply(nil, []Key{{VPC: "a", Prefix: p1}}); !slices.Equal(got, []string{"a"}) {
		t.Fatalf("changed = %v", got)
	}
	if len(tab.Routes("a")) != 0 || len(tab.Routes("b")) != 1 {
		t.Fatalf("routes a=%v b=%v", tab.Routes("a"), tab.Routes("b"))
	}
	w := tab.Withdrawn("a")
	if len(w) != 1 || w[0].Route != r1 || w[0].Removed {
		t.Fatalf("withdrawn = %+v, want r1 unconfirmed", w)
	}
	if !tab.HasWork("a") {
		t.Error("an unconfirmed withdrawal is no work")
	}
	tab.ConfirmRemoved([]Route{r1})
	if tab.HasWork("a") || !tab.Withdrawn("a")[0].Removed {
		t.Error("confirmed withdrawal still pending")
	}
	if _, _, w, ok := tab.Covering("a", p1.Addr()); !ok || !w.Removed {
		t.Error("confirmed withdrawal not reported as covering")
	}

	// An upsert clears the withdrawal.
	tab.Apply([]Route{r1}, nil)
	if len(tab.Withdrawn("a")) != 0 {
		t.Error("upsert kept the withdrawal")
	}
}

func TestWithdrawalOfAnUnknownRouteHasNoSID(t *testing.T) {
	tab := New()
	tab.Apply(nil, []Key{{VPC: "a", Prefix: p1}})
	w := tab.Withdrawn("a")
	if len(w) != 1 || w[0].SID.IsValid() || w[0].TableID != 0 {
		t.Fatalf("withdrawn = %+v, want one with no SID or table", w)
	}
}

func TestConfirmIgnoresAReplacedWithdrawal(t *testing.T) {
	tab := New()
	r1 := Route{Key: Key{VPC: "a", Prefix: p1}, TableID: 10, SID: sid1}
	tab.Apply([]Route{r1}, nil)
	tab.Apply(nil, []Key{r1.Key})
	// Re-learned toward another SID and withdrawn again before the first
	// removal is confirmed.
	r2 := r1
	r2.SID = sid2
	tab.Apply([]Route{r2}, []Key{r2.Key})
	tab.ConfirmRemoved([]Route{r1})
	if w := tab.Withdrawn("a"); len(w) != 1 || w[0].Removed || w[0].SID != sid2 {
		t.Fatalf("withdrawn = %+v, want the second withdrawal unconfirmed", w)
	}
}

func TestCoveringIsLongestMatch(t *testing.T) {
	tab := New()
	tab.Apply([]Route{
		{Key: Key{VPC: "a", Prefix: p64}, TableID: 10, SID: sid1},
		{Key: Key{VPC: "a", Prefix: p1}, TableID: 10, SID: sid2},
	}, nil)
	r, ok, _, _ := tab.Covering("a", p1.Addr())
	if !ok || r.SID != sid2 {
		t.Errorf("Covering(%s) = %+v, want the /128", p1.Addr(), r)
	}
	r, ok, _, _ = tab.Covering("a", netip.MustParseAddr("2001:db8:a::9"))
	if !ok || r.SID != sid1 {
		t.Errorf("Covering(::9) = %+v, want the /64", r)
	}
	if _, ok, _, _ := tab.Covering("b", p1.Addr()); ok {
		t.Error("route of VPC a covers VPC b")
	}
}

func TestConfirmedWithdrawalsExpire(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	tab := New()
	tab.now = func() time.Time { return now }
	r1 := Route{Key: Key{VPC: "a", Prefix: p1}, TableID: 10, SID: sid1}
	tab.Apply([]Route{r1}, []Key{r1.Key})
	tab.ConfirmRemoved([]Route{r1})
	now = now.Add(removedRetention + time.Second)
	tab.Apply(nil, nil)
	if w := tab.Withdrawn("a"); len(w) != 0 {
		t.Fatalf("withdrawn = %+v, want the expired one dropped", w)
	}
}
