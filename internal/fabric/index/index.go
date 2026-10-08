// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package index keeps a local copy of FRR's selected BGP routes so fabric-api
// can answer AS-path, community and large-community searches without asking
// bgpd to scan its table.
//
// A full-table load test (hack/fabric-api-loadtest) showed that answering
// those searches with FRR's own regexp/community commands pins bgpd's main
// thread and roughly triples convergence after a session reset. The index is
// fed instead by BMP Loc-RIB route monitoring (RFC 9069), which bgpd streams
// incrementally to a station on the node's loopback (see Station), and
// searches run in the sidecar against it. Until the index has the full table
// (End-of-RIB for both families), searches are refused rather than served
// from a partial table or from bgpd.
//
// The index holds each prefix's selected path only. Path attributes are
// interned and reference-counted, since a full table shares a few hundred
// thousand distinct attribute sets across about a million prefixes.
package index

import (
	"container/heap"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.datum.net/galactic/internal/fabric/frr"
	"go.datum.net/galactic/internal/fabric/query"
)

// Well-known community names in canonical queries.
const (
	communityNoExport  = "no-export"
	communityBlackhole = "blackhole"
)

// Origin attribute names, as FRR prints them.
const (
	originIGP        = "IGP"
	originEGP        = "EGP"
	originIncomplete = "incomplete"
)

// Attrs is one interned set of path attributes.
type Attrs struct {
	ASPath     frr.ASPath
	OriginASN  uint32
	Origin     string
	MED        *uint32
	LocalPref  *uint32
	Community  []uint32
	Large      []LargeCommunity
	NextHop    netip.Addr
	refs       int
	key        string
	matchEpoch uint64
	matched    bool
}

// LargeCommunity is one RFC 8092 large community.
type LargeCommunity struct {
	Global, Local1, Local2 uint32
}

func (l LargeCommunity) String() string {
	return fmt.Sprintf("%d:%d:%d", l.Global, l.Local1, l.Local2)
}

// key renders the attribute set as its interning key.
func (a *Attrs) computeKey() string {
	var b strings.Builder
	b.WriteString(a.ASPath.String)
	b.WriteByte('|')
	b.WriteString(a.Origin)
	b.WriteByte('|')
	if a.MED != nil {
		b.WriteString(strconv.FormatUint(uint64(*a.MED), 10))
	}
	b.WriteByte('|')
	if a.LocalPref != nil {
		b.WriteString(strconv.FormatUint(uint64(*a.LocalPref), 10))
	}
	b.WriteByte('|')
	for _, c := range a.Community {
		b.WriteString(strconv.FormatUint(uint64(c), 10))
		b.WriteByte(',')
	}
	b.WriteByte('|')
	for _, l := range a.Large {
		b.WriteString(l.String())
		b.WriteByte(',')
	}
	b.WriteByte('|')
	b.WriteString(a.NextHop.String())
	return b.String()
}

// State describes the index's freshness, reported with every search.
type State struct {
	// Synced is true once both families' initial table has been received.
	Synced bool
	// SyncedAt is when the current session's initial table completed.
	SyncedAt time.Time
	// LastUpdate is when the last route update was applied.
	LastUpdate time.Time
	// Version counts route updates applied since the index started; it
	// only grows.
	Version uint64
	// Routes is the number of prefixes held.
	Routes int
	// Connected is true while bgpd's BMP session is up.
	Connected bool
}

// families indexes the two unicast families.
const (
	famV4 = 0
	famV6 = 1
)

func famOf(p netip.Prefix) int {
	if p.Addr().Is4() {
		return famV4
	}
	return famV6
}

// Index is the route store. It is safe for concurrent use; searches are
// serialized with each other.
type Index struct {
	// MaxRoutes bounds the prefixes held across both families; updates for
	// new prefixes beyond it are dropped and counted, never silently
	// served as complete. Zero means unbounded.
	MaxRoutes int

	mu         sync.RWMutex
	routes     [2]map[netip.Prefix]*Attrs
	attrs      map[string]*Attrs
	eor        [2]bool
	connected  bool
	syncedAt   time.Time
	lastUpdate time.Time
	version    uint64
	overflow   uint64

	searchMu sync.Mutex
	epoch    uint64

	now func() time.Time
}

// New returns an empty, unsynced index.
func New() *Index {
	ix := &Index{now: time.Now}
	ix.reset()
	return ix
}

func (ix *Index) reset() {
	ix.routes = [2]map[netip.Prefix]*Attrs{{}, {}}
	ix.attrs = map[string]*Attrs{}
	ix.eor = [2]bool{}
	ix.syncedAt = time.Time{}
}

// BeginSession discards everything for a new BMP session, which resends the
// whole table.
func (ix *Index) BeginSession() {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	ix.reset()
	ix.connected = true
}

// EndSession marks the index unsynced: without the session it can no longer
// follow changes.
func (ix *Index) EndSession() {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	ix.connected = false
	ix.eor = [2]bool{}
	ix.syncedAt = time.Time{}
}

// Update replaces prefix's selected path with attrs.
func (ix *Index) Update(prefix netip.Prefix, attrs Attrs) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	f := famOf(prefix)
	old, existed := ix.routes[f][prefix]
	if !existed && ix.MaxRoutes > 0 && len(ix.routes[famV4])+len(ix.routes[famV6]) >= ix.MaxRoutes {
		ix.overflow++
		return
	}
	attrs.key = attrs.computeKey()
	a, ok := ix.attrs[attrs.key]
	if !ok {
		a = &attrs
		ix.attrs[a.key] = a
	}
	a.refs++
	ix.routes[f][prefix] = a
	if existed {
		ix.release(old)
	}
	ix.touch()
}

// Withdraw removes prefix.
func (ix *Index) Withdraw(prefix netip.Prefix) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	f := famOf(prefix)
	if old, ok := ix.routes[f][prefix]; ok {
		delete(ix.routes[f], prefix)
		ix.release(old)
	}
	ix.touch()
}

func (ix *Index) release(a *Attrs) {
	a.refs--
	if a.refs == 0 {
		delete(ix.attrs, a.key)
	}
}

func (ix *Index) touch() {
	ix.version++
	ix.lastUpdate = ix.now()
}

// EndOfRIB records that ipv4 (or IPv6) initial table is complete.
func (ix *Index) EndOfRIB(ipv4 bool) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	f := famV6
	if ipv4 {
		f = famV4
	}
	ix.eor[f] = true
	if ix.eor[famV4] && ix.eor[famV6] && ix.syncedAt.IsZero() {
		ix.syncedAt = ix.now()
	}
}

// State returns the index's current state.
func (ix *Index) State() State {
	ix.mu.RLock()
	defer ix.mu.RUnlock()
	return ix.stateLocked()
}

func (ix *Index) stateLocked() State {
	return State{
		Synced:     ix.connected && !ix.syncedAt.IsZero(),
		SyncedAt:   ix.syncedAt,
		LastUpdate: ix.lastUpdate,
		Version:    ix.version,
		Routes:     len(ix.routes[famV4]) + len(ix.routes[famV6]),
		Connected:  ix.connected,
	}
}

// Stats returns per-family route counts, distinct attribute sets and
// dropped-for-overflow updates.
func (ix *Index) Stats() (v4, v6, attrs int, overflow uint64) {
	ix.mu.RLock()
	defer ix.mu.RUnlock()
	return len(ix.routes[famV4]), len(ix.routes[famV6]), len(ix.attrs), ix.overflow
}

// ErrNotSynced is returned by Search before the initial table is complete.
var ErrNotSynced = errors.New("the search index has not received the full table")

// Result is a search's bounded answer.
type Result struct {
	// Routes are the first matches in prefix order, at most the limit.
	Routes []frr.Route
	// Matched is the exact number of matching prefixes.
	Matched int
	// State is the index's freshness when the search ran.
	State State
}

// matcher decides whether an attribute set matches a search.
type matcher func(a *Attrs) bool

// Search runs a canonical AS-path, community or large-community query and
// returns at most limit matches in prefix order, with the exact total.
func (ix *Index) Search(q query.Query, limit int) (Result, error) {
	m, err := compile(q)
	if err != nil {
		return Result{}, err
	}
	ix.searchMu.Lock()
	defer ix.searchMu.Unlock()
	ix.mu.RLock()
	defer ix.mu.RUnlock()
	st := ix.stateLocked()
	if !st.Synced {
		return Result{}, ErrNotSynced
	}
	// Evaluate each distinct attribute set once.
	ix.epoch++
	for _, a := range ix.attrs {
		a.matchEpoch, a.matched = ix.epoch, m(a)
	}
	f := famV4
	if q.AddressFamily == query.IPv6 {
		f = famV6
	}
	h := &prefixHeap{}
	matched := 0
	for p, a := range ix.routes[f] {
		if !a.matched || a.matchEpoch != ix.epoch {
			continue
		}
		matched++
		if limit <= 0 {
			continue
		}
		if h.Len() < limit {
			heap.Push(h, entry{p, a})
		} else if prefixLess(p, (*h)[0].p) {
			(*h)[0] = entry{p, a}
			heap.Fix(h, 0)
		}
	}
	out := make([]entry, h.Len())
	for i := len(out) - 1; i >= 0; i-- {
		out[i] = heap.Pop(h).(entry)
	}
	res := Result{Matched: matched, State: st, Routes: make([]frr.Route, 0, len(out))}
	for _, e := range out {
		res.Routes = append(res.Routes, frr.Route{Prefix: e.p.String(), Paths: []frr.Path{pathOf(e.a)}})
	}
	return res, nil
}

// compile turns a canonical query into a matcher.
func compile(q query.Query) (matcher, error) {
	switch q.Type {
	case query.TypeASPath:
		re, err := regexp.CompilePOSIX(strings.ReplaceAll(q.Target, "_", "(^|[,{}() ]|$)"))
		if err != nil {
			return nil, fmt.Errorf("compile %q: %w", q.Target, err)
		}
		return func(a *Attrs) bool { return re.MatchString(a.ASPath.String) }, nil
	case query.TypeCommunity:
		want, err := communityValue(q.Target)
		if err != nil {
			return nil, err
		}
		return func(a *Attrs) bool {
			return slices.Contains(a.Community, want)
		}, nil
	case query.TypeLargeCommunity:
		parts := strings.Split(q.Target, ":")
		if len(parts) != 3 {
			return nil, fmt.Errorf("large community %q", q.Target)
		}
		var v [3]uint32
		for i, p := range parts {
			n, err := strconv.ParseUint(p, 10, 32)
			if err != nil {
				return nil, fmt.Errorf("large community %q: %w", q.Target, err)
			}
			v[i] = uint32(n)
		}
		want := LargeCommunity{v[0], v[1], v[2]}
		return func(a *Attrs) bool {
			return slices.Contains(a.Large, want)
		}, nil
	}
	return nil, fmt.Errorf("%s is not an index search", q.Type)
}

// wellKnown maps the well-known communities to the names a canonical query
// uses and the names FRR prints in JSON.
var wellKnown = []struct {
	value      uint32
	query, frr string
}{
	{0xFFFFFF01, communityNoExport, "noExport"},
	{0xFFFFFF02, "no-advertise", "noAdvertise"},
	{0xFFFFFF03, "local-AS", "localAs"},
	{0xFFFFFF04, "no-peer", "noPeer"},
	{0xFFFF029A, communityBlackhole, communityBlackhole},
	{0xFFFF0000, "graceful-shutdown", "gracefulShutdown"},
	{0xFFFF0001, "accept-own", "acceptOwn"},
}

func communityValue(s string) (uint32, error) {
	for _, w := range wellKnown {
		if s == w.query {
			return w.value, nil
		}
	}
	hi, lo, ok := strings.Cut(s, ":")
	if !ok {
		return 0, fmt.Errorf("community %q", s)
	}
	h, err1 := strconv.ParseUint(hi, 10, 16)
	l, err2 := strconv.ParseUint(lo, 10, 16)
	if err1 != nil || err2 != nil {
		return 0, fmt.Errorf("community %q", s)
	}
	return uint32(h)<<16 | uint32(l), nil
}

// CommunityString renders a community the way FRR's JSON lists do.
func CommunityString(c uint32) string {
	for _, w := range wellKnown {
		if c == w.value {
			return w.frr
		}
	}
	return fmt.Sprintf("%d:%d", c>>16, c&0xFFFF)
}

// pathOf renders an attribute set as the selected path of a prefix.
func pathOf(a *Attrs) frr.Path {
	p := frr.Path{
		Best:      true,
		Valid:     true,
		ASPath:    a.ASPath,
		Origin:    a.Origin,
		OriginASN: a.OriginASN,
		MED:       a.MED,
		LocalPref: a.LocalPref,
	}
	for _, c := range a.Community {
		p.Communities = append(p.Communities, CommunityString(c))
	}
	for _, l := range a.Large {
		p.LargeCommunities = append(p.LargeCommunities, l.String())
	}
	if a.NextHop.IsValid() {
		p.NextHops = []frr.NextHop{{Address: a.NextHop.String(), Used: true}}
	}
	if len(a.ASPath.Segments) == 0 {
		p.Local = true
	}
	return p
}

type entry struct {
	p netip.Prefix
	a *Attrs
}

func prefixLess(a, b netip.Prefix) bool {
	if c := a.Addr().Compare(b.Addr()); c != 0 {
		return c < 0
	}
	return a.Bits() < b.Bits()
}

// prefixHeap is a max-heap by prefix order, so the root is the largest of
// the kept smallest.
type prefixHeap []entry

func (h prefixHeap) Len() int           { return len(h) }
func (h prefixHeap) Less(i, j int) bool { return prefixLess(h[j].p, h[i].p) }
func (h prefixHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *prefixHeap) Push(x any)        { *h = append(*h, x.(entry)) }
func (h *prefixHeap) Pop() any {
	old := *h
	e := old[len(old)-1]
	*h = old[:len(old)-1]
	return e
}
