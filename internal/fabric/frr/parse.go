// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package frr

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Route is one prefix in the BGP table and the paths the source router holds
// for it, in FRR's order.
type Route struct {
	// Prefix is the matched prefix, which for a longest-match lookup may be
	// less specific than the address asked about.
	Prefix string
	// Paths are the router's paths for Prefix.
	Paths []Path
}

// Path is one BGP path as the source router holds it. Best and Multipath
// describe that router's own BGP selection only, not zebra's installation
// or any forwarding behavior.
type Path struct {
	Best            bool
	Multipath       bool
	Valid           bool
	SelectionReason string
	// ASPath is the path's AS_PATH, segment by segment.
	ASPath ASPath
	// Origin is the BGP ORIGIN attribute: IGP, EGP or incomplete.
	Origin string
	// OriginASN is the AS that originated the prefix: the last AS of a
	// trailing AS_SEQUENCE. Zero when the path is local or ends in a set.
	OriginASN uint32
	// LocalPref and MED are nil when FRR did not report them.
	LocalPref *uint32
	MED       *uint32
	Weight    uint32
	// Local is true for a path this router originated.
	Local bool
	// Aggregated is true for a path from a local aggregate.
	Aggregated       bool
	Communities      []string
	LargeCommunities []string
	NextHops         []NextHop
	// PeerAddress is the session the path was learned from; "" for a local
	// path.
	PeerAddress  string
	PeerRouterID string
	PeerHostname string
	// PeerType is FRR's internal/external/confed-* classification.
	PeerType string
	// LastUpdate is when the path last changed; zero when unknown.
	LastUpdate time.Time
}

// ASPath is an AS_PATH as a sequence of segments.
type ASPath struct {
	// String is FRR's rendering, e.g. "65001 {65002,65003}".
	String   string
	Segments []ASSegment
}

// ASSegment is one AS_PATH segment.
type ASSegment struct {
	// Type is as-sequence, as-set, as-confed-sequence or as-confed-set.
	Type string
	ASNs []uint32
}

// AS_PATH segment types, as FRR names them in JSON.
const (
	SegmentSequence       = "as-sequence"
	SegmentSet            = "as-set"
	SegmentConfedSequence = "as-confed-sequence"
	SegmentConfedSet      = "as-confed-set"
)

// NextHop is one BGP next hop of a path.
type NextHop struct {
	Address    string
	Hostname   string
	Scope      string
	Accessible bool
	Used       bool
}

// Summary is `show bgp <afi> unicast summary json`.
type Summary struct {
	RouterID string
	ASN      uint32
	// Peers are sorted by address.
	Peers []Peer
}

// Peer is one BGP session in a summary. A session that is down is data, not
// an error.
type Peer struct {
	Address                string
	Hostname               string
	Description            string
	RemoteAS               uint32
	LocalAS                uint32
	State                  string
	Established            bool
	Uptime                 time.Duration
	PrefixesReceived       uint32
	PrefixesSent           uint32
	MessagesReceived       uint64
	MessagesSent           uint64
	ConnectionsEstablished uint32
	ConnectionsDropped     uint32
}

// Installation is zebra's RIB entry for one prefix: the evidence of whether
// a BGP choice was installed. Present is false when zebra has no route for
// the prefix.
type Installation struct {
	Prefix  string
	Present bool
	Routes  []ZebraRoute
}

// ZebraRoute is one zebra RIB route for a prefix.
type ZebraRoute struct {
	Protocol  string
	Selected  bool
	Installed bool
	Distance  uint32
	Metric    uint32
	NextHops  []ZebraNextHop
}

// ZebraNextHop is one zebra next hop.
type ZebraNextHop struct {
	Address   string
	Interface string
	Active    bool
	FIB       bool
	Blackhole bool
}

// SearchResult is the outcome of a table search.
type SearchResult struct {
	// Routes are the matching prefixes, sorted by prefix.
	Routes []Route
}

// decode checks the response is a single complete JSON object and decodes
// it. A warning response whose output is not JSON is FRR rejecting the
// command (for example a regular expression it cannot compile).
func decode(resp Response, v any) error {
	out := bytes.TrimSpace(resp.Output)
	if len(out) == 0 || out[0] != '{' {
		msg := string(out)
		if len(msg) > 200 {
			msg = msg[:200]
		}
		if resp.Warning {
			return &Error{Code: CodeCommandFailed, Message: "FRR warning: " + msg}
		}
		return &Error{Code: CodeMalformed, Message: "response is not a JSON object: " + msg}
	}
	if !json.Valid(out) {
		return &Error{Code: CodeMalformed, Message: "response is not complete JSON"}
	}
	if err := json.Unmarshal(out, v); err != nil {
		return &Error{Code: CodeMalformed, Message: "unexpected JSON shape", Err: err}
	}
	return nil
}

// isEmptyObject reports whether the response is `{}`, FRR's answer for "no
// such prefix".
func isEmptyObject(resp Response) bool {
	return bytes.Equal(bytes.TrimSpace(resp.Output), []byte("{}"))
}

// rawDetailRoute is `show bgp <afi> unicast <prefix> json`.
type rawDetailRoute struct {
	Prefix *string          `json:"prefix"`
	Paths  *[]rawDetailPath `json:"paths"`
}

type rawDetailPath struct {
	ASPath *struct {
		String   string `json:"string"`
		Segments []struct {
			Type string   `json:"type"`
			List []uint32 `json:"list"`
		} `json:"segments"`
	} `json:"aspath"`
	Origin     string  `json:"origin"`
	Metric     *uint32 `json:"metric"`
	LocPrf     *uint32 `json:"locPrf"`
	Weight     uint32  `json:"weight"`
	Valid      bool    `json:"valid"`
	Multipath  bool    `json:"multipath"`
	Local      bool    `json:"local"`
	Aggregated bool    `json:"aggregated"`
	Bestpath   *struct {
		Overall         bool   `json:"overall"`
		SelectionReason string `json:"selectionReason"`
	} `json:"bestpath"`
	Community *struct {
		List []string `json:"list"`
	} `json:"community"`
	LargeCommunity *struct {
		List []string `json:"list"`
	} `json:"largeCommunity"`
	LastUpdate *struct {
		Epoch int64 `json:"epoch"`
	} `json:"lastUpdate"`
	Nexthops *[]struct {
		IP         string `json:"ip"`
		Hostname   string `json:"hostname"`
		Scope      string `json:"scope"`
		Accessible bool   `json:"accessible"`
		Used       bool   `json:"used"`
	} `json:"nexthops"`
	Peer *struct {
		PeerID   string `json:"peerId"`
		RouterID string `json:"routerId"`
		Hostname string `json:"hostname"`
		Type     string `json:"type"`
	} `json:"peer"`
}

// ParseLookup parses a prefix or address lookup. It returns nil, nil when the
// router has no matching prefix. Every path must carry an AS path and next
// hops; a path missing either is reported as malformed rather than skipped.
func ParseLookup(resp Response) (*Route, error) {
	if isEmptyObject(resp) {
		return nil, nil
	}
	var raw rawDetailRoute
	if err := decode(resp, &raw); err != nil {
		return nil, err
	}
	if raw.Prefix == nil || raw.Paths == nil {
		return nil, &Error{Code: CodeMalformed, Message: "lookup response has no prefix or paths"}
	}
	if _, err := netip.ParsePrefix(*raw.Prefix); err != nil {
		return nil, &Error{Code: CodeMalformed, Message: "lookup response prefix is invalid", Err: err}
	}
	r := &Route{Prefix: *raw.Prefix, Paths: make([]Path, 0, len(*raw.Paths))}
	for i, rp := range *raw.Paths {
		p, err := rp.path()
		if err != nil {
			return nil, &Error{Code: CodeMalformed, Message: fmt.Sprintf("path %d of %s", i, r.Prefix), Err: err}
		}
		r.Paths = append(r.Paths, p)
	}
	return r, nil
}

func (rp rawDetailPath) path() (Path, error) {
	if rp.ASPath == nil {
		return Path{}, errors.New("no aspath")
	}
	if rp.Nexthops == nil {
		return Path{}, errors.New("no nexthops")
	}
	p := Path{
		Valid:      rp.Valid,
		Multipath:  rp.Multipath,
		Origin:     rp.Origin,
		MED:        rp.Metric,
		LocalPref:  rp.LocPrf,
		Weight:     rp.Weight,
		Local:      rp.Local,
		Aggregated: rp.Aggregated,
		ASPath:     ASPath{String: rp.ASPath.String},
	}
	if p.ASPath.String == localASPath {
		p.ASPath.String = ""
	}
	for _, s := range rp.ASPath.Segments {
		if !validSegmentType(s.Type) {
			return Path{}, fmt.Errorf("unknown AS path segment type %q", s.Type)
		}
		p.ASPath.Segments = append(p.ASPath.Segments, ASSegment{Type: s.Type, ASNs: s.List})
	}
	p.OriginASN = OriginASN(p.ASPath.Segments)
	if rp.Bestpath != nil {
		p.Best = rp.Bestpath.Overall
		p.SelectionReason = rp.Bestpath.SelectionReason
	}
	if rp.Community != nil {
		p.Communities = rp.Community.List
	}
	if rp.LargeCommunity != nil {
		p.LargeCommunities = rp.LargeCommunity.List
	}
	if rp.LastUpdate != nil && rp.LastUpdate.Epoch > 0 {
		p.LastUpdate = time.Unix(rp.LastUpdate.Epoch, 0).UTC()
	}
	for _, nh := range *rp.Nexthops {
		p.NextHops = append(p.NextHops, NextHop{
			Address: nh.IP, Hostname: nh.Hostname, Scope: nh.Scope, Accessible: nh.Accessible, Used: nh.Used,
		})
	}
	if rp.Peer != nil {
		p.PeerRouterID = rp.Peer.RouterID
		p.PeerHostname = rp.Peer.Hostname
		p.PeerType = rp.Peer.Type
		if a, err := netip.ParseAddr(rp.Peer.PeerID); err == nil && !a.IsUnspecified() {
			p.PeerAddress = rp.Peer.PeerID
		}
	}
	return p, nil
}

func validSegmentType(t string) bool {
	switch t {
	case SegmentSequence, SegmentSet, SegmentConfedSequence, SegmentConfedSet:
		return true
	}
	return false
}

// OriginASN is the last AS of the path when the path ends in an
// AS_SEQUENCE; zero otherwise (local path, or an aggregate ending in a set
// whose origin is ambiguous).
func OriginASN(segs []ASSegment) uint32 {
	for i := len(segs) - 1; i >= 0; i-- {
		s := segs[i]
		switch s.Type {
		case SegmentConfedSequence, SegmentConfedSet:
			continue
		case SegmentSequence:
			if len(s.ASNs) > 0 {
				return s.ASNs[len(s.ASNs)-1]
			}
		}
		return 0
	}
	return 0
}

// rawTable is the table format of `show bgp <afi> unicast regexp|community|
// large-community ... json`.
type rawTable struct {
	Routes *map[string][]rawTablePath `json:"routes"`
}

type rawTablePath struct {
	Valid           bool    `json:"valid"`
	Bestpath        bool    `json:"bestpath"`
	Multipath       bool    `json:"multipath"`
	SelectionReason string  `json:"selectionReason"`
	PathFrom        string  `json:"pathFrom"`
	Metric          *uint32 `json:"metric"`
	LocPrf          *uint32 `json:"locPrf"`
	Weight          uint32  `json:"weight"`
	PeerID          string  `json:"peerId"`
	Path            *string `json:"path"`
	Origin          string  `json:"origin"`
	Nexthops        *[]struct {
		IP       string `json:"ip"`
		Hostname string `json:"hostname"`
		Used     bool   `json:"used"`
	} `json:"nexthops"`
}

// ParseSearch parses a table search. A search with no matches is an empty,
// successful result. The table format carries no communities, so a search
// result's paths have AS path, origin, preference and next hops only.
func ParseSearch(resp Response) (SearchResult, error) {
	var raw rawTable
	if err := decode(resp, &raw); err != nil {
		return SearchResult{}, err
	}
	if raw.Routes == nil {
		return SearchResult{}, &Error{Code: CodeMalformed, Message: "search response has no routes object"}
	}
	res := SearchResult{Routes: make([]Route, 0, len(*raw.Routes))}
	for prefix, paths := range *raw.Routes {
		if _, err := netip.ParsePrefix(prefix); err != nil {
			return SearchResult{}, &Error{Code: CodeMalformed, Message: "search response prefix " + prefix + " is invalid"}
		}
		r := Route{Prefix: prefix, Paths: make([]Path, 0, len(paths))}
		for i, tp := range paths {
			p, err := tp.path()
			if err != nil {
				return SearchResult{}, &Error{Code: CodeMalformed, Message: fmt.Sprintf("path %d of %s", i, prefix), Err: err}
			}
			r.Paths = append(r.Paths, p)
		}
		res.Routes = append(res.Routes, r)
	}
	sort.Slice(res.Routes, func(i, j int) bool { return prefixLess(res.Routes[i].Prefix, res.Routes[j].Prefix) })
	return res, nil
}

func (tp rawTablePath) path() (Path, error) {
	if tp.Path == nil {
		return Path{}, errors.New("no path")
	}
	if tp.Nexthops == nil {
		return Path{}, errors.New("no nexthops")
	}
	segs, err := ParseASPathString(*tp.Path)
	if err != nil {
		return Path{}, err
	}
	p := Path{
		Best:            tp.Bestpath,
		Multipath:       tp.Multipath,
		Valid:           tp.Valid,
		SelectionReason: tp.SelectionReason,
		ASPath:          ASPath{String: *tp.Path, Segments: segs},
		OriginASN:       OriginASN(segs),
		Origin:          tp.Origin,
		MED:             tp.Metric,
		LocalPref:       tp.LocPrf,
		Weight:          tp.Weight,
		PeerType:        tp.PathFrom,
	}
	if a, err := netip.ParseAddr(tp.PeerID); err == nil && !a.IsUnspecified() {
		p.PeerAddress = tp.PeerID
	} else {
		p.Local = true
	}
	for _, nh := range *tp.Nexthops {
		p.NextHops = append(p.NextHops, NextHop{Address: nh.IP, Hostname: nh.Hostname, Used: nh.Used})
	}
	return p, nil
}

// localASPath is how FRR renders the empty AS path of a locally originated
// route.
const localASPath = "Local"

// ParseASPathString parses FRR's AS path rendering into segments: ASNs
// separated by spaces form a sequence, {a,b} a set, (a b) a confederation
// sequence and [a,b] a confederation set. "" and "Local" are the empty path.
func ParseASPathString(s string) ([]ASSegment, error) {
	s = strings.TrimSpace(s)
	if s == "" || s == localASPath {
		return nil, nil
	}
	var segs []ASSegment
	appendSeq := func(typ string, asn uint32) {
		if n := len(segs); n > 0 && segs[n-1].Type == typ {
			segs[n-1].ASNs = append(segs[n-1].ASNs, asn)
			return
		}
		segs = append(segs, ASSegment{Type: typ, ASNs: []uint32{asn}})
	}
	for i := 0; i < len(s); {
		switch c := s[i]; {
		case c == ' ':
			i++
		case c == '{' || c == '(' || c == '[':
			closer, typ, sep := map[byte]byte{'{': '}', '(': ')', '[': ']'}[c],
				map[byte]string{'{': SegmentSet, '(': SegmentConfedSequence, '[': SegmentConfedSet}[c],
				map[byte]string{'{': ",", '(': " ", '[': ","}[c]
			end := strings.IndexByte(s[i:], closer)
			if end < 0 {
				return nil, fmt.Errorf("unterminated %q in AS path %q", c, s)
			}
			seg := ASSegment{Type: typ}
			for f := range strings.SplitSeq(s[i+1:i+end], sep) {
				n, err := strconv.ParseUint(strings.TrimSpace(f), 10, 32)
				if err != nil {
					return nil, fmt.Errorf("bad ASN %q in AS path %q", f, s)
				}
				seg.ASNs = append(seg.ASNs, uint32(n))
			}
			segs = append(segs, seg)
			i += end + 1
		case c >= '0' && c <= '9':
			j := i
			for j < len(s) && s[j] >= '0' && s[j] <= '9' {
				j++
			}
			n, err := strconv.ParseUint(s[i:j], 10, 32)
			if err != nil {
				return nil, fmt.Errorf("bad ASN in AS path %q", s)
			}
			appendSeq(SegmentSequence, uint32(n))
			i = j
		default:
			return nil, fmt.Errorf("unexpected %q in AS path %q", c, s)
		}
	}
	return segs, nil
}

// rawSummary is `show bgp <afi> unicast summary json`.
type rawSummary struct {
	RouterID *string `json:"routerId"`
	AS       *uint32 `json:"as"`
	Peers    map[string]struct {
		Hostname               string `json:"hostname"`
		Desc                   string `json:"desc"`
		RemoteAS               uint32 `json:"remoteAs"`
		LocalAS                uint32 `json:"localAs"`
		State                  string `json:"state"`
		PeerUptimeMsec         int64  `json:"peerUptimeMsec"`
		PfxRcd                 uint32 `json:"pfxRcd"`
		PfxSnt                 uint32 `json:"pfxSnt"`
		MsgRcvd                uint64 `json:"msgRcvd"`
		MsgSent                uint64 `json:"msgSent"`
		ConnectionsEstablished uint32 `json:"connectionsEstablished"`
		ConnectionsDropped     uint32 `json:"connectionsDropped"`
	} `json:"peers"`
}

// ParseSummary parses a BGP summary. `{}`, FRR's answer when the family has
// no sessions, is an empty summary.
func ParseSummary(resp Response) (Summary, error) {
	if isEmptyObject(resp) {
		return Summary{}, nil
	}
	var raw rawSummary
	if err := decode(resp, &raw); err != nil {
		return Summary{}, err
	}
	if raw.RouterID == nil || raw.AS == nil {
		return Summary{}, &Error{Code: CodeMalformed, Message: "summary has no routerId or as"}
	}
	s := Summary{RouterID: *raw.RouterID, ASN: *raw.AS, Peers: make([]Peer, 0, len(raw.Peers))}
	for addr, rp := range raw.Peers {
		s.Peers = append(s.Peers, Peer{
			Address:                addr,
			Hostname:               rp.Hostname,
			Description:            rp.Desc,
			RemoteAS:               rp.RemoteAS,
			LocalAS:                rp.LocalAS,
			State:                  rp.State,
			Established:            rp.State == "Established",
			Uptime:                 time.Duration(rp.PeerUptimeMsec) * time.Millisecond,
			PrefixesReceived:       rp.PfxRcd,
			PrefixesSent:           rp.PfxSnt,
			MessagesReceived:       rp.MsgRcvd,
			MessagesSent:           rp.MsgSent,
			ConnectionsEstablished: rp.ConnectionsEstablished,
			ConnectionsDropped:     rp.ConnectionsDropped,
		})
	}
	sort.Slice(s.Peers, func(i, j int) bool { return addrLess(s.Peers[i].Address, s.Peers[j].Address) })
	return s, nil
}

// rawZebraRoute is one entry of `show ip[v6] route <prefix> json`.
type rawZebraRoute struct {
	Protocol  *string `json:"protocol"`
	Selected  bool    `json:"selected"`
	Installed bool    `json:"installed"`
	Distance  uint32  `json:"distance"`
	Metric    uint32  `json:"metric"`
	Nexthops  []struct {
		IP            string `json:"ip"`
		InterfaceName string `json:"interfaceName"`
		Active        bool   `json:"active"`
		FIB           bool   `json:"fib"`
		Blackhole     bool   `json:"blackhole"`
	} `json:"nexthops"`
}

// ParseInstallation parses zebra's routes for prefix. `{}` (which zebra
// returns with a warning code) means zebra has no route for it.
func ParseInstallation(resp Response, prefix string) (Installation, error) {
	inst := Installation{Prefix: prefix}
	if isEmptyObject(resp) {
		return inst, nil
	}
	var raw map[string][]rawZebraRoute
	if err := decode(resp, &raw); err != nil {
		return Installation{}, err
	}
	routes, ok := raw[prefix]
	if !ok {
		keys := make([]string, 0, len(raw))
		for k := range raw {
			keys = append(keys, k)
		}
		return Installation{}, &Error{Code: CodeMalformed,
			Message: fmt.Sprintf("zebra answered for %v, not %s", keys, prefix)}
	}
	inst.Present = true
	for i, r := range routes {
		if r.Protocol == nil {
			return Installation{}, &Error{Code: CodeMalformed,
				Message: fmt.Sprintf("zebra route %d of %s has no protocol", i, prefix)}
		}
		zr := ZebraRoute{
			Protocol: *r.Protocol, Selected: r.Selected, Installed: r.Installed, Distance: r.Distance, Metric: r.Metric,
		}
		for _, nh := range r.Nexthops {
			zr.NextHops = append(zr.NextHops, ZebraNextHop{
				Address: nh.IP, Interface: nh.InterfaceName, Active: nh.Active, FIB: nh.FIB, Blackhole: nh.Blackhole,
			})
		}
		inst.Routes = append(inst.Routes, zr)
	}
	return inst, nil
}

// prefixLess orders prefixes by address then length, falling back to string
// order for anything unparsable.
func prefixLess(a, b string) bool {
	pa, errA := netip.ParsePrefix(a)
	pb, errB := netip.ParsePrefix(b)
	if errA != nil || errB != nil {
		return a < b
	}
	if c := pa.Addr().Compare(pb.Addr()); c != 0 {
		return c < 0
	}
	return pa.Bits() < pb.Bits()
}

func addrLess(a, b string) bool {
	pa, errA := netip.ParseAddr(a)
	pb, errB := netip.ParseAddr(b)
	if errA != nil || errB != nil {
		return a < b
	}
	return pa.Less(pb)
}
