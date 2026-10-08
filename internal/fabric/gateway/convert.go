// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gateway

import (
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	fabricv1 "go.datum.net/galactic/api/fabric/v1"
	fabricapi "go.datum.net/galactic/internal/fabric/api/v1alpha1"
	"go.datum.net/galactic/internal/fabric/query"
)

// QueryFromSpec converts a FabricQuery's query into the query package's
// form.
func QueryFromSpec(q fabricapi.QuerySpec) query.Query {
	return query.Query{Type: query.Type(q.Type), Target: q.Target, AddressFamily: query.AddressFamily(q.AddressFamily)}
}

// BudgetsFromSpec converts spec budgets, clamped to the ceilings.
func BudgetsFromSpec(b fabricapi.ResultBudgets) query.Budgets {
	return query.Budgets{
		MaxNodes:              int(b.MaxNodes),
		MaxNodeResponseBytes:  int(b.MaxNodeResponseBytes),
		MaxObjectBytes:        int(b.MaxObjectBytes),
		MaxPrefixes:           int(b.MaxPrefixes),
		MaxPathsPerPrefix:     int(b.MaxPathsPerPrefix),
		MaxCommunitiesPerPath: int(b.MaxCommunitiesPerPath),
	}.Clamp()
}

func mtime(t interface{ AsTime() time.Time }, valid bool) *metav1.Time {
	if !valid {
		return nil
	}
	mt := metav1.NewTime(t.AsTime().UTC())
	return &mt
}

// observationFromProto converts a node's answer into its status form.
func observationFromProto(node string, o *fabricv1.Observation) fabricapi.NodeObservation {
	out := fabricapi.NodeObservation{
		Node:                 node,
		SampleTime:           mtime(o.GetSampleTime(), o.GetSampleTime() != nil),
		DurationMilliseconds: o.GetDuration().AsDuration().Milliseconds(),
		RouterID:             o.GetRouterId(),
		ASN:                  int64(o.GetAsn()),
		FRRVersion:           o.GetFrrVersion(),
		MatchedIsExact:       o.GetMatchedIsExact(),
		Truncated:            o.GetTruncated(),
	}
	if o.Matched != nil && o.GetMatchedIsExact() {
		m := int32(o.GetMatched())
		out.Matched = &m
	}
	switch r := o.GetResult().(type) {
	case *fabricv1.Observation_Routes:
		out.Routes = routesFromProto(r.Routes)
	case *fabricv1.Observation_Summary:
		out.Summary = summaryFromProto(r.Summary)
	case *fabricv1.Observation_Ping:
		out.Ping = pingFromProto(r.Ping)
	case *fabricv1.Observation_Traceroute:
		out.Traceroute = tracerouteFromProto(r.Traceroute)
	}
	return out
}

func routesFromProto(r *fabricv1.RouteResult) *fabricapi.RouteResult {
	out := &fabricapi.RouteResult{}
	switch r.GetLookupKind() {
	case fabricv1.LookupKind_LOOKUP_KIND_EXACT:
		out.LookupKind = "Exact"
	case fabricv1.LookupKind_LOOKUP_KIND_LONGEST_MATCH:
		out.LookupKind = "LongestMatch"
	default:
		out.LookupKind = "Search"
	}
	if ix := r.GetIndex(); ix != nil {
		out.Index = &fabricapi.IndexState{
			SyncedAt:   mtime(ix.GetSyncedAt(), ix.GetSyncedAt() != nil),
			LastUpdate: mtime(ix.GetLastUpdate(), ix.GetLastUpdate() != nil),
			Version:    int64(ix.GetVersion()),
			Routes:     int64(ix.GetRoutes()),
		}
	}
	for _, p := range r.GetPrefixes() {
		po := fabricapi.PrefixObservation{Prefix: p.GetPrefix(), TotalPaths: int32(p.GetTotalPaths())}
		for _, path := range p.GetPaths() {
			po.Paths = append(po.Paths, pathFromProto(path))
		}
		if inst := p.GetInstallation(); inst != nil {
			po.Installation = installationFromProto(inst)
		}
		out.Prefixes = append(out.Prefixes, po)
	}
	return out
}

func pathFromProto(p *fabricv1.Path) fabricapi.Path {
	out := fabricapi.Path{
		Best:                  p.GetBest(),
		Multipath:             p.GetMultipath(),
		Valid:                 p.GetValid(),
		SelectionReason:       p.GetSelectionReason(),
		ASPath:                p.GetAsPath(),
		Origin:                p.GetOrigin(),
		OriginASN:             int64(p.GetOriginAsn()),
		Weight:                int64(p.GetWeight()),
		Local:                 p.GetLocal(),
		Aggregated:            p.GetAggregated(),
		Communities:           p.GetCommunities(),
		TotalCommunities:      int32(p.GetTotalCommunities()),
		LargeCommunities:      p.GetLargeCommunities(),
		TotalLargeCommunities: int32(p.GetTotalLargeCommunities()),
		PeerAddress:           p.GetPeerAddress(),
		PeerRouterID:          p.GetPeerRouterId(),
		PeerHostname:          p.GetPeerHostname(),
		PeerType:              p.GetPeerType(),
		LastUpdate:            mtime(p.GetLastUpdate(), p.GetLastUpdate() != nil),
	}
	if p.LocalPref != nil {
		v := int64(p.GetLocalPref())
		out.LocalPref = &v
	}
	if p.Med != nil {
		v := int64(p.GetMed())
		out.MED = &v
	}
	for _, s := range p.GetAsPathSegments() {
		seg := fabricapi.ASSegment{Type: s.GetType()}
		for _, a := range s.GetAsns() {
			seg.ASNs = append(seg.ASNs, int64(a))
		}
		out.ASPathSegments = append(out.ASPathSegments, seg)
	}
	for _, nh := range p.GetNextHops() {
		out.NextHops = append(out.NextHops, fabricapi.NextHop{
			Address: nh.GetAddress(), Hostname: nh.GetHostname(), Scope: nh.GetScope(),
			Accessible: nh.GetAccessible(), Used: nh.GetUsed(),
		})
	}
	return out
}

func installationFromProto(i *fabricv1.Installation) *fabricapi.Installation {
	out := &fabricapi.Installation{
		SampleTime:   mtime(i.GetSampleTime(), i.GetSampleTime() != nil),
		Present:      i.GetPresent(),
		ErrorCode:    i.GetErrorCode(),
		ErrorMessage: i.GetErrorMessage(),
	}
	for _, r := range i.GetRoutes() {
		zr := fabricapi.ZebraRoute{
			Protocol: r.GetProtocol(), Selected: r.GetSelected(), Installed: r.GetInstalled(),
			Distance: int64(r.GetDistance()), Metric: int64(r.GetMetric()),
		}
		for _, nh := range r.GetNextHops() {
			zr.NextHops = append(zr.NextHops, fabricapi.ZebraNextHop{
				Address: nh.GetAddress(), Interface: nh.GetInterface(), Active: nh.GetActive(), FIB: nh.GetFib(),
				Blackhole: nh.GetBlackhole(),
			})
		}
		out.Routes = append(out.Routes, zr)
	}
	return out
}

func summaryFromProto(s *fabricv1.SummaryResult) *fabricapi.SummaryResult {
	out := &fabricapi.SummaryResult{
		RouterID: s.GetRouterId(), ASN: int64(s.GetAsn()),
		TotalPeers: int32(s.GetTotalPeers()), EstablishedPeers: int32(s.GetEstablishedPeers()),
	}
	for _, p := range s.GetPeers() {
		out.Peers = append(out.Peers, fabricapi.Peer{
			Address:                p.GetAddress(),
			Hostname:               p.GetHostname(),
			Description:            p.GetDescription(),
			RemoteAS:               int64(p.GetRemoteAs()),
			LocalAS:                int64(p.GetLocalAs()),
			State:                  p.GetState(),
			Established:            p.GetEstablished(),
			UptimeSeconds:          int64(p.GetUptime().AsDuration().Seconds()),
			PrefixesReceived:       int64(p.GetPrefixesReceived()),
			PrefixesSent:           int64(p.GetPrefixesSent()),
			MessagesReceived:       int64(p.GetMessagesReceived()),
			MessagesSent:           int64(p.GetMessagesSent()),
			ConnectionsEstablished: int64(p.GetConnectionsEstablished()),
			ConnectionsDropped:     int64(p.GetConnectionsDropped()),
		})
	}
	return out
}

func repliesFromProto(rs []*fabricv1.ProbeReply) []fabricapi.ProbeReply {
	out := make([]fabricapi.ProbeReply, 0, len(rs))
	for _, r := range rs {
		out = append(out, fabricapi.ProbeReply{
			Sequence:        int32(r.GetSequence()),
			Address:         r.GetAddress(),
			RTTMicroseconds: r.GetRtt().AsDuration().Microseconds(),
			Timeout:         r.GetTimeout(),
			ICMPType:        r.GetIcmpType(),
			ICMPCode:        int32(r.GetIcmpCode()),
		})
	}
	return out
}

func pingFromProto(p *fabricv1.PingResult) *fabricapi.PingResult {
	return &fabricapi.PingResult{
		Source:             p.GetSource(),
		Destination:        p.GetDestination(),
		Sent:               int32(p.GetSent()),
		Received:           int32(p.GetReceived()),
		Replies:            repliesFromProto(p.GetReplies()),
		RTTMinMicroseconds: p.GetRttMin().AsDuration().Microseconds(),
		RTTAvgMicroseconds: p.GetRttAvg().AsDuration().Microseconds(),
		RTTMaxMicroseconds: p.GetRttMax().AsDuration().Microseconds(),
	}
}

func tracerouteFromProto(t *fabricv1.TracerouteResult) *fabricapi.TracerouteResult {
	out := &fabricapi.TracerouteResult{Source: t.GetSource(), Destination: t.GetDestination(), Reached: t.GetReached()}
	for _, h := range t.GetHops() {
		out.Hops = append(out.Hops, fabricapi.Hop{TTL: int32(h.GetTtl()), Probes: repliesFromProto(h.GetProbes())})
	}
	return out
}
