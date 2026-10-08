// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package node

import (
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	fabricv1 "go.datum.net/galactic/api/fabric/v1"
	"go.datum.net/galactic/internal/fabric/errcode"
	"go.datum.net/galactic/internal/fabric/frr"
	"go.datum.net/galactic/internal/fabric/query"
)

// budgets is the effective per-node allowance for one request: the
// request's budgets clamped to this node's ceilings.
type budgets struct {
	maxResponseBytes int
	maxPrefixes      int
	maxPaths         int
	maxCommunities   int
}

func effectiveBudgets(req *fabricv1.Budgets, ceiling query.Budgets) budgets {
	pick := func(asked uint32, ceiling int) int {
		if asked == 0 || int(asked) > ceiling {
			return ceiling
		}
		return int(asked)
	}
	return budgets{
		maxResponseBytes: pick(req.GetMaxResponseBytes(), ceiling.MaxNodeResponseBytes),
		maxPrefixes:      pick(req.GetMaxPrefixes(), ceiling.MaxPrefixes),
		maxPaths:         pick(req.GetMaxPathsPerPrefix(), ceiling.MaxPathsPerPrefix),
		maxCommunities:   pick(req.GetMaxCommunitiesPerPath(), ceiling.MaxCommunitiesPerPath),
	}
}

// prefixObservation converts one route, keeping at most maxPaths paths
// (the router's best path always among them) and maxCommunities of each
// community kind per path. It reports whether anything was dropped.
func prefixObservation(r frr.Route, b budgets) (*fabricv1.PrefixObservation, bool) {
	po := &fabricv1.PrefixObservation{Prefix: r.Prefix, TotalPaths: uint32(len(r.Paths))}
	paths := r.Paths
	truncated := false
	if len(paths) > b.maxPaths {
		truncated = true
		kept := make([]frr.Path, 0, b.maxPaths)
		// Best first, then the rest in FRR's order.
		for _, p := range paths {
			if p.Best {
				kept = append(kept, p)
				break
			}
		}
		for _, p := range paths {
			if len(kept) == b.maxPaths {
				break
			}
			if !p.Best {
				kept = append(kept, p)
			}
		}
		paths = kept
	}
	for _, p := range paths {
		pp, cut := pathProto(p, b.maxCommunities)
		truncated = truncated || cut
		po.Paths = append(po.Paths, pp)
	}
	return po, truncated
}

func pathProto(p frr.Path, maxCommunities int) (*fabricv1.Path, bool) {
	out := &fabricv1.Path{
		Best:                  p.Best,
		Multipath:             p.Multipath,
		Valid:                 p.Valid,
		SelectionReason:       p.SelectionReason,
		AsPath:                p.ASPath.String,
		Origin:                p.Origin,
		OriginAsn:             p.OriginASN,
		LocalPref:             p.LocalPref,
		Med:                   p.MED,
		Weight:                p.Weight,
		Local:                 p.Local,
		Aggregated:            p.Aggregated,
		TotalCommunities:      uint32(len(p.Communities)),
		TotalLargeCommunities: uint32(len(p.LargeCommunities)),
		PeerAddress:           p.PeerAddress,
		PeerRouterId:          p.PeerRouterID,
		PeerHostname:          p.PeerHostname,
		PeerType:              p.PeerType,
	}
	for _, s := range p.ASPath.Segments {
		out.AsPathSegments = append(out.AsPathSegments, &fabricv1.ASSegment{Type: s.Type, Asns: s.ASNs})
	}
	truncated := false
	out.Communities, truncated = capStrings(p.Communities, maxCommunities)
	var cut bool
	out.LargeCommunities, cut = capStrings(p.LargeCommunities, maxCommunities)
	truncated = truncated || cut
	for _, nh := range p.NextHops {
		out.NextHops = append(out.NextHops, &fabricv1.NextHop{
			Address: nh.Address, Hostname: nh.Hostname, Scope: nh.Scope, Accessible: nh.Accessible, Used: nh.Used,
		})
	}
	if !p.LastUpdate.IsZero() {
		out.LastUpdate = timestamppb.New(p.LastUpdate)
	}
	return out, truncated
}

func capStrings(ss []string, n int) ([]string, bool) {
	if len(ss) <= n {
		return ss, false
	}
	return ss[:n], true
}

func installationProto(inst frr.Installation) *fabricv1.Installation {
	out := &fabricv1.Installation{Present: inst.Present}
	for _, r := range inst.Routes {
		zr := &fabricv1.ZebraRoute{
			Protocol: r.Protocol, Selected: r.Selected, Installed: r.Installed, Distance: r.Distance, Metric: r.Metric,
		}
		for _, nh := range r.NextHops {
			zr.NextHops = append(zr.NextHops, &fabricv1.ZebraNextHop{
				Address: nh.Address, Interface: nh.Interface, Active: nh.Active, Fib: nh.FIB, Blackhole: nh.Blackhole,
			})
		}
		out.Routes = append(out.Routes, zr)
	}
	return out
}

func summaryProto(s frr.Summary) *fabricv1.SummaryResult {
	out := &fabricv1.SummaryResult{RouterId: s.RouterID, Asn: s.ASN, TotalPeers: uint32(len(s.Peers))}
	for _, p := range s.Peers {
		if p.Established {
			out.EstablishedPeers++
		}
		out.Peers = append(out.Peers, &fabricv1.Peer{
			Address:                p.Address,
			Hostname:               p.Hostname,
			Description:            p.Description,
			RemoteAs:               p.RemoteAS,
			LocalAs:                p.LocalAS,
			State:                  p.State,
			Established:            p.Established,
			Uptime:                 durationpb.New(p.Uptime),
			PrefixesReceived:       p.PrefixesReceived,
			PrefixesSent:           p.PrefixesSent,
			MessagesReceived:       p.MessagesReceived,
			MessagesSent:           p.MessagesSent,
			ConnectionsEstablished: p.ConnectionsEstablished,
			ConnectionsDropped:     p.ConnectionsDropped,
		})
	}
	return out
}

// fitResponse shrinks resp until it serializes within maxBytes: first by
// dropping prefixes from the end (keeping at least one), then by cutting
// each prefix to its best path, then by dropping communities, then by
// dropping summary peers from the end. It marks the observation truncated
// when it changed anything, and returns ResponseTooLarge if even the
// smallest form does not fit.
func fitResponse(resp *fabricv1.ExecuteResponse, maxBytes int) error {
	obs := resp.GetObservation()
	fits := func() bool { return proto.Size(resp) <= maxBytes }
	if fits() {
		return nil
	}
	obs.Truncated = true
	if routes := obs.GetRoutes(); routes != nil {
		for len(routes.Prefixes) > 1 && !fits() {
			routes.Prefixes = routes.Prefixes[:len(routes.Prefixes)-1]
		}
		if !fits() {
			for _, p := range routes.Prefixes {
				if len(p.Paths) > 1 {
					p.Paths = p.Paths[:1]
				}
			}
		}
		if !fits() {
			for _, p := range routes.Prefixes {
				for _, path := range p.Paths {
					path.Communities, path.LargeCommunities = nil, nil
				}
			}
		}
	}
	if sum := obs.GetSummary(); sum != nil {
		for len(sum.Peers) > 0 && !fits() {
			sum.Peers = sum.Peers[:len(sum.Peers)-1]
		}
	}
	if !fits() {
		return errcode.Status(errcode.ResponseTooLarge, "result does not fit the node response budget even when shaped")
	}
	return nil
}
