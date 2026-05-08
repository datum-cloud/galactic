// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package bgp

import (
	"context"
	"fmt"
	"log"
	"net"

	api "github.com/osrg/gobgp/v3/api"
	"google.golang.org/protobuf/types/known/anypb"
)

// watchPeers subscribes to peer FSM state changes and forwards them to
// the SessionEvents channel. The reconciler uses this to drive
// re-origination when a session re-establishes.
func (s *Server) watchPeers(ctx context.Context) {
	err := s.bs.WatchEvent(ctx, &api.WatchEventRequest{
		Peer: &api.WatchEventRequest_Peer{},
	}, func(rsp *api.WatchEventResponse) {
		peer := rsp.GetPeer()
		if peer == nil {
			return
		}
		p := peer.GetPeer()
		if p == nil || p.GetState() == nil {
			return
		}
		ev := SessionEvent{
			Peer:  p.GetState().GetNeighborAddress(),
			State: bgpStateFromAPI(p.GetState().GetSessionState()),
		}
		s.updatePeerState(ev.Peer, ev.State)
		select {
		case s.sessionCh <- ev:
		case <-ctx.Done():
		default:
			// drop on a saturated channel rather than block GoBGP's
			// internal goroutine; the reconciler reads continuously
			// and a missed transient state is harmless (the next
			// transition wakes it back up).
		}
	})
	if err != nil && ctx.Err() == nil {
		log.Printf("bgp: watchPeers ended: %v", err)
	}
}

// watchTable subscribes to inbound BGP UPDATEs in the VPN AFs and
// forwards them, normalized, to the ReceivedRoutes channel.
func (s *Server) watchTable(ctx context.Context) {
	err := s.bs.WatchEvent(ctx, &api.WatchEventRequest{
		Table: &api.WatchEventRequest_Table{
			Filters: []*api.WatchEventRequest_Table_Filter{
				{Type: api.WatchEventRequest_Table_Filter_BEST},
			},
		},
	}, func(rsp *api.WatchEventResponse) {
		t := rsp.GetTable()
		if t == nil {
			return
		}
		for _, p := range t.GetPaths() {
			route, ok := s.normalizeReceivedPath(p)
			if !ok {
				continue
			}
			select {
			case s.receiveCh <- route:
			case <-ctx.Done():
				return
			}
		}
	})
	if err != nil && ctx.Err() == nil {
		log.Printf("bgp: watchTable ended: %v", err)
	}
}

// normalizeReceivedPath converts a GoBGP path into the agent's
// ReceivedRoute. Returns ok=false if the path lacks the expected
// VPN-NLRI shape or if no SID is recoverable (we have no way to
// program kernel egress without one).
func (s *Server) normalizeReceivedPath(p *api.Path) (ReceivedRoute, bool) {
	if p == nil || p.GetNlri() == nil {
		return ReceivedRoute{}, false
	}

	prefix, rd, ok := decodeVPNPrefix(p.GetNlri())
	if !ok {
		return ReceivedRoute{}, false
	}

	var rts []string
	var sid net.IP
	var nextHop net.IP
	for _, attr := range p.GetPattrs() {
		switch attr.GetTypeUrl() {
		case "type.googleapis.com/apipb.ExtendedCommunitiesAttribute":
			var v api.ExtendedCommunitiesAttribute
			if attr.UnmarshalTo(&v) == nil {
				rts = append(rts, rtsFromExtCommunities(v.GetCommunities())...)
			}
		case "type.googleapis.com/apipb.NextHopAttribute":
			var v api.NextHopAttribute
			if attr.UnmarshalTo(&v) == nil {
				nextHop = net.ParseIP(v.GetNextHop())
			}
		case "type.googleapis.com/apipb.MpReachNLRIAttribute":
			var v api.MpReachNLRIAttribute
			if attr.UnmarshalTo(&v) == nil {
				if hops := v.GetNextHops(); len(hops) > 0 {
					nextHop = net.ParseIP(hops[0])
				}
			}
		case "type.googleapis.com/apipb.TunnelEncapAttribute":
			if got := sidFromTunnelEncap(attr); got != nil {
				sid = got
			}
		case "type.googleapis.com/apipb.PrefixSID":
			if got := sidFromPrefixSID(attr); got != nil {
				sid = got
			}
		}
	}

	if sid == nil {
		// No SID to program — drop. PrefixSID encoding path will land
		// here too once implemented, with its own decoder above.
		return ReceivedRoute{}, false
	}

	return ReceivedRoute{
		Prefix:             prefix,
		RouteDistinguisher: rd,
		RouteTargets:       rts,
		NextHop:            nextHop,
		ServiceSID:         sid,
		IsWithdraw:         p.GetIsWithdraw(),
	}, true
}

func decodeVPNPrefix(nlri *anypb.Any) (*net.IPNet, string, bool) {
	var v api.LabeledVPNIPAddressPrefix
	if nlri.UnmarshalTo(&v) != nil {
		return nil, "", false
	}
	ip := net.ParseIP(v.GetPrefix())
	if ip == nil {
		return nil, "", false
	}
	bits := 128
	if ip.To4() != nil {
		bits = 32
	}
	prefix := &net.IPNet{IP: ip, Mask: net.CIDRMask(int(v.GetPrefixLen()), bits)}
	return prefix, rdString(v.GetRd()), true
}

func bgpStateFromAPI(st api.PeerState_SessionState) SessionState {
	switch st {
	case api.PeerState_IDLE:
		return SessionStateIdle
	case api.PeerState_CONNECT:
		return SessionStateConnect
	case api.PeerState_ACTIVE:
		return SessionStateActive
	case api.PeerState_OPENSENT:
		return SessionStateOpenSent
	case api.PeerState_OPENCONFIRM:
		return SessionStateOpenConfirm
	case api.PeerState_ESTABLISHED:
		return SessionStateEstablished
	}
	return SessionStateIdle
}

// String makes Encoding values human-readable in logs and errors.
func (e Encoding) String() string {
	switch e {
	case EncodingTunnelEncap, EncodingPrefixSID:
		return string(e)
	}
	return fmt.Sprintf("unknown(%q)", string(e))
}
