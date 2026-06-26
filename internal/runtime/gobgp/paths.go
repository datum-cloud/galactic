// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gobgp

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/osrg/gobgp/v4/pkg/apiutil"
	bgp "github.com/osrg/gobgp/v4/pkg/packet/bgp"
	gobgpserver "github.com/osrg/gobgp/v4/pkg/server"

	"go.datum.net/galactic/internal/model"
)

// buildEVPNPaths adds or withdraws EVPN Type 5 IP Prefix paths for each prefix
// in adv into the local GoBGP RIB.
//
// routerID is the BGP router-ID (IPv4 dotted-decimal) and is used to derive the
// per-router route distinguisher (Type 1 IP-address: routerID:0). adv.NextHop
// is the transit-reachable BGP peering address placed in MpReachNLRI. adv.SRv6SID,
// when set, is the End.DT46 SID placed in the EVPN GWIPAddress field — this is
// the SRv6 segment that remote nodes install in their seg6 encap kernel routes.
// When adv.SRv6SID is empty the next-hop is used for both (non-SRv6 fallback).
func buildEVPNPaths(b *gobgpserver.BgpServer, adv model.DesiredAdvertisement, routerID string, withdraw bool) error {
	nextHop, err := netip.ParseAddr(adv.NextHop)
	if err != nil {
		return fmt.Errorf("invalid EVPN next-hop %q: %w", adv.NextHop, err)
	}

	gwIP := nextHop
	if adv.SRv6SID != "" {
		sid, err := netip.ParseAddr(adv.SRv6SID)
		if err != nil {
			return fmt.Errorf("invalid SRv6 SID %q: %w", adv.SRv6SID, err)
		}
		gwIP = sid
	}

	// Type 1 (IP-address:local-admin) RD, unique per router.
	rd, err := bgp.ParseRouteDistinguisher(routerID + ":0")
	if err != nil {
		return fmt.Errorf("derive route distinguisher from router-ID %q: %w", routerID, err)
	}

	rts, err := parseRouteTargets(adv.Communities)
	if err != nil {
		return err
	}

	paths := make([]*apiutil.Path, 0, len(adv.Prefixes))
	for _, prefixStr := range adv.Prefixes {
		prefix, err := netip.ParsePrefix(prefixStr)
		if err != nil {
			return fmt.Errorf("invalid prefix %q: %w", prefixStr, err)
		}

		// EVPN Type 5 IP Prefix route. ESI all-zeros (Type 0 = not multihomed),
		// ETag 0, label 0 (SRv6 — MPLS label unused).
		// gwIP is the End.DT46 SRv6 SID when adv.SRv6SID is set; otherwise falls
		// back to nextHop. Remote nodes use this as the seg6 encap segment.
		nlri, err := bgp.NewEVPNIPPrefixRoute(
			rd,
			bgp.EthernetSegmentIdentifier{},
			0,
			uint8(prefix.Bits()),
			prefix.Addr(),
			gwIP,
			0,
		)
		if err != nil {
			return fmt.Errorf("build EVPN NLRI for prefix %q: %w", prefixStr, err)
		}

		// apiutil2Path extracts the nexthop from MpReachNLRI then discards the
		// attribute and reconstructs it from path.Nlri — include it here purely
		// to carry the nexthop through.
		mpreach, err := bgp.NewPathAttributeMpReachNLRI(bgp.RF_EVPN, []bgp.PathNLRI{{NLRI: nlri}}, nextHop)
		if err != nil {
			return fmt.Errorf("build MpReachNLRI for prefix %q: %w", prefixStr, err)
		}

		attrs := []bgp.PathAttributeInterface{
			bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_IGP),
			mpreach,
		}
		if len(rts) > 0 {
			attrs = append(attrs, bgp.NewPathAttributeExtendedCommunities(rts))
		}
		if adv.LocalPreference != nil {
			attrs = append(attrs, bgp.NewPathAttributeLocalPref(*adv.LocalPreference))
		}

		paths = append(paths, &apiutil.Path{
			Family:     bgp.RF_EVPN,
			Nlri:       nlri,
			Attrs:      attrs,
			Age:        time.Now().Unix(),
			Withdrawal: withdraw,
		})
	}

	if len(paths) == 0 {
		return nil
	}

	if withdraw {
		return b.DeletePath(apiutil.DeletePathRequest{Paths: paths})
	}
	_, err = b.AddPath(apiutil.AddPathRequest{Paths: paths})
	return err
}

// parseRouteTargets parses route target community strings (e.g. "65000:100")
// into extended community interfaces.
func parseRouteTargets(communities []string) ([]bgp.ExtendedCommunityInterface, error) {
	rts := make([]bgp.ExtendedCommunityInterface, 0, len(communities))
	for _, c := range communities {
		rt, err := bgp.ParseRouteTarget(c)
		if err != nil {
			return nil, fmt.Errorf("invalid route target %q: %w", c, err)
		}
		rts = append(rts, rt)
	}
	return rts, nil
}
