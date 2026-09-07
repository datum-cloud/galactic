// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gobgp

import (
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/osrg/gobgp/v4/pkg/apiutil"
	bgp "github.com/osrg/gobgp/v4/pkg/packet/bgp"
	gobgpserver "github.com/osrg/gobgp/v4/pkg/server"

	"go.datum.net/galactic/internal/model"
	"go.datum.net/galactic/internal/plumbing/ebpf/uformat"
)

// deriveRD builds an RFC 4364 Type 1 route distinguisher from the router ID and
// the advertisement's VRFID. A set VRFID yields "routerID:vrfID", matching the
// per-VRF distinguisher used at VRF registration; a nil one falls back to
// "routerID:0".
func deriveRD(routerID string, vrfID *int32) string {
	if vrfID != nil {
		return fmt.Sprintf("%s:%d", routerID, *vrfID)
	}
	return routerID + ":0"
}

// parseSIDAddr parses an SRv6 SID string that may be a bare IPv6 address or a
// /128 CIDR (e.g. "2001:db8::1/128"). It strips the CIDR suffix before parsing.
func parseSIDAddr(sid string) (netip.Addr, error) {
	if idx := strings.Index(sid, "/"); idx != -1 {
		sid = sid[:idx]
	}
	return netip.ParseAddr(sid)
}

// gatewayForPrefix returns the EVPN Type 5 gateway address to pair with prefix:
// always the zero address in prefix's own family, the field being unused, which
// the specification permits when it is not an overlay index.
//
// The SID travels in the Prefix-SID path attribute instead. That attribute is
// independent of the NLRI's address family and so, unlike this field, can carry
// a SID for an IPv4 prefix: the standard requires the prefix and gateway fields
// to share a family, and the wire encoding recognises only an all-IPv4 or
// all-IPv6 layout, so there was never a way to fit a 16-byte SID into an IPv4
// prefix's gateway field.
func gatewayForPrefix(prefix netip.Prefix) netip.Addr {
	if prefix.Addr().Is4() {
		return netip.IPv4Unspecified()
	}
	return netip.IPv6Unspecified()
}

// prefixSIDAttr builds the BGP Prefix-SID path attribute carrying sid as an
// End.DT46 SRv6 information sub-TLV. It is the only carrier for the destination
// SID in this design.
//
// The sub-TLV also carries a structure descriptor for the uSID layout already
// present in sid, with no transposition. The field widths come from the shared
// format constants rather than being hardcoded again, so the wire encoding and
// the datapath's bit layout cannot drift apart.
func prefixSIDAttr(sid netip.Addr) bgp.PathAttributeInterface {
	structure := bgp.NewSRv6SIDStructureSubSubTLV(
		uformat.BlockBits,    // LBL = 48, uSID Block
		uformat.NodeIDBits,   // LNL = 16, Node-ID
		uformat.FunctionBits, // FL  = 4,  Function
		uformat.ArgumentBits, // AL  = 12, Instance ID (Argument)
		0,                    // TL  = 0,  no transposition
		0,                    // TO  = 0,  n/a when TL=0
	)
	return bgp.NewPathAttributePrefixSID(
		bgp.NewSRv6ServiceTLV(bgp.TLVTypeSRv6L3Service,
			bgp.NewSRv6InformationSubTLV(sid, bgp.END_DT46, structure),
		),
	)
}

// buildEVPNPaths adds or withdraws EVPN Type 5 IP Prefix paths for each prefix
// in adv, in the local RIB.
//
// routerID is the BGP router ID, used to derive the per-VRF route distinguisher
// when the advertisement names a VRF, matching what VRF registration uses. The
// advertisement's next hop is the transit-reachable peering address. Its SID,
// when set, becomes a Prefix-SID attribute, and is the segment remote nodes
// install in their own encapsulating routes, for IPv4 and IPv6 prefixes alike.
// With no SID, no such attribute is attached and remote nodes fall back to the
// plain next hop.
func buildEVPNPaths(b *gobgpserver.BgpServer, adv model.DesiredAdvertisement, routerID string, withdraw bool) error {
	nextHop, err := netip.ParseAddr(adv.NextHop)
	if err != nil {
		return fmt.Errorf("invalid EVPN next-hop %q: %w", adv.NextHop, err)
	}

	var sidAttr bgp.PathAttributeInterface
	if adv.SRv6SID != "" {
		sid, err := parseSIDAddr(adv.SRv6SID)
		if err != nil {
			return fmt.Errorf("invalid SRv6 SID %q: %w", adv.SRv6SID, err)
		}
		sidAttr = prefixSIDAttr(sid)
	}

	// A Type 1 distinguisher, unique per VRF. When the advertisement names a
	// VRF it matches the one used at registration, so two VRFs on one router
	// never produce colliding NLRIs even for identical prefixes.
	rdStr := deriveRD(routerID, adv.VRFID)
	rd, err := bgp.ParseRouteDistinguisher(rdStr)
	if err != nil {
		return fmt.Errorf("derive route distinguisher %q: %w", rdStr, err)
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

		// An EVPN Type 5 IP Prefix route: no ethernet segment, tag 0, label 0
		// since the label is unused with SRv6. The gateway field is left
		// unused; the SID travels in the attribute attached below.
		gwIP := gatewayForPrefix(prefix)
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

		// The path conversion extracts the next hop from this attribute and then
		// discards it, rebuilding it from the NLRI, so this is included purely
		// to carry the next hop through.
		mpreach, err := bgp.NewPathAttributeMpReachNLRI(bgp.RF_EVPN, []bgp.PathNLRI{{NLRI: nlri}}, nextHop)
		if err != nil {
			return fmt.Errorf("build MpReachNLRI for prefix %q: %w", prefixStr, err)
		}

		attrs := []bgp.PathAttributeInterface{
			bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_IGP),
			mpreach,
		}
		if sidAttr != nil {
			attrs = append(attrs, sidAttr)
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
