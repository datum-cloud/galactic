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

// deriveRD builds an RFC 4364 Type 1 route distinguisher from the router ID
// and the advertisement's VRFID. When VRFID is set, the RD is "routerID:vrfID"
// matching the per-VRF RD used by applyVRF during VRF registration. When VRFID
// is nil (legacy advertisements without a VRFID), falls back to "routerID:0".
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

// gatewayForPrefix returns the EVPN Type 5 Gateway IP Address to pair with
// prefix. This field is left unused — RFC-compliant per
// draft-ietf-bess-evpn-prefix-advertisement ("the GW IP field SHOULD be zero
// if it is not used as an Overlay Index") — always the zero address in
// prefix's own family. The SRv6 SID travels in the BGP Prefix-SID path
// attribute instead (see buildEVPNPaths), which is a separate attribute
// independent of the NLRI's address family and so, unlike this field, can
// carry a SID for an IPv4 prefix: RFC 9136 requires the Prefix and Gateway IP
// Address fields to share an address family, and GoBGP's wire encoding for
// this NLRI only recognizes an all-IPv4 or an all-IPv6 layout (see
// EVPNIPPrefixRoute.Len/Serialize) — mixing families produces a route whose
// declared length doesn't match its serialized bytes, so there was never a
// way to fit a 16-byte IPv6 SID into an IPv4 prefix's Gateway field.
func gatewayForPrefix(prefix netip.Prefix) netip.Addr {
	if prefix.Addr().Is4() {
		return netip.IPv4Unspecified()
	}
	return netip.IPv6Unspecified()
}

// prefixSIDAttr builds the BGP Prefix-SID path attribute (RFC 9252 SRv6 L3
// Service TLV) carrying sid as an End.DT46 SRv6 Information Sub-TLV. This is
// the sole carrier for the destination SID in this design — see
// gatewayForPrefix for why the EVPN route's own Gateway IP field can't be
// used for this instead.
//
// The Information Sub-TLV also carries an RFC 9252 §3.2.1 SID Structure
// Sub-Sub-TLV describing the uSID layout (uFMT 48+16, see
// internal/plumbing/ebpf/uformat) already present in sid, with no
// transposition (TL/TO = 0). The field widths are derived from uformat's own
// constants rather than re-hardcoded, so the wire encoding and the eBPF
// datapath's bit layout can't silently drift apart.
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
// in adv into the local GoBGP RIB.
//
// routerID is the BGP router-ID (IPv4 dotted-decimal) and is used to derive the
// per-VRF route distinguisher (Type 1 IP-address: routerID:vrfID) when adv.VRFID
// is set, matching the RD used by applyVRF during VRF registration. adv.NextHop
// is the transit-reachable BGP peering address placed in MpReachNLRI. adv.SRv6SID,
// when set, is the End.DT46 SID placed in a BGP Prefix-SID path attribute (see
// prefixSIDAttr) — this is the SRv6 segment that remote nodes install in their
// seg6 encap kernel routes, for both IPv4 and IPv6 prefixes alike. When
// adv.SRv6SID is empty, no Prefix-SID attribute is attached (non-SRv6 fallback);
// remote nodes then fall back to the plain next-hop (see monitor.go).
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

	// Type 1 (IP-address:local-admin) RD, unique per VRF.
	// When adv.VRFID is set, the RD matches the one used by applyVRF during
	// VRF registration ("routerID:vrfID"), ensuring two VRFs on the same
	// router never produce colliding NLRIs even for identical prefixes.
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

		// EVPN Type 5 IP Prefix route. ESI all-zeros (Type 0 = not multihomed),
		// ETag 0, label 0 (SRv6 — MPLS label unused). The Gateway IP field is
		// left unused (see gatewayForPrefix) — the SID travels in sidAttr
		// instead, attached to attrs below.
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
