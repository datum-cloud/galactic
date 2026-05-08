// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package bgp

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"

	api "github.com/osrg/gobgp/v3/api"
	"google.golang.org/protobuf/types/known/anypb"
)

// Originate advertises a single VPN prefix into BGP. Called by the
// reconciler from tryOriginate, once per pod prefix.
//
// Idempotency: re-calling Originate for the same key replaces the prior
// path. The caller (reconciler) tracks the key set; this layer tracks
// the GoBGP path UUID per key.
func (s *Server) Originate(
	ctx context.Context,
	key PathKey,
	prefix *net.IPNet,
	rd, rt string,
	nextHop net.IP,
	serviceSID net.IP,
) error {
	path, err := s.buildPath(prefix, rd, rt, nextHop, serviceSID)
	if err != nil {
		return fmt.Errorf("build path: %w", err)
	}
	resp, err := s.bs.AddPath(ctx, &api.AddPathRequest{Path: path})
	if err != nil {
		return fmt.Errorf("AddPath: %w", err)
	}
	s.mu.Lock()
	s.active[key] = activeEntry{
		uuid:       resp.GetUuid(),
		prefix:     prefix,
		rd:         rd,
		rt:         rt,
		nextHop:    nextHop,
		serviceSID: serviceSID,
	}
	s.mu.Unlock()
	return nil
}

// Withdraw removes a previously-originated path. No-op if the key is
// unknown — the reconciler may call Withdraw during teardown for keys
// that never successfully originated.
func (s *Server) Withdraw(ctx context.Context, key PathKey) error {
	s.mu.Lock()
	entry, ok := s.active[key]
	if !ok {
		s.mu.Unlock()
		return nil
	}
	delete(s.active, key)
	s.mu.Unlock()

	return s.bs.DeletePath(ctx, &api.DeletePathRequest{
		Family: familyFor(entry.prefix),
		Uuid:   entry.uuid,
	})
}

// ReoriginateAll re-issues AddPath for every entry in active. Called by
// the reconciler on session-up. Stale UUIDs from the prior session are
// discarded; this rebuilds the UUID map.
func (s *Server) ReoriginateAll(ctx context.Context) error {
	s.mu.Lock()
	snapshot := make(map[PathKey]activeEntry, len(s.active))
	for k, v := range s.active {
		snapshot[k] = v
	}
	s.mu.Unlock()

	for key, entry := range snapshot {
		if err := s.Originate(ctx, key, entry.prefix, entry.rd, entry.rt, entry.nextHop, entry.serviceSID); err != nil {
			return fmt.Errorf("reoriginate %v: %w", key, err)
		}
	}
	return nil
}

func familyFor(prefix *net.IPNet) *api.Family {
	if prefix.IP.To4() != nil {
		return &api.Family{Afi: api.Family_AFI_IP, Safi: api.Family_SAFI_MPLS_VPN}
	}
	return &api.Family{Afi: api.Family_AFI_IP6, Safi: api.Family_SAFI_MPLS_VPN}
}

func (s *Server) buildPath(
	prefix *net.IPNet,
	rd, rt string,
	nextHop net.IP,
	serviceSID net.IP,
) (*api.Path, error) {
	rdAny, err := encodeRD(rd)
	if err != nil {
		return nil, fmt.Errorf("encode RD %q: %w", rd, err)
	}
	rtAny, err := encodeRT(rt)
	if err != nil {
		return nil, fmt.Errorf("encode RT %q: %w", rt, err)
	}

	prefixLen, _ := prefix.Mask.Size()
	nlri, err := anypb.New(&api.LabeledVPNIPAddressPrefix{
		Labels:    []uint32{0}, // SID-in-tunnel-attribute mode; label is not the SID transport
		Rd:        rdAny,
		PrefixLen: uint32(prefixLen),
		Prefix:    prefix.IP.String(),
	})
	if err != nil {
		return nil, err
	}

	originAttr, err := anypb.New(&api.OriginAttribute{Origin: 0})
	if err != nil {
		return nil, err
	}
	nextHopAttr, err := anypb.New(&api.NextHopAttribute{NextHop: nextHop.String()})
	if err != nil {
		return nil, err
	}
	extCommunitiesAttr, err := anypb.New(&api.ExtendedCommunitiesAttribute{
		Communities: []*anypb.Any{rtAny},
	})
	if err != nil {
		return nil, err
	}

	pattrs := []*anypb.Any{originAttr, nextHopAttr, extCommunitiesAttr}

	switch s.cfg.Encoding {
	case EncodingTunnelEncap:
		tunnelAttr, err := encodeTunnelEncapForSID(serviceSID)
		if err != nil {
			return nil, fmt.Errorf("encode tunnel-encap: %w", err)
		}
		pattrs = append(pattrs, tunnelAttr)
	case EncodingPrefixSID:
		prefixSIDAttr, err := encodePrefixSIDForSID(serviceSID)
		if err != nil {
			return nil, fmt.Errorf("encode prefix-sid: %w", err)
		}
		pattrs = append(pattrs, prefixSIDAttr)
	}

	return &api.Path{
		Family: familyFor(prefix),
		Nlri:   nlri,
		Pattrs: pattrs,
	}, nil
}

// encodeTunnelEncapForSID builds a Tunnel Encapsulation Attribute (RFC
// 9012) carrying a single Type-A IPv6 segment whose value is the
// service SID. Tunnel type 15 = SR Policy. Receivers extract the
// segment list and use the first IPv6 segment as the END.DT* SID for
// the encap rule.
func encodeTunnelEncapForSID(serviceSID net.IP) (*anypb.Any, error) {
	segment, err := anypb.New(&api.SegmentTypeA{
		Flags: &api.SegmentFlags{},
		Label: 0,
	})
	if err != nil {
		return nil, err
	}
	// SegmentTypeA in GoBGP does not carry an IPv6 SID directly; in
	// SR-MPLS contexts it carries an MPLS label. For SRv6 we want the
	// SID-as-IPv6 form. GoBGP exposes this via a custom encoding —
	// fall back to UnknownSubTLV that carries the raw segment bytes.
	_ = segment // unused in the minimal path; see TODO below

	// Encode the SID as a 16-byte raw value in an unknown sub-TLV.
	// This is the deliberate "bytes on the wire we control" path
	// described in PLAN-bgp-cutover.md. A future revision can switch
	// to a typed sub-TLV once GoBGP exposes one with stable round-trip
	// semantics for arbitrary endpoint behaviors.
	sidBytes := serviceSID.To16()
	if sidBytes == nil {
		return nil, fmt.Errorf("service SID is not a 16-byte IPv6 address: %v", serviceSID)
	}

	unknownSubTLV, err := anypb.New(&api.TunnelEncapSubTLVUnknown{
		Type:  galacticSegmentSubTLVType,
		Value: sidBytes,
	})
	if err != nil {
		return nil, err
	}
	tlv := &api.TunnelEncapTLV{
		Type: tunnelTypeSRPolicy,
		Tlvs: []*anypb.Any{unknownSubTLV},
	}
	return anypb.New(&api.TunnelEncapAttribute{Tlvs: []*api.TunnelEncapTLV{tlv}})
}

// Wire-format constants for the tunnel-encap encoding.
const (
	// tunnelTypeSRPolicy is the IANA-assigned tunnel type for
	// Segment Routing policy (RFC 9012). The receiver does not need
	// to install an SR policy — it only needs the segment list, which
	// in our use-case is exactly one IPv6 segment = the service SID.
	tunnelTypeSRPolicy uint32 = 15

	// galacticSegmentSubTLVType is a private sub-TLV type code
	// chosen from the experimental range. The wire format is 16
	// bytes of IPv6 address, big-endian. Receivers are this same
	// agent build (cluster-wide encoding consistency, per
	// PLAN-bgp-cutover.md), so the value is a closed contract.
	galacticSegmentSubTLVType uint32 = 240
)

// encodeRD parses the human-readable form ("asn:value") into the
// FourOctetAsSpecific RD type (RFC 4364 type 2 — 4-byte AS, 4-byte
// assigned). All Galactic VPC IDs fit in 32 bits per Decision 6 of the
// cutover plan.
func encodeRD(rd string) (*anypb.Any, error) {
	asn, val, err := parseAsnValue(rd)
	if err != nil {
		return nil, err
	}
	return anypb.New(&api.RouteDistinguisherFourOctetASN{
		Admin:    asn,
		Assigned: val,
	})
}

// encodeRT parses "asn:value" into the FourOctetAsSpecific RT extended
// community (RFC 5668), type 0x0202 = transitive 4-octet AS specific.
func encodeRT(rt string) (*anypb.Any, error) {
	asn, val, err := parseAsnValue(rt)
	if err != nil {
		return nil, err
	}
	return anypb.New(&api.FourOctetAsSpecificExtended{
		IsTransitive: true,
		SubType:      0x02, // route-target
		Asn:          asn,
		LocalAdmin:   val,
	})
}

func parseAsnValue(s string) (uint32, uint32, error) {
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("expected asn:value, got %q", s)
	}
	asn, err := strconv.ParseUint(parts[0], 10, 32)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid asn %q: %w", parts[0], err)
	}
	val, err := strconv.ParseUint(parts[1], 10, 32)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid value %q: %w", parts[1], err)
	}
	return uint32(asn), uint32(val), nil
}

// rdString formats an RD anypb back into "asn:value" form. Used by
// watch.go when normalizing inbound paths.
func rdString(any *anypb.Any) string {
	if any == nil {
		return ""
	}
	switch any.TypeUrl {
	case "type.googleapis.com/apipb.RouteDistinguisherFourOctetASN":
		var v api.RouteDistinguisherFourOctetASN
		if err := any.UnmarshalTo(&v); err == nil {
			return fmt.Sprintf("%d:%d", v.GetAdmin(), v.GetAssigned())
		}
	case "type.googleapis.com/apipb.RouteDistinguisherTwoOctetASN":
		var v api.RouteDistinguisherTwoOctetASN
		if err := any.UnmarshalTo(&v); err == nil {
			return fmt.Sprintf("%d:%d", v.GetAdmin(), v.GetAssigned())
		}
	case "type.googleapis.com/apipb.RouteDistinguisherIPAddress":
		var v api.RouteDistinguisherIPAddress
		if err := any.UnmarshalTo(&v); err == nil {
			return fmt.Sprintf("%s:%d", v.GetAdmin(), v.GetAssigned())
		}
	}
	return ""
}

// rtsFromExtCommunities pulls "asn:value" RT strings out of a
// FourOctetAsSpecificExtended community list.
func rtsFromExtCommunities(communities []*anypb.Any) []string {
	var out []string
	for _, c := range communities {
		switch c.TypeUrl {
		case "type.googleapis.com/apipb.FourOctetAsSpecificExtended":
			var v api.FourOctetAsSpecificExtended
			if err := c.UnmarshalTo(&v); err != nil {
				continue
			}
			if v.SubType != 0x02 { // not a route-target
				continue
			}
			out = append(out, fmt.Sprintf("%d:%d", v.Asn, v.LocalAdmin))
		case "type.googleapis.com/apipb.TwoOctetAsSpecificExtended":
			// Out of scope for our 32-bit VPC ID design but cheap to
			// include for interoperability with vendor RRs that may
			// rewrite/transcribe. Skipped here; can be added if a
			// real-world peer requires it.
		}
	}
	return out
}

// sidFromTunnelEncap extracts the IPv6 service SID from a Tunnel
// Encapsulation attribute encoded with our private Galactic sub-TLV.
// Returns nil if the attribute is missing or malformed.
func sidFromTunnelEncap(any *anypb.Any) net.IP {
	var attr api.TunnelEncapAttribute
	if any.UnmarshalTo(&attr) != nil {
		return nil
	}
	for _, tlv := range attr.GetTlvs() {
		if tlv.GetType() != tunnelTypeSRPolicy {
			continue
		}
		for _, sub := range tlv.GetTlvs() {
			var unknown api.TunnelEncapSubTLVUnknown
			if sub.UnmarshalTo(&unknown) != nil {
				continue
			}
			if unknown.GetType() != galacticSegmentSubTLVType {
				continue
			}
			b := unknown.GetValue()
			if len(b) != 16 {
				continue
			}
			ip := net.IP(append(make([]byte, 0, 16), b...))
			return ip
		}
	}
	return nil
}

// _ keeps binary imported even if a future refactor stops using it
// directly. Removing this line should cause goimports to drop the
// import.
var _ = binary.BigEndian
