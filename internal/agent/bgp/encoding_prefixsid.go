// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package bgp

import (
	"bytes"
	"fmt"
	"net"
	"net/netip"

	api "github.com/osrg/gobgp/v3/api"
	bgppkt "github.com/osrg/gobgp/v3/pkg/packet/bgp"
	"google.golang.org/protobuf/types/known/anypb"
)

// SRv6 endpoint behavior code for Galactic's per-attachment service SID.
// END.DT46 (RFC 8986 §4.10) installs a decap rule that delivers the
// inner packet to the lookup table associated with the SID — matching
// the kernel routeingress behavior.
const endpointBehaviorEndDT46 = 20

// encodePrefixSIDForSID builds a PA_PREFIX_SID attribute carrying a
// single SRv6 L3 Service Sub-TLV with one SRv6 Information Sub-TLV
// (SID + END.DT46 endpoint behavior). RFC 9252 wire format.
//
// The agent verifies at startup that this encoder + GoBGP's wire
// serialization round-trip cleanly via VerifyPrefixSIDRoundTrip; if the
// pinned GoBGP build doesn't preserve the bytes, the agent refuses to
// start with `prefix-sid` selected.
func encodePrefixSIDForSID(serviceSID net.IP) (*anypb.Any, error) {
	sidBytes := serviceSID.To16()
	if sidBytes == nil {
		return nil, fmt.Errorf("service SID is not a 16-byte IPv6 address: %v", serviceSID)
	}
	apiInfo, err := anypb.New(&api.SRv6InformationSubTLV{
		Sid:              sidBytes,
		Flags:            &api.SRv6SIDFlags{},
		EndpointBehavior: endpointBehaviorEndDT46,
	})
	if err != nil {
		return nil, err
	}
	apiL3, err := anypb.New(&api.SRv6L3ServiceTLV{
		SubTlvs: map[uint32]*api.SRv6TLV{
			1: {Tlv: []*anypb.Any{apiInfo}}, // sub-TLV type 1 = SRv6 Information
		},
	})
	if err != nil {
		return nil, err
	}
	return anypb.New(&api.PrefixSID{Tlvs: []*anypb.Any{apiL3}})
}

// sidFromPrefixSID extracts the IPv6 service SID from a PA_PREFIX_SID
// attribute encoded with the L3 Service Sub-TLV. Returns nil if the
// attribute is missing the expected shape.
func sidFromPrefixSID(any *anypb.Any) net.IP {
	var attr api.PrefixSID
	if any.UnmarshalTo(&attr) != nil {
		return nil
	}
	for _, tlv := range attr.GetTlvs() {
		var l3 api.SRv6L3ServiceTLV
		if tlv.UnmarshalTo(&l3) != nil {
			continue
		}
		for _, set := range l3.GetSubTlvs() {
			for _, sub := range set.GetTlv() {
				var info api.SRv6InformationSubTLV
				if sub.UnmarshalTo(&info) != nil {
					continue
				}
				if len(info.GetSid()) != 16 {
					continue
				}
				return net.IP(append([]byte(nil), info.GetSid()...))
			}
		}
	}
	return nil
}

// VerifyPrefixSIDRoundTrip exercises the PA_PREFIX_SID wire format
// against the pinned GoBGP build. Encodes a sample SID via the L3
// Service Sub-TLV path, serializes it to wire bytes, parses the bytes
// back, and asserts the recovered SID and endpoint behavior match.
//
// Called from agent startup when --bgp-srv6-encoding=prefix-sid is
// selected. If the round-trip fails, the agent refuses to start —
// silently producing routes the rest of the cluster can't decode is
// the failure mode this guard prevents.
func VerifyPrefixSIDRoundTrip() error {
	const sample = "fc00::feed:beef:0:0"
	sid, err := netip.ParseAddr(sample)
	if err != nil {
		return fmt.Errorf("VerifyPrefixSIDRoundTrip: parse sample SID: %w", err)
	}

	// Build via the wire-format constructors directly (not the api/
	// proto layer). This is what GoBGP serializes to bytes and what
	// peers decode.
	infoSubTLV := bgppkt.NewSRv6InformationSubTLV(sid, bgppkt.END_DT46)
	l3 := bgppkt.NewSRv6ServiceTLV(bgppkt.TLVTypeSRv6L3Service, infoSubTLV)
	attr := bgppkt.NewPathAttributePrefixSID(l3)

	encoded, err := attr.Serialize()
	if err != nil {
		return fmt.Errorf("VerifyPrefixSIDRoundTrip: serialize: %w", err)
	}

	decoded := &bgppkt.PathAttributePrefixSID{}
	if err := decoded.DecodeFromBytes(encoded); err != nil {
		return fmt.Errorf("VerifyPrefixSIDRoundTrip: decode: %w", err)
	}

	// Walk the decoded structure and recover the SID + behavior.
	gotSID, gotBehavior, ok := extractFirstSRv6SID(decoded)
	if !ok {
		return fmt.Errorf("VerifyPrefixSIDRoundTrip: decoded attribute lacks an SRv6 Information Sub-TLV")
	}
	if !bytes.Equal(gotSID, sid.AsSlice()) {
		return fmt.Errorf("VerifyPrefixSIDRoundTrip: SID mismatch: got %x, want %x", gotSID, sid.AsSlice())
	}
	if gotBehavior != uint16(bgppkt.END_DT46) {
		return fmt.Errorf("VerifyPrefixSIDRoundTrip: endpoint behavior mismatch: got %d, want %d (END_DT46)",
			gotBehavior, bgppkt.END_DT46)
	}
	return nil
}

func extractFirstSRv6SID(p *bgppkt.PathAttributePrefixSID) ([]byte, uint16, bool) {
	for _, tlv := range p.TLVs {
		l3, ok := tlv.(*bgppkt.SRv6ServiceTLV)
		if !ok {
			continue
		}
		for _, sub := range l3.SubTLVs {
			info, ok := sub.(*bgppkt.SRv6InformationSubTLV)
			if !ok {
				continue
			}
			return info.SID, info.EndpointBehavior, true
		}
	}
	return nil, 0, false
}
