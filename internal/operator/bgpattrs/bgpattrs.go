// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package bgpattrs formats the BGP route distinguisher and route target
// strings written into VPCAttachment.status. The string form is
// <asn>:<vpc-id-32> for both, and is a stable, human-readable
// representation of:
//
//   - RD type 2 (RFC 4364): 4-byte ASN administrator + 4-byte assigned
//   - RT transitive 4-octet AS-specific extended community (RFC 5668,
//     type 0x0202): 4-byte ASN + 4-byte assigned
//
// With the 32-bit VPC identifier locked in (Decision 6 of the cutover
// plan), there is no truncation: the string form is unambiguous and
// the wire encoding follows directly.
package bgpattrs

import (
	"fmt"
	"strconv"
)

// Formatter holds the cluster ASN and produces RD and RT strings.
type Formatter struct {
	asn uint32
}

// NewFormatter returns a Formatter bound to the cluster ASN. ASN must
// be non-zero. Reserved ASNs (0, 23456, 65535, 4294967295) are not
// rejected here; the operator-side validation may layer that on.
func NewFormatter(asn uint32) (*Formatter, error) {
	if asn == 0 {
		return nil, fmt.Errorf("asn must be non-zero")
	}
	return &Formatter{asn: asn}, nil
}

// RD returns the route distinguisher string for the given VPC. vpcHex
// must be lowercase hex up to 8 characters wide.
func (f *Formatter) RD(vpcHex string) (string, error) {
	v, err := parseVPC(vpcHex)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%d:%d", f.asn, v), nil
}

// RT returns the route target string for the given VPC. Same encoding
// as RD; the wire community type differs but the user-facing string is
// the same. All attachments in the same VPC share this RT.
func (f *Formatter) RT(vpcHex string) (string, error) {
	v, err := parseVPC(vpcHex)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%d:%d", f.asn, v), nil
}

func parseVPC(vpcHex string) (uint32, error) {
	v, err := strconv.ParseUint(vpcHex, 16, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid vpc hex %q: %w", vpcHex, err)
	}
	return uint32(v), nil
}
