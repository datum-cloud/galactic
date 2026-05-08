// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package srv6sid computes the SRv6 service SID written into
// VPCAttachment.status.serviceSID. The SID is a function of the cluster
// POP-locator, the VPC's 32-bit identifier, and the attachment's 16-bit
// identifier. It is identical on every node — agents install END.DT46
// decap for it locally on the node hosting a given attachment.
package srv6sid

import (
	"fmt"

	"go.datum.net/galactic/pkg/common/util"
)

// Encoder holds the cluster POP-locator and computes service SIDs.
// The locator is validated once at construction; per-attachment
// invocations only validate the identifier widths.
type Encoder struct {
	popLocator string
}

// NewEncoder returns an Encoder bound to the given POP-locator. The
// locator must be a parseable IPv6 CIDR with mask length <= 64.
func NewEncoder(popLocator string) (*Encoder, error) {
	if _, err := util.EncodeSRv6Endpoint(popLocator, "ffffffff", "ffff"); err != nil {
		return nil, fmt.Errorf("invalid pop-locator %q: %w", popLocator, err)
	}
	return &Encoder{popLocator: popLocator}, nil
}

// ForAttachment returns the service SID for (vpcHex, attachmentHex).
// Both inputs must be lowercase hex of the canonical width (8 chars for
// vpc, 4 chars for attachment); shorter values are accepted and treated
// as their numeric equivalents per util.EncodeSRv6Endpoint.
func (e *Encoder) ForAttachment(vpcHex, attachmentHex string) (string, error) {
	return util.EncodeSRv6Endpoint(e.popLocator, vpcHex, attachmentHex)
}
