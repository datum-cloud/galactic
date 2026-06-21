// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gobgp

import (
	"errors"

	"go.datum.net/galactic/internal/model"
)

// ErrEVPNNotImplemented is returned when an EVPN advertisement is requested.
// EVPN Type 5 path construction is not yet implemented; the controller converts
// this error into an Accepted=False condition on the BGPAdvertisement resource.
var ErrEVPNNotImplemented = errors.New("EVPN path construction is not yet implemented")

// buildEVPNPath is a stub that always returns ErrEVPNNotImplemented.
// TODO: implement EVPN Type 5 IP Prefix path construction using api.AddPath
// with the SRv6 endpoint prefix, node IPv6 as next-hop, and route target communities.
func buildEVPNPath(_ model.DesiredAdvertisement, _ bool) error {
	return ErrEVPNNotImplemented
}
