// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gobgp

import (
	"strings"

	api "github.com/osrg/gobgp/v4/api"

	"go.datum.net/galactic/internal/model"
)

const (
	afiIPv4     = "ipv4"
	afiIPv6     = "ipv6"
	afiL2VPN    = "l2vpn"
	safiUnicast = "unicast"
	safiEVPN    = "evpn"
)

// familyToGlobalInt maps a model.AddressFamily to the integer used in
// api.Global.Families. These values correspond to OC AfiSafi type codes:
// ipv4/unicast=0, ipv6/unicast=1, l2vpn/evpn=9.
func familyToGlobalInt(af model.AddressFamily) uint32 {
	switch {
	case af.AFI == afiIPv4 && af.SAFI == safiUnicast:
		return 0
	case af.AFI == afiIPv6 && af.SAFI == safiUnicast:
		return 1
	case af.AFI == afiL2VPN && af.SAFI == safiEVPN:
		return 9
	default:
		return 0
	}
}

// familyFromModel maps a model.AddressFamily to a GoBGP api.Family.
func familyFromModel(af model.AddressFamily) *api.Family {
	f := &api.Family{}
	switch af.AFI {
	case afiIPv4:
		f.Afi = api.Family_AFI_IP
	case afiIPv6:
		f.Afi = api.Family_AFI_IP6
	case afiL2VPN:
		f.Afi = api.Family_AFI_L2VPN
	}
	switch strings.ToLower(string(af.SAFI)) {
	case safiUnicast:
		f.Safi = api.Family_SAFI_UNICAST
	case safiEVPN:
		f.Safi = api.Family_SAFI_EVPN
	}
	return f
}

// peerFromDesired converts a DesiredPeer to a GoBGP api.Peer.
func peerFromDesired(p model.DesiredPeer) *api.Peer {
	peer := &api.Peer{
		Conf: &api.PeerConf{
			NeighborAddress: p.Address,
			PeerAsn:         uint32(p.PeerASN),
		},
	}

	for _, af := range p.AddressFamilies {
		peer.AfiSafis = append(peer.AfiSafis, &api.AfiSafi{
			Config: &api.AfiSafiConfig{Family: familyFromModel(af)},
		})
	}

	if p.HoldTime > 0 || p.KeepaliveTime > 0 {
		peer.Timers = &api.Timers{
			Config: &api.TimersConfig{
				HoldTime:          uint64(p.HoldTime.Seconds()),
				KeepaliveInterval: uint64(p.KeepaliveTime.Seconds()),
			},
		}
	}

	if p.AuthPassword != "" {
		peer.Conf.AuthPassword = p.AuthPassword
	}

	// Connect on the overlay BGP port (1790). Port 179 is occupied by the
	// underlay FRR bgpd on every node, so GoBGP uses a non-conflicting port.
	peer.Transport = &api.Transport{
		RemotePort:  1790,
		PassiveMode: false,
	}

	return peer
}
