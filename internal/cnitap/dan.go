// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cnitap

import (
	"crypto/sha256"
	"fmt"
	"net"

	"go.datum.net/galactic/internal/cniipam"
	"go.datum.net/galactic/internal/plumbing/dan"
)

// ipv4TapMask is the prefix length a tap's IPv4 address carries in the guest.
// It matches the mask the host side of the tap is given, so the guest and the
// host agree on what is on-link.
const ipv4TapMask = 25

// writeDANFile hands this attachment to a Kata runtime-rs shim by describing
// it in the sandbox's DAN file.
//
// Callers must treat an error as fatal to CNI ADD. See dan.Write.
func writeDANFile(dir, sandboxID, tapName string, res *cniipam.IPAMResult, mtu int) error {
	document, err := buildDANDocument(tapName, res, mtu)
	if err != nil {
		return fmt.Errorf("build DAN document: %w", err)
	}
	return dan.Write(dir, sandboxID, document)
}

// buildDANDocument describes this attachment to a Kata runtime-rs shim. It
// names the tap to adopt and what the guest should configure on it.
//
// Every value comes from state this plugin already owns, so the shim discovers
// nothing. The document carries exactly one device, because an attachment is
// one interface.
func buildDANDocument(tapName string, res *cniipam.IPAMResult, mtu int) (*dan.Document, error) {
	if res == nil {
		return nil, fmt.Errorf("no addresses were allocated for tap %q", tapName)
	}

	var addresses []string
	routes := []dan.Route{}

	if res.IPv6Subnet != nil {
		addresses = append(addresses, res.IPv6Subnet.String())
	}
	if res.IPv6Gateway != nil {
		routes = append(routes, defaultRoute(res.IPv6Gateway))
	}
	if res.IPv4Address != nil {
		ipv4 := net.IPNet{IP: res.IPv4Address, Mask: net.CIDRMask(ipv4TapMask, 32)}
		addresses = append(addresses, ipv4.String())
	}
	if res.IPv4Gateway != nil {
		routes = append(routes, defaultRoute(res.IPv4Gateway))
	}

	if len(addresses) == 0 {
		return nil, fmt.Errorf("no addresses were allocated for tap %q", tapName)
	}

	return &dan.Document{
		Devices: []dan.Device{{
			Name:     "eth0",
			GuestMAC: guestMAC(tapName).String(),
			Device: dan.DeviceSpec{
				Type:    dan.DeviceTypeHostTap,
				TapName: tapName,
			},
			NetworkInfo: dan.NetworkInfo{
				Interface: dan.Interface{
					IPAddresses: addresses,
					MTU:         mtu,
					Ntype:       dan.InterfaceTypeTap,
				},
				Routes:    routes,
				Neighbors: []any{},
			},
		}},
	}, nil
}

// defaultRoute returns the guest's default route through gateway. An empty
// destination is the default route for the gateway's own family.
func defaultRoute(gateway net.IP) dan.Route {
	return dan.Route{Gateway: gateway.String()}
}

// guestMAC derives the guest interface's address from the tap's name, which
// already encodes the VPC and the attachment.
//
// A derived address stays stable across instance replacement, so a guest or a
// peer holding a neighbor entry sees the same interface come back. The address
// is locally administered and unicast, and the attachment is unique per node,
// so it cannot collide on the link.
func guestMAC(tapName string) net.HardwareAddr {
	sum := sha256.Sum256([]byte(tapName))
	mac := make(net.HardwareAddr, 6)
	copy(mac, sum[:6])
	mac[0] = 0x02
	return mac
}
