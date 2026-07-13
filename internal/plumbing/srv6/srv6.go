// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package srv6 manages kernel SRv6 END.DT46 ingress routes for Galactic VPC
// endpoints and computes compressed SRv6 uSIDs (see ComputeSID). Route
// installation accepts a USID (/128) and VPC identifiers to install the decap
// route on the correct host interface and VRF routing table, and requires
// CAP_NET_ADMIN; ComputeSID is pure computation and requires no privilege.
package srv6

import (
	"fmt"
	"net"
	"strings"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"

	"go.datum.net/galactic/internal/plumbing/intf"
	"go.datum.net/galactic/internal/plumbing/vrf"
)

// parseSID returns the /128 IPNet for the given SID string.
// It accepts both bare IPv6 addresses and /128 CIDR notation.
func parseSID(sid string) (*net.IPNet, error) {
	if strings.Contains(sid, "/") {
		_, ipnet, err := net.ParseCIDR(sid)
		if err != nil {
			return nil, fmt.Errorf("invalid sid %q: %w", sid, err)
		}
		return ipnet, nil
	}
	ip := net.ParseIP(sid)
	if ip == nil {
		return nil, fmt.Errorf("invalid sid %q: not an IP address", sid)
	}
	return netlink.NewIPNet(ip), nil
}

// RouteIngressAdd installs an SRv6 END.DT46 ingress route for the given USID.
// The VPC and VPCAttachment identifiers (base62-encoded) are used to resolve
// the host interface and VRF routing table.
func RouteIngressAdd(sid, vpc, vpcAttachment string) error {
	ipnet, err := parseSID(sid)
	if err != nil {
		return err
	}
	if err := addIngressRoute(ipnet, vpc, vpcAttachment); err != nil {
		return fmt.Errorf("add ingress route failed: %w", err)
	}
	return nil
}

// RouteIngressDel removes the SRv6 END.DT46 ingress route previously installed
// by RouteIngressAdd for the given USID.
func RouteIngressDel(sid, vpc, vpcAttachment string) error {
	ipnet, err := parseSID(sid)
	if err != nil {
		return err
	}
	if err := deleteIngressRoute(ipnet, vpc, vpcAttachment); err != nil {
		return fmt.Errorf("delete ingress route failed: %w", err)
	}
	return nil
}

func addIngressRoute(ip *net.IPNet, vpc, vpcAttachment string) error {
	dev := intf.GenerateInterfaceNameHost(vpc, vpcAttachment)
	link, err := netlink.LinkByName(dev)
	if err != nil {
		return err
	}

	vrfID, err := vrf.TableID(vpc, vpcAttachment)
	if err != nil {
		return err
	}

	var flags [nl.SEG6_LOCAL_MAX]bool
	flags[nl.SEG6_LOCAL_ACTION] = true
	flags[nl.SEG6_LOCAL_VRFTABLE] = true
	encap := &netlink.SEG6LocalEncap{
		Action:   nl.SEG6_LOCAL_ACTION_END_DT46,
		Flags:    flags,
		VrfTable: int(vrfID),
	}
	return netlink.RouteReplace(&netlink.Route{
		Dst:       ip,
		LinkIndex: link.Attrs().Index,
		Encap:     encap,
	})
}

func deleteIngressRoute(ip *net.IPNet, vpc, vpcAttachment string) error {
	dev := intf.GenerateInterfaceNameHost(vpc, vpcAttachment)
	link, err := netlink.LinkByName(dev)
	if err != nil {
		return err
	}

	return netlink.RouteDel(&netlink.Route{
		Dst:       ip,
		LinkIndex: link.Attrs().Index,
		Encap:     &netlink.SEG6LocalEncap{},
	})
}
