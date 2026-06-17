// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package srv6 manages kernel SRv6 END.DT46 ingress routes for Galactic VPC
// endpoints. It decodes SRv6 SIDs to extract VPC identity and delegates route
// installation to the Linux kernel via netlink. Requires CAP_NET_ADMIN.
package srv6

import (
	"fmt"
	"net"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"

	"go.datum.net/galactic/internal/plumbing/intf"
	"go.datum.net/galactic/internal/plumbing/vrf"
)

// RouteIngressAdd installs an SRv6 END.DT46 ingress route for the given SRv6
// SID, decoding the embedded VPC and VPCAttachment to locate the correct host
// interface and VRF routing table.
func RouteIngressAdd(ipStr string) error {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return fmt.Errorf("invalid ip: %s", ipStr)
	}
	vpc, vpcAttachment, err := intf.DecodeSRv6Endpoint(ip)
	if err != nil {
		return fmt.Errorf("could not extract SRv6 endpoint: %w", err)
	}
	vpc, err = intf.HexToBase62(vpc)
	if err != nil {
		return fmt.Errorf("invalid vpc: %w", err)
	}
	vpcAttachment, err = intf.HexToBase62(vpcAttachment)
	if err != nil {
		return fmt.Errorf("invalid vpcattachment: %w", err)
	}
	if err := addIngressRoute(netlink.NewIPNet(ip), vpc, vpcAttachment); err != nil {
		return fmt.Errorf("add ingress route failed: %w", err)
	}
	return nil
}

// RouteIngressDel removes the SRv6 END.DT46 ingress route previously installed
// by RouteIngressAdd for the given SRv6 SID.
func RouteIngressDel(ipStr string) error {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return fmt.Errorf("invalid ip: %s", ipStr)
	}
	vpc, vpcAttachment, err := intf.DecodeSRv6Endpoint(ip)
	if err != nil {
		return fmt.Errorf("could not extract SRv6 endpoint: %w", err)
	}
	vpc, err = intf.HexToBase62(vpc)
	if err != nil {
		return fmt.Errorf("invalid vpc: %w", err)
	}
	vpcAttachment, err = intf.HexToBase62(vpcAttachment)
	if err != nil {
		return fmt.Errorf("invalid vpcattachment: %w", err)
	}
	if err := deleteIngressRoute(netlink.NewIPNet(ip), vpc, vpcAttachment); err != nil {
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
