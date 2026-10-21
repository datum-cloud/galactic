// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package ingresssidecar

import (
	"errors"
	"fmt"
	"net"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const gatewayReplyFilterPriority = 100

// ensureGatewayReplyRedirect sends replies arriving on eth0 into the VPC's
// VRF-slave veth before the kernel selects a TCP socket. Envoy binds its
// upstream sockets to the VRF with SO_BINDTODEVICE. A local or main-table
// route alone delivers the reply in the default L3 domain, where it cannot
// match that socket. The destination /128 limits this redirect to the gateway
// address assigned to this VPC on this pod.
func ensureGatewayReplyRedirect(addr net.IP, inner netlink.Link) error {
	eth0, err := netlink.LinkByName(primaryPodInterface)
	if err != nil {
		return fmt.Errorf("look up pod interface for gateway reply %s: %w", addr, err)
	}
	if err := ensureGatewayReplyClsact(eth0); err != nil {
		return err
	}

	filters, err := gatewayReplyFilters(eth0)
	if err != nil {
		return err
	}
	for _, filter := range filters {
		if !filter.DestIP.Equal(addr) {
			continue
		}
		if len(filter.Actions) == 1 {
			if action, ok := filter.Actions[0].(*netlink.MirredAction); ok &&
				action.Ifindex == inner.Attrs().Index && action.MirredAction == netlink.TCA_INGRESS_REDIR {
				return nil
			}
		}
		if err := netlink.FilterDel(filter); err != nil {
			return fmt.Errorf("replace gateway reply filter for %s: %w", addr, err)
		}
	}

	action := netlink.NewMirredAction(inner.Attrs().Index)
	action.MirredAction = netlink.TCA_INGRESS_REDIR
	filter := &netlink.Flower{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: eth0.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_INGRESS,
			Priority:  gatewayReplyFilterPriority,
			Protocol:  unix.ETH_P_IPV6,
		},
		DestIP:     addr,
		DestIPMask: net.CIDRMask(net.IPv6len*8, net.IPv6len*8),
		EthType:    unix.ETH_P_IPV6,
		Actions:    []netlink.Action{action},
	}
	if err := netlink.FilterAdd(filter); err != nil {
		return fmt.Errorf("install gateway reply redirect for %s on %s: %w", addr, inner.Attrs().Name, err)
	}
	return nil
}

func ensureGatewayReplyClsact(link netlink.Link) error {
	qdiscs, err := netlink.QdiscList(link)
	if err != nil {
		return fmt.Errorf("list qdiscs on %s: %w", link.Attrs().Name, err)
	}
	for _, qdisc := range qdiscs {
		if _, ok := qdisc.(*netlink.Clsact); ok {
			return nil
		}
	}
	qdisc := &netlink.Clsact{QdiscAttrs: netlink.QdiscAttrs{
		LinkIndex: link.Attrs().Index,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_CLSACT,
	}}
	if err := netlink.QdiscAdd(qdisc); err != nil && !errors.Is(err, unix.EEXIST) {
		return fmt.Errorf("add clsact qdisc on %s: %w", link.Attrs().Name, err)
	}
	return nil
}

func gatewayReplyFilters(link netlink.Link) ([]*netlink.Flower, error) {
	all, err := netlink.FilterList(link, netlink.HANDLE_MIN_INGRESS)
	if err != nil {
		return nil, fmt.Errorf("list gateway reply filters on %s: %w", link.Attrs().Name, err)
	}
	var filters []*netlink.Flower
	for _, filter := range all {
		flower, ok := filter.(*netlink.Flower)
		if ok && flower.Attrs().Priority == gatewayReplyFilterPriority && flower.Attrs().Protocol == unix.ETH_P_IPV6 {
			filters = append(filters, flower)
		}
	}
	return filters, nil
}

func removeGatewayReplyRedirect(vpc string) error {
	prefix, nodeID := gatewayAddressAssignment()
	if prefix == nil {
		return nil
	}
	addr, err := DeriveGatewayAddress(prefix, vpc, nodeID)
	if err != nil {
		return fmt.Errorf("derive gateway address for vpc %s: %w", vpc, err)
	}
	eth0, err := netlink.LinkByName(primaryPodInterface)
	if err != nil {
		return fmt.Errorf("look up pod interface for gateway reply %s: %w", addr, err)
	}
	filters, err := gatewayReplyFilters(eth0)
	if err != nil {
		return err
	}
	for _, filter := range filters {
		if filter.DestIP.Equal(addr) {
			if err := netlink.FilterDel(filter); err != nil {
				return fmt.Errorf("delete gateway reply filter for %s: %w", addr, err)
			}
		}
	}
	return nil
}
