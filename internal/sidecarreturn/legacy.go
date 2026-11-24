// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package sidecarreturn handles the legacy ingress sidecar's host return route
// during promotion of the shared SRv6 row to the canonical VPC table.
package sidecarreturn

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"

	"github.com/vishvananda/netlink"
	"sigs.k8s.io/controller-runtime/pkg/client"

	bgpv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	"go.datum.net/galactic/internal/crdnames"
	"go.datum.net/galactic/internal/plumbing/ebpf/attach"
	"go.datum.net/galactic/internal/plumbing/ebpf/uformat"
	"go.datum.net/galactic/internal/plumbing/ebpf/usidmap"
	"go.datum.net/galactic/internal/plumbing/intf"
)

const (
	// TableBase is the base of the legacy installer range, with one table per
	// valid uSID Argument. Canonical host VRFs use IDs below it.
	TableBase = 0xF000
	// RouteProtocol marks the compatibility route for cleanup.
	RouteProtocol netlink.RouteProtocol = 249
	// RouteMetric leaves the Worker IPv6 route (1024) preferred.
	RouteMetric = 2048

	Attachment  = "ingress"
	HostIfindex = "galactic.datum.net/ingress-host-ifindex"
	HostMAC     = "galactic.datum.net/ingress-host-mac"
)

type Scope struct {
	K8s       client.Reader
	Namespace string
	Node      string
	VPC       string
	Router    string
}

type Endpoint struct {
	Prefix  netip.Prefix
	Ifindex int
	MAC     net.HardwareAddr
}

func (e Endpoint) Route(table uint32) netlink.Route {
	return netlink.Route{
		Dst:       &net.IPNet{IP: e.Prefix.Addr().AsSlice(), Mask: net.CIDRMask(128, 128)},
		LinkIndex: e.Ifindex, Table: int(table), Scope: netlink.SCOPE_LINK,
		Priority: RouteMetric, Protocol: RouteProtocol,
	}
}

func HostPrefix(raw bgpv1alpha1.Prefix) (netip.Prefix, bool) {
	prefix, err := netip.ParsePrefix(string(raw))
	return prefix, err == nil && prefix.Bits() == 128 && prefix.Addr().Is6() &&
		!prefix.Addr().Is4In6() && prefix.Addr().IsGlobalUnicast()
}

func LegacyLink(link netlink.Link) bool {
	return link.Type() == "veth" && !intf.IsGalacticLinkName(link.Attrs().Name) && !attach.IsInternalLink(link)
}

func (s Scope) advertisementName() string {
	return crdnames.BGPAdvertisementName(s.VPC, Attachment, s.Node)
}

// Endpoints verifies the advertisement identifies the legacy sidecar for
// this VPC and node, using the Argument from the live VRF instance.
func (s Scope) Endpoints(adv *bgpv1alpha1.BGPAdvertisement, argument uint16) []Endpoint {
	if adv.Name != s.advertisementName() || adv.Spec.RouterRef.Name != s.Router ||
		adv.Spec.VRFID == nil || *adv.Spec.VRFID != int32(argument) ||
		adv.Spec.Function == nil || *adv.Spec.Function != bgpv1alpha1.SRv6FunctionEndDT46 ||
		crdnames.HasCNIContainer(adv.Annotations) {
		return nil
	}
	ifindex, indexErr := strconv.Atoi(adv.Annotations[HostIfindex])
	mac, macErr := net.ParseMAC(adv.Annotations[HostMAC])
	if indexErr != nil || ifindex <= 0 || macErr != nil || len(mac) != 6 {
		return nil
	}
	var endpoints []Endpoint
	for _, raw := range adv.Spec.Prefixes {
		if prefix, ok := HostPrefix(raw); ok {
			endpoints = append(endpoints, Endpoint{Prefix: prefix, Ifindex: ifindex, MAC: mac})
		}
	}
	return endpoints
}

// LegacyRow identifies a row written by the old host installer. The sidecar
// itself owns its separate block and table range inside the pod namespace.
func LegacyRow(row usidmap.VRFEntry) bool {
	return row.Block != uformat.BlockIngressSidecar &&
		row.Argument >= uformat.ArgumentMin && row.Argument <= uformat.ArgumentMax &&
		row.VRFTableID == TableBase+uint32(row.Argument) && row.EgressKind == usidmap.EgressKindVeth
}

// Preserve installs any live legacy route in the canonical VPC table before
// a caller redirects the SRv6 row. The old route's interface and permanent
// neighbor are shared by both tables. The caller holds the VPC write fence
// across this check and its map update. The installer handles subsequent
// reconciliation and cleanup.
func (s Scope) Preserve(ctx context.Context, row usidmap.VRFEntry, table uint32) error {
	if !LegacyRow(row) {
		return nil
	}
	var adv bgpv1alpha1.BGPAdvertisement
	if err := s.K8s.Get(ctx, client.ObjectKey{Namespace: s.Namespace, Name: s.advertisementName()}, &adv); err != nil {
		return client.IgnoreNotFound(err)
	}
	for _, e := range s.Endpoints(&adv, row.Argument) {
		link, err := netlink.LinkByIndex(e.Ifindex)
		var missing netlink.LinkNotFoundError
		if errors.As(err, &missing) {
			continue
		}
		if err != nil {
			return err
		}
		if !LegacyLink(link) {
			continue
		}
		oldRoute := e.Route(row.VRFTableID)
		routes, err := netlink.RouteListFiltered(netlink.FAMILY_V6, &oldRoute,
			netlink.RT_FILTER_TABLE|netlink.RT_FILTER_DST|netlink.RT_FILTER_OIF)
		if err != nil {
			return err
		}
		if len(routes) == 0 {
			continue
		}
		route := e.Route(table)
		if err := netlink.RouteReplace(&route); err != nil {
			return fmt.Errorf("preserve legacy gateway %s in table %d: %w", e.Prefix, table, err)
		}
	}
	return nil
}
