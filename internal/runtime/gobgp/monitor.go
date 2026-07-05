// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gobgp

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"time"

	api "github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	bgp "github.com/osrg/gobgp/v4/pkg/packet/bgp"
	gobgpserver "github.com/osrg/gobgp/v4/pkg/server"
	"github.com/vishvananda/netlink"

	"go.datum.net/galactic/internal/plumbing/srv6"
	vrfpkg "go.datum.net/galactic/internal/plumbing/vrf"
)

// startRIBMonitor starts the shared EVPN best-path watcher goroutine once per
// GoBGPRuntime lifetime, regardless of how many VRFs exist. It installs and
// removes kernel SEG6 encap routes in the relevant VRF routing table as
// remote EVPN Type 5 paths are added or withdrawn, dispatching each path to
// its VRF via rtIndex (kept current by applyVRFs) rather than being scoped to
// one VRF — a node can host thousands of VRFs, one per VPC attachment, so a
// dedicated goroutine and WatchEvent subscription per VRF would not scale.
func (r *GoBGPRuntime) startRIBMonitor(b *gobgpserver.BgpServer) {
	if r.srvCtx == nil {
		slog.Info("startRIBMonitor: skipping — srvCtx is nil")
		return
	}
	r.monitorOnce.Do(func() {
		slog.Info("startRIBMonitor: launching shared watchEVPNRIB goroutine")
		go r.watchEVPNRIB(r.srvCtx, b)
	})
}

func (r *GoBGPRuntime) watchEVPNRIB(ctx context.Context, b *gobgpserver.BgpServer) {
	watchErr := b.WatchEvent(ctx, gobgpserver.WatchEventMessageCallbacks{
		OnBestPath: func(paths []*apiutil.Path, _ time.Time) {
			for _, path := range paths {
				r.processEVPNPath(path, "watchEVPNRIB")
			}
		},
	}, gobgpserver.WatchBestPath(true))
	if watchErr != nil {
		slog.Error("watchEVPNRIB: WatchEvent returned error", "err", watchErr)
	}
}

// backfillEVPNRoutes scans the current global EVPN RIB and (re)applies every
// best path against rtIndex. It is called synchronously from applyVRFs right
// after a new VRF is registered, to catch remote paths that were already
// best-path before that VRF's route target existed in rtIndex.
//
// This matters because the shared watchEVPNRIB goroutine starts once for the
// whole runtime and registers WatchBestPath(true), which only replays the
// then-current RIB at that single moment. VRFs are registered incrementally
// as BGPVRFInstance CRDs are reconciled (potentially thousands, arriving over
// time), so a remote path that became best-path before its VRF's RT was
// indexed would otherwise never be installed — WatchBestPath only notifies on
// future changes, not on-demand re-delivery. Since RouteEgressAdd is a
// netlink route replace, re-applying already-installed routes here is a
// harmless no-op.
func (r *GoBGPRuntime) backfillEVPNRoutes(b *gobgpserver.BgpServer) {
	err := b.ListPath(apiutil.ListPathRequest{
		TableType: api.TableType_TABLE_TYPE_GLOBAL,
		Family:    bgp.RF_EVPN,
	}, func(_ bgp.NLRI, paths []*apiutil.Path) {
		for _, path := range paths {
			if !path.Best {
				continue
			}
			r.processEVPNPath(path, "backfillEVPNRoutes")
		}
	})
	if err != nil {
		slog.Error("backfillEVPNRoutes: ListPath failed", "err", err)
	}
}

// processEVPNPath installs or withdraws the kernel SEG6 encap route for a
// single EVPN Type 5 path if it matches a VRF in rtIndex. logPrefix names the
// caller for log correlation (the shared watcher vs. a VRF-registration backfill).
func (r *GoBGPRuntime) processEVPNPath(path *apiutil.Path, logPrefix string) {
	if path.Family != bgp.RF_EVPN {
		return
	}
	evpnNLRI, ok := path.Nlri.(*bgp.EVPNNLRI)
	if !ok {
		return
	}
	ipPrefix, ok := evpnNLRI.RouteTypeData.(*bgp.EVPNIPPrefixRoute)
	if !ok {
		return
	}
	// Skip locally-originated paths (our own EVPN advertisements). Compare the
	// MpReachNLRI next-hop against localAddr rather than GWIPAddress — after
	// the SRv6SID fix, GWIPAddress is the End.DT46 SID (not the BGP peering
	// loopback), so the old check would miss locally-originated paths and try
	// to install a seg6 encap route for our own VPC subnet.
	if evpnMpReachNexthop(path.Attrs) == r.localAddress {
		return
	}

	tableID, ok := r.matchTableID(path.Attrs)
	if !ok {
		return
	}

	prefix := addrToIPNet(ipPrefix.IPPrefix, int(ipPrefix.IPPrefixLength))
	gw := addrToNetIP(ipPrefix.GWIPAddress)

	if path.Withdrawal {
		slog.Info(logPrefix+": withdrawing route", "prefix", prefix, "table", tableID)
		if delErr := srv6.RouteEgressDel(prefix, tableID); delErr != nil {
			slog.Error(logPrefix+": RouteEgressDel failed", "prefix", prefix, "table", tableID, "err", delErr)
		}
	} else {
		slog.Info(logPrefix+": installing route", "prefix", prefix, "gw", gw, "table", tableID)
		if addErr := srv6.RouteEgressAdd(prefix, gw, tableID); addErr != nil {
			slog.Error(logPrefix+": RouteEgressAdd failed", "prefix", prefix, "gw", gw, "table", tableID, "err", addErr)
		}
	}
}

// matchTableID looks up the kernel VRF table that imports one of the
// extended communities on attrs, via the RT index maintained by applyVRFs.
// It returns false if no configured VRF imports any route target on the
// path. This is an O(1)-per-community lookup, not an O(#VRFs) scan, so it
// stays cheap even with thousands of VRFs on the node.
func (r *GoBGPRuntime) matchTableID(attrs []bgp.PathAttributeInterface) (uint32, bool) {
	r.rtIndexMu.RLock()
	defer r.rtIndexMu.RUnlock()
	for _, attr := range attrs {
		ec, ok := attr.(*bgp.PathAttributeExtendedCommunities)
		if !ok {
			continue
		}
		for _, community := range ec.Value {
			if tableID, ok := r.rtIndex[community.String()]; ok {
				return tableID, true
			}
		}
	}
	return 0, false
}

// vrfTableID resolves the kernel VRF table ID for a VRF named "{vpc}-{vpcAttachment}"
// in base62 — see bgpVRFInstanceName in cni.go.
func vrfTableID(vrfName string) (uint32, error) {
	parts := strings.SplitN(vrfName, "-", 2)
	if len(parts) != 2 {
		return 0, fmt.Errorf("VRF name %q does not contain '-'", vrfName)
	}
	return vrfpkg.TableID(parts[0], parts[1])
}

// evpnMpReachNexthop returns the MpReachNLRI next-hop address string from path
// attrs, or empty string if none is found. Used to identify locally-originated
// EVPN paths without relying on GWIPAddress (which is now the SRv6 SID).
func evpnMpReachNexthop(attrs []bgp.PathAttributeInterface) string {
	for _, attr := range attrs {
		if mp, ok := attr.(*bgp.PathAttributeMpReachNLRI); ok {
			return mp.Nexthop.String()
		}
	}
	return ""
}

// addrToIPNet converts a netip.Addr and prefix length to a masked *net.IPNet.
func addrToIPNet(addr netip.Addr, bits int) *net.IPNet {
	masked := netip.PrefixFrom(addr, bits).Masked()
	a := masked.Addr().As16()
	ip := make(net.IP, 16)
	copy(ip, a[:])
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(masked.Bits(), 128)}
}

// addrToNetIP converts a netip.Addr to net.IP (16-byte form).
func addrToNetIP(addr netip.Addr) net.IP {
	a := addr.As16()
	ip := make(net.IP, 16)
	copy(ip, a[:])
	return ip
}

// probeRouteWrite verifies that the process holds the privileges needed to
// install kernel routes into tableID. It installs a test host route from the
// RFC 3849 documentation range (2001:db8::/32) — which can never conflict with
// real VPC traffic — then immediately removes it. This catches a missing
// runAsUser:0 or CAP_NET_ADMIN before the first real EVPN best-path event
// arrives, rather than silently failing minutes later.
func probeRouteWrite(tableID uint32) error {
	lo, err := netlink.LinkByName("lo")
	if err != nil {
		return fmt.Errorf("lookup loopback for probe: %w", err)
	}
	_, dst, _ := net.ParseCIDR("2001:db8:ffff:ffff:ffff:ffff:ffff:fffe/128")
	probe := &netlink.Route{
		Dst:       dst,
		Table:     int(tableID),
		LinkIndex: lo.Attrs().Index,
	}
	if err := netlink.RouteReplace(probe); err != nil {
		return fmt.Errorf("route write probe (missing root or CAP_NET_ADMIN?): %w", err)
	}
	if err := netlink.RouteDel(probe); err != nil {
		slog.Warn("probeRouteWrite: failed to remove probe route", "dst", probe.Dst, "err", err)
	}
	return nil
}
