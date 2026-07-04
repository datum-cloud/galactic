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

	"github.com/osrg/gobgp/v4/pkg/apiutil"
	bgp "github.com/osrg/gobgp/v4/pkg/packet/bgp"
	gobgpserver "github.com/osrg/gobgp/v4/pkg/server"
	"github.com/vishvananda/netlink"

	"go.datum.net/galactic/internal/model"
	"go.datum.net/galactic/internal/plumbing/srv6"
	vrfpkg "go.datum.net/galactic/internal/plumbing/vrf"
)

// startRIBMonitor starts the EVPN best-path watcher goroutine once per
// GoBGPRuntime lifetime. It installs and removes kernel SEG6 encap routes in
// the VRF routing tables as remote EVPN Type 5 paths are added or withdrawn.
func (r *GoBGPRuntime) startRIBMonitor(b *gobgpserver.BgpServer, vrfs []model.DesiredVRFInstance) {
	if len(vrfs) == 0 || r.srvCtx == nil {
		slog.Info("startRIBMonitor: skipping — no VRFs or srvCtx is nil", "vrfCount", len(vrfs), "srvCtx", r.srvCtx)
		return
	}
	r.monitorOnce.Do(func() {
		names := make([]string, len(vrfs))
		for i, v := range vrfs {
			names[i] = v.Name
		}
		slog.Info("startRIBMonitor: launching watchEVPNRIB goroutine", "vrfs", names)
		go r.watchEVPNRIB(r.srvCtx, b, vrfs)
	})
}

// vrfTable maps an import RT value to the VRF's kernel routing table ID.
type vrfTable struct {
	name    string
	tableID uint32
}

func (r *GoBGPRuntime) watchEVPNRIB(
	ctx context.Context, b *gobgpserver.BgpServer, vrfInsts []model.DesiredVRFInstance,
) {
	// Build a map from import RT → VRF table info for all VRFs.
	rtToVRF := make(map[string]vrfTable)
	tableIDs := make(map[uint32]struct{})

	for _, vrfInst := range vrfInsts {
		// VRF name is "{vpc}-{vpcAttachment}" in base62 — see bgpVRFInstanceName in cni.go.
		parts := strings.SplitN(vrfInst.Name, "-", 2)
		if len(parts) != 2 {
			slog.Error("watchEVPNRIB: VRF name does not contain '-'", "name", vrfInst.Name)
			continue
		}
		vpc, vpcAtt := parts[0], parts[1]

		tableID, err := vrfpkg.TableID(vpc, vpcAtt)
		if err != nil {
			slog.Error("watchEVPNRIB: failed to get VRF table ID", "vpc", vpc, "vpcAtt", vpcAtt, "err", err)
			continue
		}
		slog.Info("watchEVPNRIB: resolved VRF table", "vpc", vpc, "vpcAtt", vpcAtt, "tableID", tableID)
		tableIDs[tableID] = struct{}{}

		for _, rt := range vrfInst.ImportRouteTargets {
			rtToVRF[rt] = vrfTable{name: vrfInst.Name, tableID: tableID}
		}
	}

	// Probe route write for each unique table ID.
	for tableID := range tableIDs {
		if err := probeRouteWrite(tableID); err != nil {
			slog.Error("watchEVPNRIB: route write probe failed; SEG6 encap routes will not be installed",
				"err", err, "table", tableID,
				"hint", "set runAsUser: 0 and capabilities.add: [NET_ADMIN] in the container securityContext")
			return
		}
	}

	localAddr := r.localAddress
	slog.Info("watchEVPNRIB: registering WatchBestPath", "vrfCount", len(vrfInsts), "localAddr", localAddr)

	watchErr := b.WatchEvent(ctx, gobgpserver.WatchEventMessageCallbacks{
		OnBestPath: func(paths []*apiutil.Path, _ time.Time) {
			for _, path := range paths {
				if path.Family != bgp.RF_EVPN {
					continue
				}
				evpnNLRI, ok := path.Nlri.(*bgp.EVPNNLRI)
				if !ok {
					continue
				}
				ipPrefix, ok := evpnNLRI.RouteTypeData.(*bgp.EVPNIPPrefixRoute)
				if !ok {
					continue
				}
				// Skip locally-originated paths (our own EVPN advertisements).
				if evpnMpReachNexthop(path.Attrs) == localAddr {
					continue
				}

				// Find which VRF(s) this path belongs to by matching communities.
				match := findMatchingVRF(path.Attrs, rtToVRF)
				if match == nil {
					continue
				}

				prefix := addrToIPNet(ipPrefix.IPPrefix, int(ipPrefix.IPPrefixLength))
				gw := addrToNetIP(ipPrefix.GWIPAddress)

				if path.Withdrawal {
					slog.Info("watchEVPNRIB: withdrawing route", "prefix", prefix, "vrf", match.name, "table", match.tableID)
					if delErr := srv6.RouteEgressDel(prefix, match.tableID); delErr != nil {
						slog.Error("watchEVPNRIB: RouteEgressDel failed", "prefix", prefix, "table", match.tableID, "err", delErr)
					}
				} else {
					slog.Info("watchEVPNRIB: installing route", "prefix", prefix, "gw", gw, "vrf", match.name, "table", match.tableID)
					if addErr := srv6.RouteEgressAdd(prefix, gw, match.tableID); addErr != nil {
						slog.Error("watchEVPNRIB: RouteEgressAdd failed",
							"prefix", prefix, "gw", gw, "table", match.tableID, "err", addErr)
					}
				}
			}
		},
	}, gobgpserver.WatchBestPath(true))
	if watchErr != nil {
		slog.Error("watchEVPNRIB: WatchEvent returned error", "err", watchErr)
	}
}

// findMatchingVRF returns the VRF table info for the first matching import RT,
// or nil if no VRF matches the path's communities.
func findMatchingVRF(attrs []bgp.PathAttributeInterface, rtToVRF map[string]vrfTable) *vrfTable {
	ec, ok := func() (*bgp.PathAttributeExtendedCommunities, bool) {
		for _, attr := range attrs {
			if e, ok := attr.(*bgp.PathAttributeExtendedCommunities); ok {
				return e, true
			}
		}
		return nil, false
	}()
	if !ok {
		return nil
	}
	for _, community := range ec.Value {
		if vt, ok := rtToVRF[community.String()]; ok {
			return &vt
		}
	}
	return nil
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
