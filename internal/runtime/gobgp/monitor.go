// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gobgp

import (
	"context"
	"errors"
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

	"go.datum.net/galactic/internal/plumbing/ebpf/attach"
	"go.datum.net/galactic/internal/plumbing/ebpf/egressroutemap"
	"go.datum.net/galactic/internal/plumbing/intf"
	"go.datum.net/galactic/internal/plumbing/srv6"
	vrfpkg "go.datum.net/galactic/internal/plumbing/vrf"
)

// pinDir is the bpffs directory probeEgressRouteWrite opens
// egress_route_table from. A package var so tests need no bpffs mount or
// root.
var pinDir = attach.PinDir

// errVRFNotInThisNetns marks the one vrfTableID failure that is an ordinary
// condition rather than a fault: the VRF exists, but not in this process's
// network namespace. applyVRFs skips such a VRF at debug level, since there is
// nothing for this process to install for it anyway.
var errVRFNotInThisNetns = errors.New("kernel VRF interface is not in this process's network namespace")

// startRIBMonitor starts the shared EVPN best-path watcher goroutine, once per
// runtime lifetime however many VRFs exist. It installs and removes routes in
// the relevant VRF routing table as remote EVPN Type 5 paths are added and
// withdrawn, dispatching each path to its VRF through the route-target index.
// One goroutine and subscription for all VRFs, because a node can host
// thousands and one per VRF would not scale.
func (r *GoBGPRuntime) startRIBMonitor(b *gobgpserver.BgpServer) {
	if r.srvCtx == nil {
		slog.Info("startRIBMonitor: skipping — srvCtx is nil")
		return
	}
	r.monitorOnce.Do(func() {
		slog.Info("startRIBMonitor: launching shared watchEVPNRIB goroutine")
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			r.watchEVPNRIB(r.srvCtx, b)
		}()
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

// backfillEVPNRoutes scans the current global EVPN RIB and reapplies every best
// path against the route-target index. applyVRFs calls it synchronously right
// after registering a new VRF, to catch remote paths that were already best
// path before that VRF's route target was indexed.
//
// The shared watcher registers for best-path notifications once and replays the
// RIB only at that moment, while VRFs are registered incrementally as CRDs are
// reconciled. Without this, a path that became best before its route target was
// indexed would never be installed, since the watch notifies only on future
// changes. Reapplying an already-installed route is a harmless replace.
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

// processEVPNPath installs or withdraws the route for a single EVPN Type 5 path
// when it matches a known VRF. logPrefix names the caller, the shared watcher
// or a registration backfill, for log correlation.
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
	// Skip locally-originated paths (our own EVPN advertisements), identified
	// by the MpReachNLRI next-hop matching our own address.
	if evpnMpReachNexthop(path.Attrs) == r.localAddress {
		return
	}

	install, ok := r.matchTableID(path.Attrs)
	if !ok {
		return
	}
	tableID := install.tableID

	prefix := addrToIPNet(ipPrefix.IPPrefix, int(ipPrefix.IPPrefixLength))

	if path.Withdrawal {
		slog.Info(logPrefix+": withdrawing route", "prefix", prefix, "table", tableID, "plain", install.plain)
		var delErr error
		if install.plain {
			delErr = srv6.RouteMainDel(prefix, tableID)
		} else {
			delErr = srv6.RouteEgressDel(prefix, tableID)
		}
		if delErr != nil {
			slog.Error(logPrefix+": route delete failed", "prefix", prefix, "table", tableID, "err", delErr)
		}
		return
	}

	// The destination SID travels in the BGP Prefix-SID attribute, not the EVPN
	// route's Gateway IP field. That field cannot carry an IPv6 SID for an IPv4
	// prefix, since RFC 9136 requires the Gateway IP and Prefix to share an
	// address family, so reading it installs a garbage segment for every IPv4
	// VPC prefix. Fall back to the transit next hop for non-SRv6
	// advertisements, which carry no Prefix-SID.
	gw, ok := evpnPrefixSID(path.Attrs)
	if !ok {
		if nh := evpnMpReachNexthop(path.Attrs); nh != "" {
			if addr, err := netip.ParseAddr(nh); err == nil {
				gw = addrToNetIP(addr)
			}
		}
	}

	slog.Info(logPrefix+": installing route", "prefix", prefix, "gw", gw, "table", tableID, "plain", install.plain)
	var addErr error
	if install.plain {
		addErr = srv6.RouteMainAdd(prefix, gw, tableID)
	} else {
		addErr = srv6.RouteEgressAdd(prefix, gw, tableID)
	}
	if addErr != nil {
		slog.Error(logPrefix+": route install failed", "prefix", prefix, "gw", gw, "table", tableID, "err", addErr)
	}
}

// routeInstall is matchTableID's result: which kernel table the route belongs
// in, and which installer to use. plain selects an ordinary next-hop route for
// a path with no route target; otherwise the route is encapsulated toward a
// uSID decap SID.
type routeInstall struct {
	tableID uint32
	plain   bool
}

// matchTableID resolves how to install one EVPN Type 5 path's route, and
// reports false when the path belongs to no VRF this node participates in.
//
// A path carrying at least one route target is a tenant VRF route. It is looked
// up in the route-target index applyVRFs maintains, an O(1) lookup per
// community rather than a scan over VRFs, so it stays cheap with thousands on a
// node.
//
// A path carrying no route target is not VRF-scoped by construction, since the
// extended communities attribute is attached only when there is at least one.
// The anycast ingress-VIP advertisements are the case today, and they leave
// VRFID and Function unset for exactly this reason. Such a path goes into the
// main routing table as a plain route rather than an encapsulated one.
//
// The distinction is on the absence of any route target, not on a lookup miss,
// so a path naming a VRF this node does not have still returns false rather
// than landing in the main table by accident.
func (r *GoBGPRuntime) matchTableID(attrs []bgp.PathAttributeInterface) (routeInstall, bool) {
	r.rtIndexMu.RLock()
	defer r.rtIndexMu.RUnlock()

	var sawRouteTarget bool
	for _, attr := range attrs {
		ec, ok := attr.(*bgp.PathAttributeExtendedCommunities)
		if !ok {
			continue
		}
		for _, community := range ec.Value {
			sawRouteTarget = true
			if tableID, ok := r.rtIndex[community.String()]; ok {
				return routeInstall{tableID: tableID}, true
			}
		}
	}
	if !sawRouteTarget {
		return routeInstall{plain: true}, true
	}
	return routeInstall{}, false
}

// vrfTableID resolves the kernel VRF table ID for a VRF named "{vpc}-{node}",
// where vpc is hex-encoded.
//
// The kernel VRF is keyed by the base62 vpc alone, since it is shared by every
// attachment on this VPC on this node and interface names need only be unique
// within one host. Only the segment before the first '-' matters, which is why
// this splits into exactly two parts: a node name may itself contain '-'. The
// hex segment is decoded back to base62 to build the interface name, which
// naturally errors on the hash fallback form used for a VPC that does not
// cleanly hex-encode. That form was never recoverable to an interface name.
//
// A VRF absent from this process's netns is reported by wrapping
// errVRFNotInThisNetns, so applyVRFs treats it as an ordinary skip.
//
// The underlying link lookup is scoped to this process's namespace. This
// process runs with host networking, which is correct for a VRF the CNI created
// there for a tenant pod, and structurally blind to one the ingress sidecar
// creates inside an Envoy pod's namespace so its own socket binds resolve
// there. On a node running only the sidecar for a VPC, that lookup fails on
// every reconcile and no restart or wait changes it.
//
// Skipping quietly is the honest handling. On such a node the egress routes
// this table ID would install are already written per-EndpointSlice by the
// sidecar itself, and Envoy only connects to backends those slices published,
// so there is nothing for this process to add.
func vrfTableID(vrfName string) (uint32, error) {
	parts := strings.SplitN(vrfName, "-", 2)
	if len(parts) != 2 {
		return 0, fmt.Errorf("VRF name %q does not contain '-'", vrfName)
	}
	vpc, err := intf.HexToBase62(parts[0])
	if err != nil {
		return 0, fmt.Errorf("VRF name %q: could not decode VPC segment %q back to base62: %w", vrfName, parts[0], err)
	}

	tableID, err := vrfpkg.TableID(vpc)
	if err != nil {
		if errors.Is(err, vrfpkg.ErrNotFound) {
			return 0, fmt.Errorf("VRF %q: %w: %w", vrfName, errVRFNotInThisNetns, err)
		}
		return 0, fmt.Errorf("VRF %q: %w", vrfName, err)
	}
	return tableID, nil
}

// evpnMpReachNexthop returns the MpReachNLRI next-hop address from attrs, or ""
// when none is found. It identifies locally-originated paths, and serves as the
// gateway for a path carrying no Prefix-SID attribute.
func evpnMpReachNexthop(attrs []bgp.PathAttributeInterface) string {
	for _, attr := range attrs {
		if mp, ok := attr.(*bgp.PathAttributeMpReachNLRI); ok {
			return mp.Nexthop.String()
		}
	}
	return ""
}

// evpnPrefixSID extracts the destination SRv6 SID from a BGP Prefix-SID
// attribute's SRv6 L3 Service TLV, reporting whether one was present. It is the
// only carrier for the SID in this design. Being a separate path attribute,
// independent of the NLRI's address family, it carries a SID correctly for both
// IPv4 and IPv6 VPC prefixes.
func evpnPrefixSID(attrs []bgp.PathAttributeInterface) (net.IP, bool) {
	for _, attr := range attrs {
		psid, ok := attr.(*bgp.PathAttributePrefixSID)
		if !ok {
			continue
		}
		for _, tlv := range psid.TLVs {
			svc, ok := tlv.(*bgp.SRv6ServiceTLV)
			if !ok || svc.Type != bgp.TLVTypeSRv6L3Service {
				continue
			}
			for _, sub := range svc.SubTLVs {
				info, ok := sub.(*bgp.SRv6InformationSubTLV)
				if !ok || len(info.SID) == 0 {
					continue
				}
				return net.IP(info.SID), true
			}
		}
	}
	return nil, false
}

// addrToIPNet converts addr and a prefix length of bits to a masked *net.IPNet.
//
// IPv4 addresses are kept in native 4-byte form. An IPv4-mapped 16-byte address
// paired with a 128-bit mask sets the mask's leading bits, the wrong end for an
// address whose meaningful octets are the last four, so any consumer that
// reduces the address to 4 bytes reads the prefix length as 0 whatever bits
// says.
func addrToIPNet(addr netip.Addr, bits int) *net.IPNet {
	masked := netip.PrefixFrom(addr, bits).Masked()
	if masked.Addr().Is4() {
		a := masked.Addr().As4()
		ip := make(net.IP, 4)
		copy(ip, a[:])
		return &net.IPNet{IP: ip, Mask: net.CIDRMask(masked.Bits(), 32)}
	}
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

// probeEgressRouteWrite verifies that this process can write
// egress_route_table entries for tableID, before applyVRFs trusts this VRF's
// routing to work. It installs a pass-through entry for a prefix from the RFC
// 3849 documentation range, which can never conflict with real traffic, then
// removes it.
//
// A pass-through entry rather than a real route: it needs no SID or next-hop
// resolution, so the probe exercises only the pinned map's open and write path
// and does not incidentally depend on some prefix having a resolvable
// neighbor.
//
// Probing the map rather than the kernel FIB is the point. Installing a VRF's
// routes writes only into this map, so a probe of kernel route-write capability
// would test a privilege this path no longer needs while never checking the one
// it does: a mounted bpffs at pinDir this process can read and write.
func probeEgressRouteWrite(tableID uint32) error {
	table, closer, err := egressroutemap.OpenPinnedEgressRouteTable(pinDir)
	if err != nil {
		return fmt.Errorf("open pinned egress_route_table (missing bpffs mount, BPF capability, or root?): %w", err)
	}
	defer closer.Close() //nolint:errcheck // best-effort close of our own fd, immediately after use

	_, probe, _ := net.ParseCIDR("2001:db8:ffff:ffff:ffff:ffff:ffff:fffe/128")
	if err := table.RegisterPassThrough(tableID, probe); err != nil {
		return fmt.Errorf("egress_route_table write probe: %w", err)
	}
	if err := table.Unregister(tableID, probe); err != nil {
		slog.Warn("probeEgressRouteWrite: failed to remove probe entry", "prefix", probe, "err", err)
	}
	return nil
}
