// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gobgp

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	api "github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	bgp "github.com/osrg/gobgp/v4/pkg/packet/bgp"
	gobgpserver "github.com/osrg/gobgp/v4/pkg/server"

	"go.datum.net/galactic/internal/plumbing/ebpf/attach"
	"go.datum.net/galactic/internal/plumbing/ebpf/egressroutemap"
	"go.datum.net/galactic/internal/plumbing/ebpf/usidmap"
	"go.datum.net/galactic/internal/plumbing/intf"
	"go.datum.net/galactic/internal/plumbing/srv6"
	vrfpkg "go.datum.net/galactic/internal/plumbing/vrf"
)

// pinDir is the bpffs directory probeEgressRouteWrite opens egress_route_table
// from -- a package var defaulting to attach.PinDir, the same test seam
// internal/plumbing/srv6's own pinDir var provides, so this package's tests
// don't depend on a real bpffs mount or root privileges either.
var pinDir = attach.PinDir

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

	// The destination SRv6 SID travels in the BGP Prefix-SID attribute (see
	// prefixSIDAttr in paths.go), not the EVPN route's own Gateway IP field —
	// that field can't carry an IPv6 SID for an IPv4 prefix (RFC 9136 requires
	// the Gateway IP and Prefix to share an address family), so relying on it
	// here silently installed a garbage seg6 segment for every IPv4 VPC
	// prefix. Fall back to the transit next-hop when no Prefix-SID attribute
	// is present (non-SRv6 advertisements — see buildEVPNPaths).
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

// routeInstall is matchTableID's result: which kernel table processEVPNPath
// should install path's route into, and which of srv6's two installers to
// use -- RouteEgressAdd's SEG6 encap (a VRF-scoped tenant path, whose gw
// always resolves to a real uSID decap SID) or RouteMainAdd's plain
// next-hop route (plain is true; see RouteMainAdd's own doc comment for
// why an RT-less path needs this instead).
type routeInstall struct {
	tableID uint32
	plain   bool
}

// matchTableID resolves how to install one EVPN Type 5 path's route.
//
// A path carrying at least one Route Target extended community is a
// tenant VRF route: matchTableID looks up the kernel VRF table that
// imports one of those RTs, via the RT index maintained by applyVRFs, and
// returns false if no VRF configured on this node imports any RT on the
// path (a VRF this node doesn't participate in -- correctly skipped, not
// installed anywhere). This is an O(1)-per-community lookup, not an
// O(#VRFs) scan, so it stays cheap even with thousands of VRFs on the node.
//
// A path carrying no Route Target community at all is not VRF-scoped by
// construction (buildEVPNPaths in paths.go only attaches the extended
// communities attribute "if len(rts) > 0") -- e.g.
// NetworkGatewayReconciler's anycast ingress-VIP advertisements, which
// leave VRFID/Function unset for exactly this reason (that reconciler's
// own package doc comment). Such a path is installed into the kernel's
// main routing table (table ID 0, which both the kernel and this
// vishvananda/netlink call resolve to RT_TABLE_MAIN when left unset) via
// RouteMainAdd's plain routing, not RouteEgressAdd's SEG6 encap -- see that
// function's own doc comment for why. This previously silently dropped
// every anycast VIP path on every node in the mesh (found live: a
// containerlab NetworkGateway/NetworkRule canary's VIP was never reachable
// from any other site, even once BGP itself and the DSR/Maglev datapath
// were both working correctly) -- gated on the absence of any RT
// altogether, not merely a lookup miss, so a genuine unrecognized-VRF path
// still correctly falls through to false above rather than being installed
// into main by accident.
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
// where vpc is hex-encoded per crdnames.BGPVRFInstanceName/VPCSegment. The
// kernel VRF itself is keyed by the base62 vpc alone (it's shared by every
// attachment on this VPC on this node — vrfpkg.TableID needs no node
// component, since interface names only need to be unique within one host's
// own namespace), so only the segment before the first '-' matters here;
// node can itself contain '-' (e.g. "dfw-worker-control"), which is why this
// splits into exactly 2 parts instead of parsing node back out too. The hex
// segment has to be decoded back to base62 before it can be used to build
// the kernel interface name — intf.HexToBase62 naturally errors out on the
// SHA-256 hash fallback form (crdnames.nameSegment's "x..." prefix, for VPCs
// that don't cleanly hex-encode), which is correct here too: that form was
// never recoverable to a real interface name in the first place.
//
// argument is the same value as the owning BGPVRFInstance's own
// Spec.VRFID — used only by the vrf_table fallback below, not by the
// primary netlink lookup.
//
// vrfpkg.TableID's own netlink.LinkList() call is scoped to this
// process's own network namespace — galactic-router runs
// hostNetwork: true, so that's the host's root netns, correct for a VRF
// galactic-cni created there directly for a real tenant pod's own CNI
// attachment. It is structurally blind to a VRF #855's ingress sidecar
// creates instead, which lives entirely inside Envoy's own pod netns by
// design (so its own SO_BINDTODEVICE calls resolve there). Confirmed
// live on us-central-1-staging-lab: a node running only the ingress
// sidecar for a given VPC — no real tenant CNI attachment for it at all
// — never has that VRF's interface visible in its own root netns, so the
// primary lookup fails on every single reconcile, forever; not a race,
// not something a restart or a longer wait fixes.
//
// The fallback below reads vrf_table directly instead of reaching into
// that other netns: internal/ingresssidecar's own ensureEgressDatapath
// already writes this exact (block, argument) -> kernel table ID mapping
// there the moment it creates its own VRF, so usid_ingress's own decap
// path can find it — the same bpffs-pinned map this process already
// opens a second handle onto for vip_xlat_table
// (cmd/galactic-router/root.go). Reading it here needs no new privilege,
// no cross-namespace setns, and no change to the network repo's own CRD
// schema: it's the same value, already published by whoever actually
// created the VRF, through a channel this process already has open.
func vrfTableID(vrfName string, argument int32) (uint32, error) {
	parts := strings.SplitN(vrfName, "-", 2)
	if len(parts) != 2 {
		return 0, fmt.Errorf("VRF name %q does not contain '-'", vrfName)
	}
	vpc, err := intf.HexToBase62(parts[0])
	if err != nil {
		return 0, fmt.Errorf("VRF name %q: could not decode VPC segment %q back to base62: %w", vrfName, parts[0], err)
	}

	tableID, localErr := vrfpkg.TableID(vpc)
	if localErr == nil {
		return tableID, nil
	}

	fallbackID, ok, fallbackErr := vrfTableIDFromRegistry(vpc, argument)
	if fallbackErr != nil {
		return 0, fmt.Errorf("VRF %q: local netlink lookup failed (%w), and vrf_table fallback also failed: %w",
			vrfName, localErr, fallbackErr)
	}
	if !ok {
		return 0, fmt.Errorf(
			"VRF %q: local netlink lookup failed (%w), and no vrf_table entry exists either (vpc=%s argument=%d) "+
				"— this VRF may not exist on this node yet", vrfName, localErr, vpc, argument)
	}
	return fallbackID, nil
}

// vrfTableIDFromRegistry looks up the kernel VRF table ID (vpc, argument)
// maps to in vrf_table — see vrfTableID's own doc comment for why this
// fallback exists. Opens a fresh handle each call via pinDir, the same
// on-demand-open idiom probeEgressRouteWrite (below) already uses for
// egress_route_table, rather than keeping a long-lived handle: this only
// runs on the local-netlink-miss path (once per affected VRF per
// reconcile that needs it), not a per-packet or per-reconcile hot path
// for every VRF.
func vrfTableIDFromRegistry(vpc string, argument int32) (uint32, bool, error) {
	if argument < 0 || argument > math.MaxUint16 {
		return 0, false, fmt.Errorf("argument %d out of range for a uint16 uSID Argument", argument)
	}
	vpcHex, err := intf.Base62ToHex(vpc)
	if err != nil {
		return 0, false, fmt.Errorf("convert vpc %q to hex: %w", vpc, err)
	}
	block, err := strconv.ParseUint(vpcHex, 16, 64)
	if err != nil {
		return 0, false, fmt.Errorf("parse vpc hex %q: %w", vpcHex, err)
	}

	registry, closer, err := usidmap.OpenPinnedRegistry(pinDir)
	if err != nil {
		return 0, false, fmt.Errorf("open pinned vrf_table (missing bpffs mount, BPF capability, or root?): %w", err)
	}
	defer closer.Close() //nolint:errcheck // best-effort close of our own fd, immediately after use

	entry, ok, err := registry.VRF.Get(block, uint16(argument))
	if err != nil {
		return 0, false, fmt.Errorf("vrf_table: get vpc=%s (block=%#x) argument=%#x: %w", vpc, block, argument, err)
	}
	if !ok {
		return 0, false, nil
	}
	return entry.VRFTableID, true, nil
}

// evpnMpReachNexthop returns the MpReachNLRI next-hop address string from path
// attrs, or empty string if none is found. Used to identify locally-originated
// EVPN paths, and as the non-SRv6 fallback gateway when no Prefix-SID
// attribute is present (see evpnPrefixSID).
func evpnMpReachNexthop(attrs []bgp.PathAttributeInterface) string {
	for _, attr := range attrs {
		if mp, ok := attr.(*bgp.PathAttributeMpReachNLRI); ok {
			return mp.Nexthop.String()
		}
	}
	return ""
}

// evpnPrefixSID extracts the destination SRv6 SID from a BGP Prefix-SID path
// attribute's SRv6 L3 Service TLV (RFC 9252), if present. This is the sole
// carrier for the SID in this design — see prefixSIDAttr in paths.go. Unlike
// the EVPN Type 5 route's own Gateway IP field, the Prefix-SID attribute is a
// separate path attribute independent of the NLRI's address family, so it
// carries a SID correctly for both IPv4 and IPv6 VPC prefixes.
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

// addrToIPNet converts a netip.Addr and prefix length to a masked *net.IPNet.
// IPv4 addresses are kept in native 4-byte form: netip.Addr.As16() returns an
// IPv4-mapped 16-byte address, but pairing that with net.CIDRMask(bits, 128)
// sets the mask's leading bits — the wrong end for a 4-in-16 address, whose
// meaningful octets sit in the last 4 bytes — so consumers that reduce the IP
// to 4 bytes (net.IP.To4(), as net.IPNet.String() and vishvananda/netlink's
// family detection both do) see the mask's trailing, unset bits and read the
// prefix length as 0 regardless of bits.
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

// probeEgressRouteWrite verifies that this process can actually write
// egress_route_table entries for tableID before applyVRFs trusts this VRF's
// routing to work at all. It installs a pass-through test entry for a
// prefix from the RFC 3849 documentation range (2001:db8::/32) — which can
// never conflict with real VPC traffic — then immediately removes it. A
// pass-through entry (RegisterPassThrough, not Register) is deliberate:
// unlike a real route, it needs no SID/next-hop resolution, so this probe
// only exercises the one thing it exists to check -- the pinned bpffs map's
// open+write path -- not incidentally depending on some other prefix
// already having a resolvable neighbor.
//
// This replaces an earlier version of this probe that wrote a real kernel
// route via netlink instead (the same RFC 3849 prefix, same install/remove
// shape) -- a leftover check from this codebase's pre-TC-BPF design, when
// RouteEgressAdd really did write kernel SEG6 routes and so really did need
// CAP_NET_ADMIN. Since the TC-BPF migration (see RouteEgressAdd's own doc
// comment in internal/plumbing/srv6/egress.go), installing a VRF's routes
// only ever writes into this pinned eBPF map — never the kernel FIB — so a
// probe that tests kernel route-write capability instead tests a privilege
// this path no longer needs, while never actually verifying the one this
// path does need (a mounted bpffs at pinDir, readable/writable by this
// process). galactic-router's DaemonSet happens to still grant NET_ADMIN
// today (for the unrelated RouteMainAdd/anycast path), which is why the
// old probe kept silently passing rather than ever catching this — but it
// was verifying the wrong thing the whole time.
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
