// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gc

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"go.datum.net/galactic/internal/crdnames"
	"go.datum.net/galactic/internal/plumbing/ebpf/attachreg"
	"go.datum.net/galactic/internal/plumbing/ebpf/egressroutemap"
	"go.datum.net/galactic/internal/plumbing/ebpf/uformat"
	"go.datum.net/galactic/internal/plumbing/srv6"
	bgpv1alpha1 "go.datum.net/network/api/v1alpha1"
)

// hostLinkNameRegex matches the host-side interface name the master plugins
// create for an attachment, "G%09s%03sH": the zero-padded base62 VPC and
// VPCAttachment.
var hostLinkNameRegex = regexp.MustCompile(`^G([A-Za-z0-9]{9})([A-Za-z0-9]{3})H$`)

// The kernel and resolution calls RepairAttachmentDatapath makes, indirected so
// tests can substitute fabricated state and in-memory maps.
var (
	openDatapathMapsFn = attachreg.OpenPinnedMaps
	listRoutesFn       = func(tableID uint32, family int) ([]netlink.Route, error) {
		return netlink.RouteListFiltered(family, &netlink.Route{Table: int(tableID)}, netlink.RT_FILTER_TABLE)
	}
	listAddrsFn                                    = netlink.AddrList
	linkByIndexFn                                  = netlink.LinkByIndex
	resolvePublicUplinkFn attachreg.UplinkResolver = srv6.ResolvePublicUplink
)

// DatapathRepairConfig is RepairAttachmentDatapath's input beyond the
// Kubernetes client.
type DatapathRepairConfig struct {
	Namespace string
	NodeName  string
	// PinDir is the bpffs directory holding the uSID datapath's pinned maps.
	PinDir string
	// Egress is the conflist's egress configuration, the same CNI ADD uses
	// for a VRF's shard routes.
	Egress attachreg.EgressConfig
	// ForeignTableID reports a VRF routing table another writer on this node
	// owns. An attachment enslaved to one is left alone. Nil reports none.
	ForeignTableID func(tableID uint32) bool
}

// DatapathRepairResult reports one RepairAttachmentDatapath pass.
type DatapathRepairResult struct {
	// Rebuilt counts the rows written, per map.
	Rebuilt attachreg.Counts
	// Attachments is how many attachments the pass matched to a
	// BGPVRFInstance and examined.
	Attachments int
	// Skipped is how many host-named interfaces the pass left alone: not
	// enslaved to a VRF, in a table another writer owns, of an unknown link
	// type, or whose BGPVRFInstance has an out-of-range VRFID.
	Skipped int
	// Pending is how many attachment interfaces the pass could not repair yet
	// because this node's BGPRouter or the VPC's BGPVRFInstance is not found.
	// Either may still be on its way, so a caller wanting a prompt repair
	// retries while Pending is non-zero.
	Pending int
	// UplinkErr reports a missing public_uplink_table row that could not be
	// rebuilt because the uplink's neighbor has not resolved. It is not a
	// failure of the pass.
	UplinkErr error
}

// discoveredAttachment is one attachment found in the kernel, with the name and
// VRF master its rows were derived from, so the pass can tell whether the
// interface was replaced while they were written.
type discoveredAttachment struct {
	attachreg.Attachment
	name        string
	masterIndex int
}

// RepairAttachmentDatapath rebuilds the uSID datapath rows CNI ADD writes for
// every attachment on nodeName, and this node's own, that are missing from the
// maps pinned under cfg.PinDir. CNI ADD is the only other writer of those
// rows, so a map recreated empty stays empty until each attachment re-attaches
// without this.
//
// Attachments are found in the kernel: every interface named like a host-side
// attachment interface and enslaved to a VRF. The VRF's table supplies the
// routing table ID, the link type the egress kind, the routes in that table
// out the interface and the interface's own non-link-local addresses the local
// prefixes and gateways. The attachment's BGPAdvertisement adds the guest
// prefixes ADD took from the IPAM result, which a family with no gateway never
// routes in the kernel. The Block and Node-ID come from nodeName's BGPRouter,
// and the Argument from the VPC's BGPVRFInstance on that router.
//
// Only a missing row is written. A row that exists is left alone, whoever
// wrote it, and nothing is ever written under the ingress sidecar's Block.
// cfg.ForeignTableID is what keeps the pass off the sidecar return path's
// tables: in the case this repairs, vrf_table may itself be empty, so the
// sidecar's own vrf_table rows, which also mark its tables, may be gone too.
//
// Attachments are repaired in ascending host ifindex order, so the shared
// per-VRF rows FillVRF writes come from the lowest-numbered attachment.
//
// A pin directory that does not exist, or a router with no SRv6 identity, is
// nothing to repair and returns a zero result. A node with attachment
// interfaces but no BGPRouter yet reports them in Pending. Every attachment is
// attempted until ctx ends; the error joins every failure.
func RepairAttachmentDatapath(
	ctx context.Context, k8s client.Client, cfg DatapathRepairConfig,
) (DatapathRepairResult, error) {
	var result DatapathRepairResult

	if _, err := os.Stat(cfg.PinDir); err != nil {
		return result, nil
	}

	node, routerName, found, err := nodeSRv6Identity(ctx, k8s, cfg.Namespace, cfg.NodeName)
	if err != nil {
		return result, err
	}
	if !found {
		result.Pending, err = countHostAttachments()
		return result, err
	}
	if !node.Configured() {
		return result, nil
	}
	block, err := node.Block()
	if err != nil {
		return result, fmt.Errorf("derive this node's uSID Block: %w", err)
	}
	if block == uformat.BlockIngressSidecar {
		return result, fmt.Errorf("BGPRouter %s locator %s maps to the ingress sidecar's reserved Block",
			routerName, node.Locator)
	}

	vrfIDs, err := vrfIDsForRouter(ctx, k8s, cfg.Namespace, routerName)
	if err != nil {
		return result, err
	}
	advertised, err := addressingForRouter(ctx, k8s, cfg.Namespace, routerName)
	if err != nil {
		return result, err
	}

	maps, closer, err := openDatapathMapsFn(cfg.PinDir)
	if err != nil {
		return result, fmt.Errorf("open pinned uSID datapath maps: %w", err)
	}
	defer func() { _ = closer.Close() }()

	sidecarTables, err := egressroutemap.SidecarOwnedTableIDs(maps.Registry.VRF)
	if err != nil {
		return result, err
	}
	foreign := func(tableID uint32) bool {
		if _, ok := sidecarTables[tableID]; ok {
			return true
		}
		return cfg.ForeignTableID != nil && cfg.ForeignTableID(tableID)
	}

	attachments, counts, err := discoverAttachments(cfg.NodeName, block, vrfIDs, advertised, foreign)
	result.Skipped, result.Pending = counts.skipped, counts.pending
	if err != nil {
		return result, err
	}
	result.Attachments = len(attachments)
	if len(attachments) == 0 {
		return result, nil
	}

	var errs []error
	nodeRows, uplinkErr, err := maps.FillNode(node, resolvePublicUplinkFn)
	result.Rebuilt.Add(nodeRows)
	result.UplinkErr = uplinkErr
	if err != nil {
		errs = append(errs, fmt.Errorf("this node's rows: %w", err))
	}

	for i, a := range attachments {
		if err := ctx.Err(); err != nil {
			errs = append(errs, fmt.Errorf("stopped before %d of %d attachments: %w", len(attachments)-i,
				len(attachments), err))
			break
		}
		rows, err := repairAttachment(maps, a, attachments, cfg.Egress)
		result.Rebuilt.Add(rows)
		if err != nil {
			errs = append(errs, fmt.Errorf("attachment %s: %w", a.name, err))
		}
	}
	return result, errors.Join(errs...)
}

// repairAttachment fills a's missing VRF and interface rows. If a's interface
// was deleted or re-enslaved while they were written, as a concurrent CNI DEL
// does, the rows are removed again rather than left for an interface that is
// gone, except those another of all still needs.
func repairAttachment(
	maps *attachreg.Maps, a discoveredAttachment, all []discoveredAttachment, egress attachreg.EgressConfig,
) (attachreg.Counts, error) {
	var errs []error
	vrfRows, err := maps.FillVRF(a.Attachment, egress)
	if err != nil {
		errs = append(errs, err)
	}

	ifaceRows, err := maps.FillInterface(a.Attachment)
	if err != nil {
		errs = append(errs, err)
	}
	if (ifaceRows.Total() > 0 || vrfRows.Total() > 0) && !stillAttached(a) {
		slog.Debug("Attachment interface went away during datapath repair; removing the rows just written",
			"hostInterface", a.name, "ifindex", a.HostIfindex)
		if err := maps.RemoveInterfaceRows(a.HostIfindex, ifaceRows); err != nil {
			errs = append(errs, fmt.Errorf("remove rows for an interface that went away: %w", err))
		}
		keepPrefixes, keepVRF := neededByOthers(a, all)
		if err := maps.RemoveVRFRows(a.Attachment, vrfRows, keepPrefixes, keepVRF); err != nil {
			errs = append(errs, fmt.Errorf("remove VRF rows for an interface that went away: %w", err))
		}
		return attachreg.Counts{ShardEgressRoutes: vrfRows.ShardEgressRoutes}, errors.Join(errs...)
	}
	rows := vrfRows.Counts
	rows.Add(ifaceRows)
	return rows, errors.Join(errs...)
}

// neededByOthers returns the local prefixes another attachment in all needs in
// a's VRF table, and whether another attachment shares a's (Block, Argument).
func neededByOthers(a discoveredAttachment, all []discoveredAttachment) (map[string]struct{}, bool) {
	prefixes := map[string]struct{}{}
	sharesKey := false
	for _, o := range all {
		if o.HostIfindex == a.HostIfindex {
			continue
		}
		if o.Block == a.Block && o.Argument == a.Argument {
			sharesKey = true
		}
		if o.VRFTableID != a.VRFTableID {
			continue
		}
		for _, p := range o.LocalPrefixes {
			if _, n, err := net.ParseCIDR(p); err == nil {
				prefixes[n.String()] = struct{}{}
			}
		}
	}
	return prefixes, sharesKey
}

// stillAttached reports whether a's interface still exists under the same
// ifindex, name, and VRF master it was discovered with.
func stillAttached(a discoveredAttachment) bool {
	link, err := linkByIndexFn(int(a.HostIfindex))
	if err != nil {
		return false
	}
	return link.Attrs().Name == a.name && link.Attrs().MasterIndex == a.masterIndex
}

// nodeSRv6Identity returns the SRv6 identity of nodeName's BGPRouter and the
// router's name. found is false when no router targets the node. A router
// with no SRv6 locator or node ID is found with an unconfigured Node, for
// which CNI ADD registers nothing either. More than one router targeting the
// node is an error, as it is for CNI ADD.
func nodeSRv6Identity(
	ctx context.Context, k8s client.Client, namespace, nodeName string,
) (node attachreg.Node, routerName string, found bool, err error) {
	routers, err := routersForNode(ctx, k8s, namespace, nodeName)
	if err != nil {
		return attachreg.Node{}, "", false, err
	}
	switch len(routers) {
	case 0:
		return attachreg.Node{}, "", false, nil
	case 1:
	default:
		return attachreg.Node{}, "", false, fmt.Errorf("ambiguous BGP config: %d BGPRouters target node %s in namespace %s",
			len(routers), nodeName, namespace)
	}
	for name, r := range routers {
		node = attachreg.Node{Locator: r.Spec.SRv6Locator, NodeID: r.Spec.NodeID}
		routerName = name
	}
	return node, routerName, true, nil
}

// countHostAttachments returns how many interfaces are named like an
// attachment's host side and enslaved to a VRF.
func countHostAttachments() (int, error) {
	links, err := listAllLinksFn()
	if err != nil {
		return 0, fmt.Errorf("list kernel interfaces: %w", err)
	}
	vrfs := map[int]bool{}
	for _, l := range links {
		if _, ok := l.(*netlink.Vrf); ok {
			vrfs[l.Attrs().Index] = true
		}
	}
	n := 0
	for _, l := range links {
		if hostLinkNameRegex.MatchString(l.Attrs().Name) && vrfs[l.Attrs().MasterIndex] {
			n++
		}
	}
	return n, nil
}

// vrfIDsForRouter returns the Spec.VRFID of every BGPVRFInstance in namespace
// whose RouterRef names routerName, keyed by instance name.
func vrfIDsForRouter(
	ctx context.Context, k8s client.Client, namespace, routerName string,
) (map[string]int32, error) {
	list := &bgpv1alpha1.BGPVRFInstanceList{}
	if err := k8s.List(ctx, list, client.InNamespace(namespace)); err != nil {
		return nil, fmt.Errorf("list BGPVRFInstances: %w", err)
	}
	ids := make(map[string]int32, len(list.Items))
	for _, inst := range list.Items {
		if inst.Spec.RouterRef == nil || inst.Spec.RouterRef.Name != routerName {
			continue
		}
		ids[inst.Name] = inst.Spec.VRFID
	}
	return ids, nil
}

// advertisedAddressing is what an attachment's BGPAdvertisement records of the
// IPAM result CNI ADD registered it from.
type advertisedAddressing struct {
	// prefixes are the guest prefixes, the advertisement's spec.prefixes.
	prefixes []string
	// noAddressing is set when the attachment's config carries no ipam block,
	// so ADD had no IPAM result at all.
	noAddressing bool
}

// addressingForRouter returns the addressing every BGPAdvertisement in
// namespace whose RouterRef names routerName records, keyed by advertisement
// name.
func addressingForRouter(
	ctx context.Context, k8s client.Client, namespace, routerName string,
) (map[string]advertisedAddressing, error) {
	list := &bgpv1alpha1.BGPAdvertisementList{}
	if err := k8s.List(ctx, list, client.InNamespace(namespace)); err != nil {
		return nil, fmt.Errorf("list BGPAdvertisements: %w", err)
	}
	out := make(map[string]advertisedAddressing, len(list.Items))
	for _, adv := range list.Items {
		if adv.Spec.RouterRef.Name != routerName {
			continue
		}
		a := advertisedAddressing{
			noAddressing: adv.Annotations[crdnames.AnnotationNoAddressing] == crdnames.AnnotationNoAddressingValue,
		}
		for _, p := range adv.Spec.Prefixes {
			a.prefixes = append(a.prefixes, string(p))
		}
		out[adv.Name] = a
	}
	return out, nil
}

// mergePrefixes returns kernel followed by every prefix of advertised whose
// network kernel does not already hold. A prefix that does not parse is
// dropped, as registering it would fail.
func mergePrefixes(kernel, advertised []string) []string {
	seen := make(map[string]struct{}, len(kernel)+len(advertised))
	for _, p := range kernel {
		if _, n, err := net.ParseCIDR(p); err == nil {
			seen[n.String()] = struct{}{}
		}
	}
	merged := kernel
	for _, p := range advertised {
		_, n, err := net.ParseCIDR(p)
		if err != nil {
			slog.Debug("Datapath repair: ignoring unparsable advertised prefix", "prefix", p, "err", err)
			continue
		}
		if _, ok := seen[n.String()]; ok {
			continue
		}
		seen[n.String()] = struct{}{}
		merged = append(merged, n.String())
	}
	return merged
}

// unpad reverses the zero padding an interface name applies to a base62
// identifier, which CRD names do not carry.
func unpad(s string) string {
	if t := strings.TrimLeft(s, "0"); t != "" {
		return t
	}
	return "0"
}

// discoveryCounts is how many host-named interfaces discoverAttachments did
// not resolve into an attachment, by reason.
type discoveryCounts struct {
	skipped int
	pending int
}

// discoverAttachments lists every interface named like an attachment's host
// side and enslaved to a VRF, and resolves each into the Attachment its rows
// are built from, in ascending host ifindex order. An interface not enslaved
// to a VRF, whose VRF table foreign claims, whose link type is neither veth
// nor tap, or whose BGPVRFInstance's VRFID is out of range is counted as
// skipped; one whose VPC has no BGPVRFInstance on this node yet as pending.
// advertised, keyed by BGPAdvertisement name, adds the guest prefixes the
// kernel does not route.
func discoverAttachments(
	nodeName string, block uint64, vrfIDs map[string]int32, advertised map[string]advertisedAddressing,
	foreign func(uint32) bool,
) (attachments []discoveredAttachment, counts discoveryCounts, err error) {
	links, err := listAllLinksFn()
	if err != nil {
		return nil, counts, fmt.Errorf("list kernel interfaces: %w", err)
	}
	byIndex := make(map[int]netlink.Link, len(links))
	for _, l := range links {
		byIndex[l.Attrs().Index] = l
	}

	routes := newRouteCache()
	var errs []error
	for _, link := range links {
		attrs := link.Attrs()
		m := hostLinkNameRegex.FindStringSubmatch(attrs.Name)
		if m == nil {
			continue
		}
		master, ok := byIndex[attrs.MasterIndex].(*netlink.Vrf)
		if !ok {
			counts.skipped++
			continue
		}
		if foreign(master.Table) {
			counts.skipped++
			continue
		}
		ifaceType, ok := attachreg.InterfaceTypeForLink(link)
		if !ok {
			slog.Debug("Datapath repair: skipping attachment interface of unknown type",
				"hostInterface", attrs.Name, "type", link.Type())
			counts.skipped++
			continue
		}
		vpc, vpcAttachment := unpad(m[1]), unpad(m[2])
		argument, found, inRange := argumentForVPC(vrfIDs, vpc, nodeName)
		if !found {
			slog.Debug("Datapath repair: no BGPVRFInstance yet for attachment interface",
				"hostInterface", attrs.Name, "vpc", vpc)
			counts.pending++
			continue
		}
		if !inRange {
			counts.skipped++
			continue
		}

		prefixes, gateways, err := localAddressing(link, master.Table, routes)
		if err != nil {
			errs = append(errs, fmt.Errorf("read addressing of %s: %w", attrs.Name, err))
			continue
		}
		if adv, ok := advertised[crdnames.BGPAdvertisementName(vpc, vpcAttachment, nodeName)]; ok {
			prefixes = mergePrefixes(prefixes, adv.prefixes)
			// ADD writes an all-zero tenant_gw_table row for an IPAM result
			// with no gateway, and none only when there was no IPAM result.
			if gateways == nil && !adv.noAddressing && len(adv.prefixes) > 0 {
				gateways = &attachreg.Gateways{}
			}
		}
		attachments = append(attachments, discoveredAttachment{
			Attachment: attachreg.Attachment{
				VPC:           vpc,
				VPCAttachment: vpcAttachment,
				HostIfindex:   uint32(attrs.Index),
				Block:         block,
				Argument:      argument,
				VRFTableID:    master.Table,
				InterfaceType: ifaceType,
				LocalPrefixes: prefixes,
				Gateways:      gateways,
			},
			name:        attrs.Name,
			masterIndex: attrs.MasterIndex,
		})
	}
	sort.Slice(attachments, func(i, j int) bool { return attachments[i].HostIfindex < attachments[j].HostIfindex })
	return attachments, counts, errors.Join(errs...)
}

// argumentForVPC returns the Argument of vpc's BGPVRFInstance on nodeName,
// accepting both the current and legacy CRD name shapes. found is false when
// no instance exists, and inRange false when its VRFID is outside the
// Argument range.
func argumentForVPC(vrfIDs map[string]int32, vpc, nodeName string) (argument uint16, found, inRange bool) {
	for _, key := range vpcKeys(vpc) {
		id, ok := vrfIDs[key+"-"+nodeName]
		if !ok {
			continue
		}
		if id < int32(uformat.ArgumentMin) || id > int32(uformat.ArgumentMax) {
			slog.Warn("Datapath repair: skipping BGPVRFInstance with out-of-range VRFID",
				"vrfInstance", key+"-"+nodeName, "vrfID", id)
			return 0, true, false
		}
		return uint16(id), true, true
	}
	return 0, false, false
}

// routeCache lists each VRF table's routes once per pass, since every
// attachment in a VRF reads the same table.
type routeCache map[uint32][]netlink.Route

func newRouteCache() routeCache { return routeCache{} }

// get returns tableID's IPv6 and IPv4 routes.
func (c routeCache) get(tableID uint32) ([]netlink.Route, error) {
	if routes, ok := c[tableID]; ok {
		return routes, nil
	}
	var routes []netlink.Route
	for _, family := range []int{netlink.FAMILY_V6, netlink.FAMILY_V4} {
		rs, err := listRoutesFn(tableID, family)
		if err != nil {
			return nil, fmt.Errorf("list routes in VRF table %d: %w", tableID, err)
		}
		routes = append(routes, rs...)
	}
	c[tableID] = routes
	return routes, nil
}

// localAddressing recovers what CNI ADD registered as link's local prefixes and
// gateways from the kernel. The guest prefixes are the pod-subnet routes the
// master plugin installs in the VRF's table out link: unicast, not
// kernel-generated, with no gateway and not link-scoped. The master plugin
// installs one only for a family with a gateway, so a family without one is
// missing here; discoverAttachments adds it from the BGPAdvertisement. The
// gateways are link's own addresses that are not link-local, each also a host
// prefix. A link with no such address has nil gateways. Where a family carries
// more than one address, the first the kernel lists is the gateway.
func localAddressing(link netlink.Link, tableID uint32, routes routeCache) ([]string, *attachreg.Gateways, error) {
	tableRoutes, err := routes.get(tableID)
	if err != nil {
		return nil, nil, err
	}
	var prefixes []string
	for i := range tableRoutes {
		if isPodSubnetRoute(&tableRoutes[i], link.Attrs().Index) {
			prefixes = append(prefixes, tableRoutes[i].Dst.String())
		}
	}

	var gw attachreg.Gateways
	for _, family := range []int{netlink.FAMILY_V6, netlink.FAMILY_V4} {
		addrs, err := listAddrsFn(link, family)
		if err != nil {
			return nil, nil, fmt.Errorf("list addresses: %w", err)
		}
		for _, a := range addrs {
			if a.IPNet == nil || a.IP.IsLinkLocalUnicast() {
				continue
			}
			prefixes = append(prefixes, attachreg.HostPrefix(a.IP))
			setGateway(&gw, a.IP)
		}
	}
	if gw.IPv6 == nil && gw.IPv4 == nil {
		return prefixes, nil, nil
	}
	return prefixes, &gw, nil
}

// setGateway records ip as gw's gateway for its family unless one is already
// set.
func setGateway(gw *attachreg.Gateways, ip net.IP) {
	if v4 := ip.To4(); v4 != nil {
		if gw.IPv4 == nil {
			gw.IPv4 = v4
		}
		return
	}
	if gw.IPv6 == nil {
		gw.IPv6 = ip
	}
}

// isPodSubnetRoute reports whether r is a pod-subnet route out ifindex, as
// opposed to a kernel-generated route or a termination route with a gateway or
// link scope.
func isPodSubnetRoute(r *netlink.Route, ifindex int) bool {
	return r.Dst != nil && r.LinkIndex == ifindex && r.Gw == nil && len(r.MultiPath) == 0 &&
		r.Type == unix.RTN_UNICAST && r.Protocol != unix.RTPROT_KERNEL && r.Scope != netlink.SCOPE_LINK
}
