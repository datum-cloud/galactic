// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package installer

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"

	bgpv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	"go.datum.net/galactic/internal/cni/vpcfence"
	"go.datum.net/galactic/internal/crdnames"
	"go.datum.net/galactic/internal/plumbing/ebpf/attach"
	"go.datum.net/galactic/internal/plumbing/ebpf/ifindexvrfmap"
	"go.datum.net/galactic/internal/plumbing/ebpf/tpmap"
	"go.datum.net/galactic/internal/plumbing/ebpf/uformat"
	"go.datum.net/galactic/internal/plumbing/ebpf/usidmap"
	"go.datum.net/galactic/internal/plumbing/intf"
	"go.datum.net/galactic/internal/plumbing/vrf"
)

const (
	sidecarReturnInterval = 5 * time.Second
	// A protocol marks the compatibility route for cleanup in the shared VRF
	// table. Its metric is less preferred than Worker's IPv6 route (1024).
	sidecarReturnProtocol netlink.RouteProtocol = 249
	sidecarReturnMetric   int                   = 2048

	// These values are part of the advertisement format emitted by legacy
	// galactic-vrf builds.
	legacyIngressAttachment  = "ingress"
	legacyIngressHostIfindex = "galactic.datum.net/ingress-host-ifindex"
	legacyIngressHostMAC     = "galactic.datum.net/ingress-host-mac"
)

type legacySidecarEndpoint struct {
	vpc      string
	argument uint16
	prefix   netip.Prefix
	ifindex  int
	mac      net.HardwareAddr
	adv      *bgpv1alpha1.BGPAdvertisement
	node     string
}

// sidecarReturnKeep protects both the previous installer's reserved table and
// the compatibility route in the shared host VRF for a live legacy endpoint.
type sidecarReturnKeep struct {
	arguments map[uint16]bool
	routes    map[sidecarReturnRouteKey]bool
	ifindexes map[uint32]bool
	neighbors map[sidecarReturnNeighborKey]bool
	retired   []netlink.Route
}

type sidecarReturnNeighborKey struct {
	ifindex int
	address string
}

func sidecarNeighborKey(route netlink.Route) sidecarReturnNeighborKey {
	if route.Dst == nil {
		return sidecarReturnNeighborKey{}
	}
	return sidecarReturnNeighborKey{route.LinkIndex, route.Dst.IP.String()}
}

type sidecarReturnRouteKey struct {
	table, ifindex int
	prefix         string
}

func compatibilityRouteKey(route netlink.Route) sidecarReturnRouteKey {
	return sidecarReturnRouteKey{route.Table, route.LinkIndex, route.Dst.String()}
}

func runSidecarReturn(ctx context.Context, st ebpfDatapathState) {
	if st.objs == nil || st.k8sClient == nil || st.nodeName == "" {
		return
	}
	ticker := time.NewTicker(sidecarReturnInterval)
	defer ticker.Stop()
	for ctx.Err() == nil {
		err := reconcileSidecarReturn(ctx, st.k8sClient, st.namespace, st.nodeName, attach.PinDir)
		if err != nil && ctx.Err() == nil {
			slog.Warn("Could not reconcile legacy ingress sidecar return paths", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func reconcileSidecarReturn(ctx context.Context, k8s client.Client, namespace, node, pinDir string) error {
	vpcs, err := sidecarReturnVPCs(ctx, k8s, namespace, node)
	if err != nil {
		return err
	}
	var advertisements bgpv1alpha1.BGPAdvertisementList
	if err := k8s.List(ctx, &advertisements, client.InNamespace(namespace)); err != nil {
		return fmt.Errorf("list sidecar return advertisements: %w", err)
	}
	endpoints, worker := sidecarReturnEndpoints(advertisements.Items, vpcs, node)
	keep := sidecarReturnKeep{
		arguments: make(map[uint16]bool, len(endpoints)),
		routes:    make(map[sidecarReturnRouteKey]bool, len(endpoints)),
		ifindexes: make(map[uint32]bool, len(endpoints)),
		neighbors: make(map[sidecarReturnNeighborKey]bool, len(endpoints)),
	}

	if len(endpoints) > 0 {
		locator, err := nodeLocatorPrefix(ctx, k8s, namespace, node)
		if err != nil || !locator.IsValid() {
			// Wait for the node identity before deciding which path to keep.
			return err
		}
		block, err := uformat.Block(locator.Addr())
		if err != nil {
			return err
		}
		nodeID, err := uformat.NodeID(locator.Addr())
		if err != nil {
			return err
		}
		err = reconcileLegacySidecarEndpoints(ctx, k8s, pinDir, block, nodeID, endpoints, worker, &keep)
		if err != nil {
			return err
		}
	}

	_, err = pruneRetiredSidecarReturn(ctx, pinDir, func(argument uint16) (string, bool) {
		vpc, ok := vpcs[argument]
		return vpc.name, ok
	}, keep)
	return err
}

// workerSidecarRoute identifies Worker routes for the same node, VPC and
// address, indexed by the route prefix. The alias ties each route to the
// attachment actually advertised by Worker.
type workerSidecarRoute struct {
	vpc    string
	prefix netip.Prefix
}

func sidecarReturnEndpoints(
	advertisements []bgpv1alpha1.BGPAdvertisement, vpcs map[uint16]sidecarReturnVPC, node string,
) ([]legacySidecarEndpoint, map[workerSidecarRoute][]string) {
	var endpoints []legacySidecarEndpoint
	worker := make(map[workerSidecarRoute][]string)
	for i := range advertisements {
		adv := &advertisements[i]
		if crdnames.HasCNIContainer(adv.Annotations) {
			continue
		}
		if adv.Labels[crdnames.LabelWorkerNode] == node && adv.Annotations[crdnames.AnnotationWorkerPod] != "" {
			vpc := adv.Labels[crdnames.LabelWorkerVPC]
			attachment := adv.Labels[crdnames.LabelWorkerAttachment]
			if vpc != "" && attachment != "" {
				for _, raw := range adv.Spec.Prefixes {
					if prefix, ok := sidecarHostPrefix(raw); ok {
						key := workerSidecarRoute{vpc, prefix}
						worker[key] = append(worker[key], attach.InternalAliasPrefix+vpc+"/"+attachment)
					}
				}
			}
			continue
		}

		argument := adv.Spec.VRFID
		if argument == nil || *argument < uformat.ArgumentMin || *argument > uformat.ArgumentMax ||
			adv.Spec.Function == nil || *adv.Spec.Function != bgpv1alpha1.SRv6FunctionEndDT46 {
			continue
		}
		id := uint16(*argument)
		vpc, ok := vpcs[id]
		if !ok || adv.Spec.RouterRef.Name != vpc.router ||
			adv.Name != crdnames.BGPAdvertisementName(vpc.name, legacyIngressAttachment, node) {
			continue
		}
		ifindex, indexErr := strconv.Atoi(adv.Annotations[legacyIngressHostIfindex])
		mac, macErr := net.ParseMAC(adv.Annotations[legacyIngressHostMAC])
		if indexErr != nil || ifindex <= 0 || macErr != nil || len(mac) != 6 {
			continue
		}
		for _, raw := range adv.Spec.Prefixes {
			if prefix, ok := sidecarHostPrefix(raw); ok {
				endpoints = append(endpoints, legacySidecarEndpoint{vpc.name, id, prefix, ifindex, mac, adv, node})
			}
		}
	}
	return endpoints, worker
}

func sidecarHostPrefix(raw bgpv1alpha1.Prefix) (netip.Prefix, bool) {
	prefix, err := netip.ParsePrefix(string(raw))
	return prefix, err == nil && prefix.Bits() == 128 && prefix.Addr().Is6() &&
		!prefix.Addr().Is4In6() && prefix.Addr().IsGlobalUnicast()
}

type sidecarReturnMaps struct {
	registry *usidmap.Registry
	policy   *tpmap.Maps
	kinds    *ifindexvrfmap.EgressKindTable
}

func reconcileLegacySidecarEndpoints(
	ctx context.Context, k8s client.Client, pinDir string, block uint64, nodeID uint16, endpoints []legacySidecarEndpoint,
	worker map[workerSidecarRoute][]string, keep *sidecarReturnKeep,
) error {
	registry, closer, err := usidmap.OpenPinnedRegistry(pinDir)
	if err != nil {
		return err
	}
	defer func() { _ = closer.Close() }()
	policy, err := tpmap.OpenPinned(pinDir)
	if err != nil {
		return err
	}
	defer policy.Close()
	kinds, kindMap, err := ifindexvrfmap.OpenPinnedEgressKind(pinDir)
	if err != nil {
		return err
	}
	defer func() { _ = kindMap.Close() }()

	if err := ensureLegacySidecarSID(registry, block, nodeID); err != nil {
		return err
	}
	maps := sidecarReturnMaps{registry, policy, kinds}
	var errs []error
	for _, e := range endpoints {
		aliases := worker[workerSidecarRoute{e.vpc, e.prefix}]
		if err := maps.reconcileEndpoint(ctx, k8s, block, e, aliases, keep); err != nil {
			errs = append(errs, fmt.Errorf("reconcile sidecar return for VPC %s: %w", e.vpc, err))
		}
	}
	return errors.Join(errs...)
}

func (m sidecarReturnMaps) reconcileEndpoint(
	ctx context.Context, k8s client.Client, block uint64, e legacySidecarEndpoint,
	workerAliases []string, keep *sidecarReturnKeep,
) error {
	link, err := netlink.LinkByIndex(e.ifindex)
	var missing netlink.LinkNotFoundError
	switch {
	case errors.As(err, &missing):
		return m.reapLegacyEndpoint(ctx, k8s, e)
	case err != nil:
		return err
	case link.Type() != "veth" || intf.IsGalacticLinkName(link.Attrs().Name) || attach.IsInternalLink(link):
		return nil
	}

	table, err := vrf.TableID(e.vpc)
	if err != nil && !errors.Is(err, vrf.ErrNotFound) {
		return err
	}
	route := e.route(table)
	// Orphan cleanup must leave the active endpoint alone. Takeover removes
	// its routes only after checking under the same fence as Worker.
	keep.arguments[e.argument] = true
	served, inPlace, err := m.endpointState(block, e, route, workerAliases)
	if err != nil {
		return err
	}
	if served {
		fallback, err := e.ownedRoutes(table)
		if err != nil {
			return err
		}
		if len(fallback) == 0 {
			// Routes may have been removed on a previous pass that stopped
			// before cleaning up their per-interface state.
			keep.retired = append(keep.retired, route)
			return nil
		}
	}
	if !inPlace {
		if err := vpcfence.Write(ctx, e.vpc, func() error {
			var err error
			route, served, err = m.updateEndpoint(ctx, k8s, block, e)
			return err
		}); err != nil {
			return err
		}
	}

	if served {
		keep.retired = append(keep.retired, route)
	} else {
		keep.routes[compatibilityRouteKey(route)] = true
		keep.ifindexes[uint32(e.ifindex)] = true //nolint:gosec // positive kernel ifindex
		keep.neighbors[sidecarNeighborKey(route)] = true
	}
	return nil
}

func (m sidecarReturnMaps) updateEndpoint(
	ctx context.Context, k8s client.Client, block uint64, e legacySidecarEndpoint,
) (netlink.Route, bool, error) {
	valid, err := e.isCurrent(ctx, k8s)
	if err != nil || !valid {
		// Keep the candidate for this pass. The next list will discover
		// the replacement advertisement or the new Argument assignment.
		return netlink.Route{}, false, fmt.Errorf("legacy endpoint changed during reconciliation: %w",
			errors.Join(err, errSidecarEndpointChanged))
	}
	table, err := vrf.TableID(e.vpc)
	if errors.Is(err, vrf.ErrNotFound) {
		if err := vrf.Add(e.vpc); err != nil {
			return netlink.Route{}, false, err
		}
		table, err = vrf.TableID(e.vpc)
	}
	if err != nil {
		return netlink.Route{}, false, err
	}
	route := e.route(table)
	var advertisements bgpv1alpha1.BGPAdvertisementList
	if err := k8s.List(ctx, &advertisements, client.InNamespace(e.adv.Namespace), client.MatchingLabels{
		crdnames.LabelWorkerNode: e.node, crdnames.LabelWorkerVPC: e.vpc,
	}); err != nil {
		return route, false, err
	}
	_, worker := sidecarReturnEndpoints(advertisements.Items, nil, e.node)
	served, inPlace, err := m.endpointState(block, e, route, worker[workerSidecarRoute{e.vpc, e.prefix}])
	if err != nil {
		return route, false, err
	}
	if served {
		return route, true, e.retireRoutes(table)
	}
	if inPlace {
		return route, false, nil
	}
	return route, false, m.installEndpoint(block, e, route)
}

var errSidecarEndpointChanged = errors.New("gateway advertisement or VRF instance changed")

func (e legacySidecarEndpoint) isCurrent(ctx context.Context, k8s client.Client) (bool, error) {
	var adv bgpv1alpha1.BGPAdvertisement
	if err := k8s.Get(ctx, client.ObjectKeyFromObject(e.adv), &adv); err != nil {
		return false, client.IgnoreNotFound(err)
	}
	if adv.UID != e.adv.UID || adv.ResourceVersion != e.adv.ResourceVersion {
		return false, nil
	}
	var instance bgpv1alpha1.BGPVRFInstance
	if err := k8s.Get(ctx, client.ObjectKey{
		Namespace: e.adv.Namespace, Name: crdnames.BGPVRFInstanceName(e.vpc, e.node),
	}, &instance); err != nil {
		return false, client.IgnoreNotFound(err)
	}
	return instance.Spec.RouterRef != nil && instance.Spec.RouterRef.Name == adv.Spec.RouterRef.Name &&
		instance.Spec.VRFID == int32(e.argument), nil
}

func (e legacySidecarEndpoint) ownedRoutes(table uint32) ([]netlink.Route, error) {
	var owned []netlink.Route
	for _, id := range []uint32{table, sidecarReturnTableBase + uint32(e.argument)} {
		filter := e.route(id)
		routes, err := netlink.RouteListFiltered(netlink.FAMILY_V6, &filter,
			netlink.RT_FILTER_TABLE|netlink.RT_FILTER_DST|netlink.RT_FILTER_OIF)
		if err != nil {
			return nil, err
		}
		for _, route := range routes {
			if id != table || route.Protocol == sidecarReturnProtocol {
				owned = append(owned, route)
			}
		}
	}
	return owned, nil
}

func (e legacySidecarEndpoint) retireRoutes(table uint32) error {
	routes, err := e.ownedRoutes(table)
	if err != nil {
		return err
	}
	for _, route := range routes {
		if err := netlink.RouteDel(&route); err != nil && !errors.Is(err, unix.ESRCH) {
			return err
		}
	}
	return nil
}

func (m sidecarReturnMaps) reapLegacyEndpoint(ctx context.Context, k8s client.Client, e legacySidecarEndpoint) error {
	// An absent veth has already lost its routes and neighbors in the
	// kernel. The advertisement still identifies the old map entries.
	ifindex := uint32(e.ifindex) //nolint:gosec // positive kernel ifindex
	infra, err := m.policy.IsInfra(ifindex)
	if err != nil {
		return err
	}
	if infra {
		if err := m.kinds.Unregister(ifindex); err != nil {
			return err
		}
		if err := m.policy.RemoveInfra(ifindex); err != nil {
			return err
		}
	}
	err = k8s.Delete(ctx, e.adv, client.Preconditions{UID: &e.adv.UID, ResourceVersion: &e.adv.ResourceVersion})
	if apierrors.IsConflict(err) {
		// The new sidecar published an updated endpoint while we reaped.
		return nil
	}
	return client.IgnoreNotFound(err)
}

func (e legacySidecarEndpoint) route(table uint32) netlink.Route {
	return netlink.Route{
		Dst:       &net.IPNet{IP: e.prefix.Addr().AsSlice(), Mask: net.CIDRMask(128, 128)},
		LinkIndex: e.ifindex, Table: int(table), Scope: netlink.SCOPE_LINK,
		Priority: sidecarReturnMetric, Protocol: sidecarReturnProtocol,
	}
}

func (m sidecarReturnMaps) endpointState(
	block uint64, e legacySidecarEndpoint, want netlink.Route, workerAliases []string,
) (served, inPlace bool, err error) {
	if want.Table == 0 {
		return false, false, nil
	}
	row, present, err := m.registry.VRF.Get(block, e.argument)
	if err != nil {
		return false, false, err
	}
	canonical := present && row.VRFTableID == uint32(want.Table) //nolint:gosec // kernel table ID
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_V6, &want, netlink.RT_FILTER_TABLE|netlink.RT_FILTER_DST)
	if err != nil {
		return false, false, err
	}
	hasRoute := false
	for _, route := range routes {
		hasRoute = hasRoute ||
			(route.Protocol == want.Protocol && route.Priority == want.Priority && route.LinkIndex == want.LinkIndex)
		if canonical && len(workerAliases) > 0 && route.Protocol != sidecarReturnProtocol && route.Priority < want.Priority {
			ready, err := m.workerRouteReady(route.LinkIndex, workerAliases)
			if err != nil || ready {
				return ready, false, err
			}
		}
	}
	if !hasRoute || !canonical {
		return false, false, nil
	}
	ifindex := uint32(e.ifindex) //nolint:gosec // positive kernel ifindex
	infra, err := m.policy.IsInfra(ifindex)
	if err != nil || !infra {
		return false, false, err
	}
	kind, present, err := m.kinds.Get(ifindex)
	if err != nil || !present || kind != usidmap.EgressKindVeth {
		return false, false, err
	}
	neighbors, err := netlink.NeighList(e.ifindex, netlink.FAMILY_V6)
	if err != nil {
		return false, false, err
	}
	for _, neighbor := range neighbors {
		if neighbor.IP.Equal(want.Dst.IP) && neighbor.State&netlink.NUD_PERMANENT != 0 &&
			bytes.Equal(neighbor.HardwareAddr, e.mac) {
			return false, true, nil
		}
	}
	return false, false, nil
}

func (m sidecarReturnMaps) workerRouteReady(ifindex int, aliases []string) (bool, error) {
	if ifindex <= 0 {
		return false, nil
	}
	link, err := netlink.LinkByIndex(ifindex)
	var missing netlink.LinkNotFoundError
	if errors.As(err, &missing) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	for _, alias := range aliases {
		if link.Type() == "veth" && link.Attrs().Alias == alias && link.Attrs().Flags&net.FlagUp != 0 {
			return m.policy.IsInfra(uint32(ifindex)) //nolint:gosec // positive kernel ifindex
		}
	}
	return false, nil
}

func (m sidecarReturnMaps) installEndpoint(block uint64, e legacySidecarEndpoint, route netlink.Route) error {
	// The legacy advertisement's ifindex must never exempt a Galactic tenant
	// interface from policy. PutInfra guards this even if the index was reused.
	ifindex := uint32(e.ifindex) //nolint:gosec // positive kernel ifindex
	if err := m.policy.PutInfra(ifindex); err != nil {
		return err
	}
	if err := m.kinds.Register(ifindex, usidmap.EgressKindVeth); err != nil {
		return err
	}
	if err := netlink.NeighSet(&netlink.Neigh{
		LinkIndex: e.ifindex, Family: netlink.FAMILY_V6, State: netlink.NUD_PERMANENT,
		IP: route.Dst.IP, HardwareAddr: e.mac,
	}); err != nil {
		return err
	}
	if err := netlink.RouteReplace(&route); err != nil {
		return err
	}
	// Route and neighbor are already present when the shared row starts
	// pointing at the canonical table. Preserve an existing canonical row's
	// legacy egress kind, which an older binary can still read.
	table := uint32(route.Table) //nolint:gosec // kernel table ID
	row, present, err := m.registry.VRF.Get(block, e.argument)
	if err != nil || (present && row.VRFTableID == table) {
		return err
	}
	return m.registry.VRF.Register(block, e.argument, table, usidmap.EgressKindVeth)
}

func ensureLegacySidecarSID(registry *usidmap.Registry, block uint64, nodeID uint16) error {
	if _, found, err := registry.Locator.Get(block, nodeID); err != nil {
		return err
	} else if !found {
		if err := registry.Locator.Register(block, nodeID); err != nil {
			return err
		}
	}
	if _, found, err := registry.Function.Get(block, uformat.FunctionEndDT46); err != nil {
		return err
	} else if !found {
		return registry.Function.Register(block, uformat.FunctionEndDT46)
	}
	return nil
}
