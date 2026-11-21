// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package installer

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"sigs.k8s.io/controller-runtime/pkg/client"

	bgpv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	"go.datum.net/galactic/internal/cni/vpcfence"
	"go.datum.net/galactic/internal/plumbing/ebpf/attach"
	"go.datum.net/galactic/internal/plumbing/ebpf/ifindexvrfmap"
	"go.datum.net/galactic/internal/plumbing/ebpf/tpmap"
	"go.datum.net/galactic/internal/plumbing/ebpf/uformat"
	"go.datum.net/galactic/internal/plumbing/ebpf/usidmap"
	"go.datum.net/galactic/internal/plumbing/intf"
	"go.datum.net/galactic/internal/plumbing/nldump"
	"go.datum.net/galactic/internal/plumbing/vrf"
)

// Leftovers of the retired host-side return path of the ingress sidecar.
//
// galactic-worker now gives the sidecar its return path. Earlier installers
// built one themselves, per advertised gateway address, from:
//
//   - a routing table sidecarReturnTableBase+VRFID holding a /128 device route
//     for the gateway address out the host side of the sidecar pod's primary
//     interface;
//   - a PERMANENT neighbor for that address on the same interface;
//   - an infra row in tp_iface_table for that interface;
//   - a vrf_table row under this node's Block, keyed on the advertised VRFID,
//     pointing at that table with EgressKindVeth.
//
// Nothing removes these once the installer no longer writes them, and the
// vrf_table row keeps steering that VPC's replies into a table that no longer
// leads to the sidecar. The prune below removes them once, at installer
// startup, so an upgraded node does not keep them.

const (
	// sidecarReturnTableBase and sidecarReturnTableMax bound the host routing
	// table IDs the retired return path allocated, one per Argument. No other
	// writer uses them: host tenant VRF tables stop at vrf.HostTableIDMax,
	// below the range, and sidecar VRF tables live in pod namespaces.
	sidecarReturnTableBase = 0xF000
	sidecarReturnTableMax  = sidecarReturnTableBase + uformat.ArgumentMax
)

// retiredSidecarReturnPruned counts what one prune removed.
type retiredSidecarReturnPruned struct {
	vrfRows   int
	routes    int
	neighbors int
	infraRows int
	// vrfRowsKept counts retired vrf_table rows left in place because no VPC
	// could be resolved for their Argument, so no fence could be taken. The
	// GC sweep removes such a row once its BGPVRFInstance is gone.
	vrfRowsKept int
}

func (p retiredSidecarReturnPruned) total() int {
	return p.vrfRows + p.routes + p.neighbors + p.infraRows
}

// startRetiredSidecarReturnPrune runs pruneRetiredSidecarReturn once, off the
// caller's goroutine, against the loaded datapath in st, and logs the result.
// It does nothing when st has no loaded datapath. Without a Kubernetes client
// it still removes the routes, neighbors and infra rows, and leaves the
// vrf_table rows to the GC sweep.
func startRetiredSidecarReturnPrune(ctx context.Context, st ebpfDatapathState) {
	if st.objs == nil {
		return
	}
	go func() {
		// The VPCs are read from the API only for a retired vrf_table row,
		// so a node with nothing left over makes no API call.
		var once bool
		vpcs := map[uint16]string{}
		vpcOf := func(argument uint16) (string, bool) {
			if !once {
				once = true
				if st.k8sClient == nil || st.nodeName == "" {
					return "", false
				}
				found, err := sidecarReturnVPCs(ctx, st.k8sClient, st.namespace, st.nodeName)
				if err != nil {
					slog.Warn("Could not resolve VPCs for the retired sidecar return path's vrf_table rows; "+
						"leaving those rows to the GC sweep", "err", err)
				} else {
					vpcs = found
				}
			}
			vpc, ok := vpcs[argument]
			return vpc, ok
		}
		pruned, err := pruneRetiredSidecarReturn(ctx, attach.PinDir, vpcOf)
		attrs := []any{"vrfRows", pruned.vrfRows, "routes", pruned.routes, "neighbors", pruned.neighbors,
			"infraRows", pruned.infraRows, "vrfRowsKept", pruned.vrfRowsKept}
		switch {
		case err != nil:
			slog.Warn("Could not remove all leftovers of the retired sidecar return path; "+
				"the next installer start retries", append(attrs, "err", err)...)
		case pruned.total() > 0 || pruned.vrfRowsKept > 0:
			slog.Info("Removed leftovers of the retired sidecar return path", attrs...)
		default:
			slog.Debug("No leftovers of the retired sidecar return path found")
		}
	}()
}

// pruneRetiredSidecarReturn removes the state the retired sidecar return path
// wrote on this node, from the routing tables in its range and from the maps
// pinned under pinDir. It is idempotent: a second call finds nothing.
//
// vpcOf resolves an Argument to the VPC whose write fence guards its vrf_table
// row. A row whose Argument it cannot resolve is kept and counted.
//
// The order mirrors the old install in reverse: vrf_table rows first, so
// nothing is delivered toward a table while it is emptied, then neighbors and
// routes, and the infra rows last. Every step is attempted; the error joins
// every failure.
func pruneRetiredSidecarReturn(
	ctx context.Context, pinDir string, vpcOf func(argument uint16) (string, bool),
) (retiredSidecarReturnPruned, error) {
	var pruned retiredSidecarReturnPruned

	routes, err := nldump.RouteListFiltered(netlink.FAMILY_ALL,
		&netlink.Route{Table: unix.RT_TABLE_UNSPEC}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return pruned, fmt.Errorf("list routes in the retired sidecar return tables: %w", err)
	}
	var leftover []netlink.Route
	for _, r := range routes {
		if r.Table >= sidecarReturnTableBase && r.Table <= sidecarReturnTableMax {
			leftover = append(leftover, r)
		}
	}

	var errs []error
	removed, kept, err := pruneRetiredSidecarReturnVRFRows(ctx, pinDir, vpcOf)
	pruned.vrfRows, pruned.vrfRowsKept = removed, kept
	errs = append(errs, err)

	ifindexes := map[uint32]bool{}
	for i := range leftover {
		r := leftover[i]
		if r.LinkIndex > 0 {
			ifindexes[uint32(r.LinkIndex)] = true //nolint:gosec // a kernel ifindex
		}
		n, err := pruneRetiredSidecarReturnNeighbor(r)
		pruned.neighbors += n
		errs = append(errs, err)
		if err := netlink.RouteDel(&r); err != nil && !errors.Is(err, unix.ESRCH) {
			errs = append(errs, fmt.Errorf("delete route %v from table %d: %w", r.Dst, r.Table, err))
			continue
		}
		pruned.routes++
	}

	n, err := pruneRetiredSidecarReturnInfra(pinDir, ifindexes)
	pruned.infraRows = n
	errs = append(errs, err)
	return pruned, errors.Join(errs...)
}

// isRetiredSidecarReturnRow reports whether a vrf_table row with this key and
// value is one the retired return path wrote: under a Block other than the
// ingress sidecar's, pointing at that Argument's table in the retired range,
// with EgressKindVeth. CNI and galactic-worker point a VPC's row at its host
// VRF table, which is never in that range.
func isRetiredSidecarReturnRow(block uint64, argument uint16, tableID, egressKind uint32) bool {
	if block == uformat.BlockIngressSidecar {
		return false
	}
	if argument < uformat.ArgumentMin || argument > uformat.ArgumentMax {
		return false
	}
	return tableID == sidecarReturnTableBase+uint32(argument) && egressKind == usidmap.EgressKindVeth
}

// pruneRetiredSidecarReturnVRFRows repairs every retired vrf_table row whose
// Argument vpcOf resolves, each under its VPC's write fence: CNI writes a row
// with the same key for that VPC, so the row is re-read under the fence and
// changed only if it is still a retired one. A row whose VPC has a host VRF
// on the node points at that VRF's table again; any other is removed. It
// returns how many rows it repaired or removed and how many it kept for want
// of a VPC. A datapath with no pinned maps has none.
func pruneRetiredSidecarReturnVRFRows(
	ctx context.Context, pinDir string, vpcOf func(argument uint16) (string, bool),
) (removed, kept int, err error) {
	registry, closer, err := usidmap.OpenPinnedRegistry(pinDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, 0, nil
		}
		return 0, 0, fmt.Errorf("open pinned uSID maps: %w", err)
	}
	defer func() { _ = closer.Close() }()

	rows, err := registry.VRF.List()
	if err != nil {
		return 0, 0, err
	}
	var errs []error
	for _, row := range rows {
		if !isRetiredSidecarReturnRow(row.Block, row.Argument, row.VRFTableID, row.EgressKind) {
			continue
		}
		vpc, ok := vpcOf(row.Argument)
		if !ok {
			kept++
			continue
		}
		deleted := false
		err := vpcfence.Write(ctx, vpc, func() error {
			cur, present, err := registry.VRF.Get(row.Block, row.Argument)
			if err != nil || !present ||
				!isRetiredSidecarReturnRow(cur.Block, cur.Argument, cur.VRFTableID, cur.EgressKind) {
				return err
			}
			// The retired path overwrote the VPC's canonical row, the one CNI
			// and galactic-worker write for its host VRF under the same key.
			// Where that VRF still exists the row is pointed back at it, as
			// nodevpc.Ensure would; only a VPC with no VRF on the node loses
			// the row.
			table, err := vrf.TableID(vpc)
			switch {
			case err == nil:
				if err := registry.VRF.Register(row.Block, row.Argument, table, usidmap.EgressKindVeth); err != nil {
					return err
				}
			case errors.Is(err, vrf.ErrNotFound):
				if err := registry.VRF.Unregister(row.Block, row.Argument); err != nil {
					return err
				}
			default:
				return err
			}
			deleted = true
			return nil
		})
		if err != nil {
			errs = append(errs, fmt.Errorf("remove vrf_table row (block %#x, argument %d): %w",
				row.Block, row.Argument, err))
			continue
		}
		if deleted {
			removed++
		}
	}
	return removed, kept, errors.Join(errs...)
}

// pruneRetiredSidecarReturnNeighbor deletes the PERMANENT neighbor for r's
// destination on r's interface, when r is a host route out a link. It returns
// how many neighbors it deleted.
func pruneRetiredSidecarReturnNeighbor(r netlink.Route) (int, error) {
	if r.Dst == nil || r.LinkIndex <= 0 {
		return 0, nil
	}
	ones, bits := r.Dst.Mask.Size()
	if ones != bits || bits == 0 {
		return 0, nil
	}
	family := netlink.FAMILY_V6
	if bits == net.IPv4len*8 {
		family = netlink.FAMILY_V4
	}
	neighs, err := nldump.NeighList(r.LinkIndex, family)
	if err != nil {
		return 0, fmt.Errorf("list neighbors on ifindex %d: %w", r.LinkIndex, err)
	}
	deleted := 0
	var errs []error
	for i := range neighs {
		n := neighs[i]
		if n.State&netlink.NUD_PERMANENT == 0 || !n.IP.Equal(r.Dst.IP) {
			continue
		}
		if err := netlink.NeighDel(&n); err != nil && !errors.Is(err, unix.ENOENT) {
			errs = append(errs, fmt.Errorf("delete neighbor %s on ifindex %d: %w", n.IP, r.LinkIndex, err))
			continue
		}
		deleted++
	}
	return deleted, errors.Join(errs...)
}

// pruneRetiredSidecarReturnInfra removes the infra rows of ifindexes, the
// interfaces the retired return routes pointed at. An ifindex at or above
// ifindexvrfmap.SidecarIfindexBase is the sidecar's own and is skipped, and a
// tenant row is never removed. It returns how many rows it removed. A
// datapath with no pinned traffic policy maps has none.
func pruneRetiredSidecarReturnInfra(pinDir string, ifindexes map[uint32]bool) (int, error) {
	if len(ifindexes) == 0 {
		return 0, nil
	}
	policy, err := tpmap.OpenPinned(pinDir)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("open pinned traffic policy maps: %w", err)
	}
	defer policy.Close()

	removed := 0
	var errs []error
	for ifindex := range ifindexes {
		if ifindex >= ifindexvrfmap.SidecarIfindexBase {
			continue
		}
		infra, err := policy.IsInfra(ifindex)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if !infra {
			continue
		}
		if err := policy.RemoveInfra(ifindex); err != nil {
			errs = append(errs, err)
			continue
		}
		removed++
	}
	return removed, errors.Join(errs...)
}

// sidecarReturnVPCs maps each VRFID of the BGPVRFInstances on this node's
// Galactic routers to its VPC, decoded from the instance name's leading
// segment. A VRFID claimed by two VPCs, or whose name does not decode, is left
// out.
func sidecarReturnVPCs(
	ctx context.Context, k8s client.Client, namespace, nodeName string,
) (map[uint16]string, error) {
	routerNames, err := galacticRouterNamesForNode(ctx, k8s, namespace, nodeName)
	if err != nil {
		return nil, err
	}
	list := &bgpv1alpha1.BGPVRFInstanceList{}
	if err := k8s.List(ctx, list, client.InNamespace(namespace)); err != nil {
		return nil, fmt.Errorf("list BGPVRFInstances in namespace %s: %w", namespace, err)
	}
	out := map[uint16]string{}
	ambiguous := map[uint16]bool{}
	for i := range list.Items {
		inst := &list.Items[i]
		if inst.Spec.RouterRef == nil {
			continue
		}
		if _, mine := routerNames[inst.Spec.RouterRef.Name]; !mine {
			continue
		}
		if inst.Spec.VRFID < int32(uformat.ArgumentMin) || inst.Spec.VRFID > int32(uformat.ArgumentMax) {
			continue
		}
		segment, _, _ := strings.Cut(inst.Name, "-")
		vpc, err := intf.HexToBase62(segment)
		if err != nil {
			continue
		}
		argument := uint16(inst.Spec.VRFID)
		if prev, ok := out[argument]; ok && prev != vpc {
			ambiguous[argument] = true
		}
		out[argument] = vpc
	}
	for argument := range ambiguous {
		delete(out, argument)
	}
	return out, nil
}

// galacticRouterNamesForNode returns the names of the Galactic-owned
// BGPRouters (no routerClassName) targeting nodeName. Objects are matched to
// the node through these names rather than by assuming a router is named after
// its node, which nothing enforces.
func galacticRouterNamesForNode(
	ctx context.Context, k8s client.Client, namespace, nodeName string,
) (map[string]struct{}, error) {
	routers := &bgpv1alpha1.BGPRouterList{}
	if err := k8s.List(ctx, routers, client.InNamespace(namespace)); err != nil {
		return nil, fmt.Errorf("list BGPRouters in namespace %s: %w", namespace, err)
	}
	names := make(map[string]struct{})
	for _, r := range bgpv1alpha1.LegacyOwnedRouters(routers.Items) {
		if r.Spec.TargetRef.Name == nodeName {
			names[r.Name] = struct{}{}
		}
	}
	return names, nil
}
