// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package attachreg

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"

	"go.datum.net/galactic/internal/plumbing/ebpf/egressroutemap"
	"go.datum.net/galactic/internal/plumbing/ebpf/ifindexvrfmap"
	"go.datum.net/galactic/internal/plumbing/ebpf/uformat"
	"go.datum.net/galactic/internal/plumbing/ebpf/usidmap"
	"go.datum.net/galactic/internal/plumbing/srv6"
)

// Maps is every pinned map RegisterDatapath and RegisterTenantGateway write,
// opened once so a repair pass can read and fill many rows. A Maps serves one
// pass: the egress_route_table prefixes its first FillVRF reads are reused by
// every later one.
//
// EgressKind and Gateway are nil when the running datapath predates those
// maps; their rows are then skipped, as ADD skips them.
type Maps struct {
	Registry     *usidmap.Registry
	IfindexVRF   *ifindexvrfmap.IfindexVRFTable
	EgressKind   *ifindexvrfmap.EgressKindTable
	Gateway      *ifindexvrfmap.GatewayTable
	EgressRoute  *egressroutemap.EgressRouteTable
	NodeSource   *egressroutemap.NodeSourceAddress
	PublicUplink *egressroutemap.PublicUplink

	// routePrefixes is egress_route_table's exact prefixes by VRF table,
	// read on first use and updated with every route this Maps writes.
	routePrefixes map[uint32]map[string]struct{}

	// shardsUnresolvable is set once a shard route fails because no
	// configured shard resolves; see FillVRF.
	shardsUnresolvable bool
}

// egressRoutesPresent returns the exact prefixes egress_route_table holds for
// tableID, reading the whole map on first use.
func (m *Maps) egressRoutesPresent(tableID uint32) (map[string]struct{}, error) {
	if m.routePrefixes == nil {
		prefixes, err := m.EgressRoute.Prefixes()
		if err != nil {
			return nil, err
		}
		m.routePrefixes = prefixes
	}
	if m.routePrefixes[tableID] == nil {
		m.routePrefixes[tableID] = map[string]struct{}{}
	}
	return m.routePrefixes[tableID], nil
}

// closers closes every map handle OpenPinnedMaps opened.
type closers []io.Closer

func (c closers) Close() error {
	var errs []error
	for _, closer := range c {
		if err := closer.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// OpenPinnedMaps opens every map in Maps from its pin under pinDir. The
// returned closer releases this process's handles and must be closed when the
// caller is done; the maps stay pinned.
func OpenPinnedMaps(pinDir string) (*Maps, io.Closer, error) {
	var (
		m  Maps
		cs closers
	)
	fail := func(err error) (*Maps, io.Closer, error) {
		_ = cs.Close()
		return nil, nil, err
	}

	registry, registryCloser, err := usidmap.OpenPinnedRegistry(pinDir)
	if err != nil {
		return fail(fmt.Errorf("open pinned uSID maps: %w", err))
	}
	m.Registry, cs = registry, append(cs, registryCloser)

	ifindexTable, ifindexMap, err := ifindexvrfmap.OpenPinned(pinDir)
	if err != nil {
		return fail(fmt.Errorf("open pinned ifindex_vrf_table: %w", err))
	}
	m.IfindexVRF, cs = ifindexTable, append(cs, ifindexMap)

	kinds, kindsMap, err := ifindexvrfmap.OpenPinnedEgressKind(pinDir)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return fail(fmt.Errorf("open pinned ifindex_egress_kind_table: %w", err))
	default:
		m.EgressKind, cs = kinds, append(cs, kindsMap)
	}

	gateways, gatewaysMap, err := ifindexvrfmap.OpenPinnedGateway(pinDir)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return fail(fmt.Errorf("open pinned tenant_gw_table: %w", err))
	default:
		m.Gateway, cs = gateways, append(cs, gatewaysMap)
	}

	routes, routesCloser, err := egressroutemap.OpenPinnedEgressRouteTable(pinDir)
	if err != nil {
		return fail(fmt.Errorf("open pinned egress_route_table: %w", err))
	}
	m.EgressRoute, cs = routes, append(cs, routesCloser)

	nodeSrc, nodeSrcCloser, err := egressroutemap.OpenPinnedNodeSourceAddress(pinDir)
	if err != nil {
		return fail(fmt.Errorf("open pinned node_src_addr_table: %w", err))
	}
	m.NodeSource, cs = nodeSrc, append(cs, nodeSrcCloser)

	uplink, uplinkCloser, err := egressroutemap.OpenPinnedPublicUplink(pinDir)
	if err != nil {
		return fail(fmt.Errorf("open pinned public_uplink_table: %w", err))
	}
	m.PublicUplink, cs = uplink, append(cs, uplinkCloser)

	return &m, cs, nil
}

// Counts is how many rows a fill wrote into each map.
type Counts struct {
	Locator           int
	Function          int
	NodeSource        int
	PublicUplink      int
	VRF               int
	VPCAttribution    int
	IfindexVRF        int
	EgressKind        int
	TenantGateway     int
	LocalEgressRoutes int
	ShardEgressRoutes int
}

// Add adds o's counts to c.
func (c *Counts) Add(o Counts) {
	c.Locator += o.Locator
	c.Function += o.Function
	c.NodeSource += o.NodeSource
	c.PublicUplink += o.PublicUplink
	c.VRF += o.VRF
	c.VPCAttribution += o.VPCAttribution
	c.IfindexVRF += o.IfindexVRF
	c.EgressKind += o.EgressKind
	c.TenantGateway += o.TenantGateway
	c.LocalEgressRoutes += o.LocalEgressRoutes
	c.ShardEgressRoutes += o.ShardEgressRoutes
}

// Total is the number of rows written across every map.
func (c Counts) Total() int {
	return c.Locator + c.Function + c.NodeSource + c.PublicUplink + c.VRF + c.VPCAttribution +
		c.IfindexVRF + c.EgressKind + c.TenantGateway + c.LocalEgressRoutes + c.ShardEgressRoutes
}

// LogAttrs returns c as slog key-value pairs, one per map.
func (c Counts) LogAttrs() []any {
	return []any{
		"locatorTable", c.Locator,
		"functionTable", c.Function,
		"nodeSrcAddrTable", c.NodeSource,
		"publicUplinkTable", c.PublicUplink,
		"vrfTable", c.VRF,
		"vpcAttributionTable", c.VPCAttribution,
		"ifindexVRFTable", c.IfindexVRF,
		"ifindexEgressKindTable", c.EgressKind,
		"tenantGWTable", c.TenantGateway,
		"egressRouteTableLocal", c.LocalEgressRoutes,
		"egressRouteTableShard", c.ShardEgressRoutes,
	}
}

// UplinkResolver resolves this node's fabric-uplink next hop: the link index
// and the destination and source MACs public_uplink_table holds.
type UplinkResolver func() (linkIndex int, dmac, smac net.HardwareAddr, err error)

// FillNode writes this node's own rows that are missing: locator_table and
// function_table for node's Block, node_src_addr_table, and
// public_uplink_table. A node with no SRv6 identity writes nothing.
//
// uplinkErr reports a public uplink that could not be resolved, which needs a
// converged underlay neighbor and is retried by the next fill rather than
// treated as a failure. err reports every other failure; each row is attempted
// regardless.
func (m *Maps) FillNode(node Node, resolveUplink UplinkResolver) (written Counts, uplinkErr, err error) {
	if !node.Configured() {
		return Counts{}, nil, nil
	}
	block, err := node.Block()
	if err != nil {
		return Counts{}, nil, err
	}

	var errs []error
	nodeID := uint16(node.NodeID)
	if _, ok, err := m.Registry.Locator.Get(block, nodeID); err != nil {
		errs = append(errs, err)
	} else if !ok {
		if err := m.Registry.Locator.Register(block, nodeID); err != nil {
			errs = append(errs, fmt.Errorf("register locator_table entry: %w", err))
		} else {
			written.Locator++
		}
	}

	if _, ok, err := m.Registry.Function.Get(block, uformat.FunctionEndDT46); err != nil {
		errs = append(errs, err)
	} else if !ok {
		if err := m.Registry.Function.Register(block, uformat.FunctionEndDT46); err != nil {
			errs = append(errs, fmt.Errorf("register function_table entry: %w", err))
		} else {
			written.Function++
		}
	}

	if _, ok, err := m.NodeSource.Get(); err != nil {
		errs = append(errs, err)
	} else if !ok {
		if err := m.fillNodeSource(node); err != nil {
			errs = append(errs, err)
		} else {
			written.NodeSource++
		}
	}

	if _, _, _, ok, err := m.PublicUplink.Get(); err != nil {
		errs = append(errs, err)
	} else if !ok {
		if linkIndex, dmac, smac, err := resolveUplink(); err != nil {
			uplinkErr = fmt.Errorf("resolve public uplink: %w", err)
		} else if err := m.PublicUplink.Set(linkIndex, dmac, smac); err != nil {
			errs = append(errs, err)
		} else {
			written.PublicUplink++
		}
	}

	return written, uplinkErr, errors.Join(errs...)
}

// fillNodeSource writes NodeSourceAddress for node into node_src_addr_table.
func (m *Maps) fillNodeSource(node Node) error {
	addr, err := NodeSourceAddress(node.Locator, node.NodeID)
	if err != nil {
		return err
	}
	return m.NodeSource.Set(addr)
}

// Attachment is one attachment's identity and the kernel state its rows are
// derived from.
type Attachment struct {
	// VPC and VPCAttachment are the base62 identifiers the host interface is
	// named after.
	VPC           string
	VPCAttachment string
	HostIfindex   uint32
	Block         uint64
	// Argument is the VPC's VRFID on this node, its 12-bit uSID Argument.
	Argument   uint16
	VRFTableID uint32
	// InterfaceType is InterfaceTypeVeth or InterfaceTypeTap.
	InterfaceType string
	// LocalPrefixes are the guest CIDRs and gateway host addresses, in the
	// form Registration.LocalPrefixes takes.
	LocalPrefixes []string
	// Gateways is nil for an attachment with no IPAM gateway, which has no
	// tenant_gw_table row.
	Gateways *Gateways
}

// VRFRows records what one FillVRF call wrote, for RemoveVRFRows.
type VRFRows struct {
	Counts
	// LocalPrefixes are the local pass-through routes written.
	LocalPrefixes []*net.IPNet
}

// FillVRF writes the missing rows a's VRF needs: vrf_table and
// vpc_attribution_table for (Block, Argument), the VRF's shard routes from
// egress, and a's local pass-through routes in egress_route_table. Every
// row is attempted; the errors are joined.
//
// vrf_table and vpc_attribution_table hold one row per VRF, which CNI ADD
// overwrites on every attachment, so after several ADDs they hold whichever
// ran last. FillVRF cannot know that order and writes them from the first
// attachment it is called for; a caller wanting a stable choice calls it in a
// stable order. Delivery does not depend on either: usid_ingress reads the
// per-interface ifindex_egress_kind_table row, which is exact.
//
// Once a shard route fails because no configured shard resolves, every later
// FillVRF on this Maps skips shard routes, since each attempt waits out a
// neighbor solicitation per shard and none would succeed. The first failure
// is the one reported.
func (m *Maps) FillVRF(a Attachment, egress EgressConfig) (VRFRows, error) {
	var (
		written VRFRows
		errs    []error
	)
	if a.Block == uformat.BlockIngressSidecar {
		return written, fmt.Errorf("attachment %s/%s: Block %#x belongs to the ingress sidecar",
			a.VPC, a.VPCAttachment, a.Block)
	}
	egressKind, err := EgressKindForInterfaceType(a.InterfaceType)
	if err != nil {
		return written, fmt.Errorf("determine eBPF egress kind: %w", err)
	}

	// Exact prefixes, not Lookup: the map's longest-prefix match would report
	// every prefix present once the VRF's ::/0 route is.
	present, err := m.egressRoutesPresent(a.VRFTableID)
	if err != nil {
		return written, err
	}
	// A prefix reported missing is about to be written, so it is recorded
	// here and no later attachment sharing this VRF writes it again in this
	// pass. A write that fails is reported, and retried by the next pass.
	routeExists := func(prefix *net.IPNet) (bool, error) {
		_, ok := present[prefix.String()]
		present[prefix.String()] = struct{}{}
		return ok, nil
	}
	tenantSIDs, err := tenantShardSIDs(egress, a.Argument)
	switch {
	case err != nil:
		errs = append(errs, err)
	case len(tenantSIDs) > 0 && !m.shardsUnresolvable:
		n, err := installEgressRoutesIn(m.EgressRoute, a.VRFTableID, tenantSIDs, egress.NAT64Prefix, routeExists)
		written.ShardEgressRoutes += n
		if errors.Is(err, srv6.ErrNoShardResolvable) {
			m.shardsUnresolvable = true
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("install shard egress routes: %w", err))
		}
	}

	local, err := registerLocalEgressRoutesIn(m.EgressRoute, a.VRFTableID, a.LocalPrefixes, routeExists)
	written.LocalPrefixes = local
	written.LocalEgressRoutes += len(local)
	if err != nil {
		errs = append(errs, fmt.Errorf("register local pass-through egress routes: %w", err))
	}

	if _, ok, err := m.Registry.VRF.Get(a.Block, a.Argument); err != nil {
		errs = append(errs, err)
	} else if !ok {
		if err := m.Registry.VRF.Register(a.Block, a.Argument, a.VRFTableID, egressKind); err != nil {
			errs = append(errs, fmt.Errorf("register vrf_table entry: %w", err))
		} else {
			written.VRF++
		}
	}

	if _, ok, err := m.Registry.VPCAttribution.Get(a.Block, a.Argument); err != nil {
		errs = append(errs, err)
	} else if !ok {
		ok, err := m.fillAttribution(a)
		switch {
		case err != nil:
			errs = append(errs, err)
		case ok:
			written.VPCAttribution++
		}
	}

	return written, errors.Join(errs...)
}

// RemoveVRFRows removes rows FillVRF wrote for a, as written records them, for
// an attachment whose interface went away while they were written. Local
// routes in keepPrefixes, which another attachment in the same VRF table
// still needs, are kept. The vrf_table and vpc_attribution_table rows are
// removed only when keepVRF is false, meaning no other attachment shares
// (Block, Argument). Shard routes are per VRF and left alone.
func (m *Maps) RemoveVRFRows(a Attachment, written VRFRows, keepPrefixes map[string]struct{}, keepVRF bool) error {
	var errs []error
	for _, prefix := range written.LocalPrefixes {
		if _, keep := keepPrefixes[prefix.String()]; keep {
			continue
		}
		if err := m.EgressRoute.Unregister(a.VRFTableID, prefix); err != nil {
			errs = append(errs, err)
			continue
		}
		if present := m.routePrefixes[a.VRFTableID]; present != nil {
			delete(present, prefix.String())
		}
	}
	if !keepVRF {
		if written.VRF > 0 {
			if err := m.Registry.VRF.Unregister(a.Block, a.Argument); err != nil {
				errs = append(errs, err)
			}
		}
		if written.VPCAttribution > 0 {
			if err := m.Registry.VPCAttribution.Unregister(a.Block, a.Argument); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

// fillAttribution writes a's vpc_attribution_table row. Identifiers that do
// not decode are logged and skipped, as ADD skips them, since retrying cannot
// change them.
func (m *Maps) fillAttribution(a Attachment) (bool, error) {
	vpcNum, vpcAttachmentNum, err := DecodeVPCIdentifiers(a.VPC, a.VPCAttachment)
	if err != nil {
		slog.Warn("Could not decode VPC/VPCAttachment for byte-accounting attribution; "+
			"vrf_table counters for this entry will report unattributed",
			"vpc", a.VPC, "vpcAttachment", a.VPCAttachment, "err", err)
		return false, nil
	}
	if err := m.Registry.VPCAttribution.Register(a.Block, a.Argument, vpcNum, vpcAttachmentNum); err != nil {
		return false, fmt.Errorf("register vpc_attribution_table entry: %w", err)
	}
	return true, nil
}

// FillInterface writes the missing rows keyed by a's host ifindex:
// ifindex_vrf_table, ifindex_egress_kind_table, and tenant_gw_table when a
// has gateways. The returned Counts records which rows it wrote, for
// RemoveInterfaceRows.
func (m *Maps) FillInterface(a Attachment) (Counts, error) {
	var (
		written Counts
		errs    []error
	)
	if a.Block == uformat.BlockIngressSidecar {
		return written, fmt.Errorf("attachment %s/%s: Block %#x belongs to the ingress sidecar",
			a.VPC, a.VPCAttachment, a.Block)
	}
	egressKind, err := EgressKindForInterfaceType(a.InterfaceType)
	if err != nil {
		return written, fmt.Errorf("determine eBPF egress kind: %w", err)
	}

	if _, ok, err := m.IfindexVRF.Get(a.HostIfindex); err != nil {
		errs = append(errs, err)
	} else if !ok {
		if err := m.IfindexVRF.Register(a.HostIfindex, a.Block, a.Argument); err != nil {
			errs = append(errs, fmt.Errorf("register ifindex_vrf_table entry: %w", err))
		} else {
			written.IfindexVRF++
		}
	}

	if m.EgressKind != nil {
		if _, ok, err := m.EgressKind.Get(a.HostIfindex); err != nil {
			errs = append(errs, err)
		} else if !ok {
			if err := m.EgressKind.Register(a.HostIfindex, egressKind); err != nil {
				errs = append(errs, fmt.Errorf("register ifindex_egress_kind_table entry: %w", err))
			} else {
				written.EgressKind++
			}
		}
	}

	if m.Gateway != nil && a.Gateways != nil {
		if _, _, ok, err := m.Gateway.Get(a.HostIfindex); err != nil {
			errs = append(errs, err)
		} else if !ok {
			if err := registerGateways(m.Gateway, a.HostIfindex, *a.Gateways); err != nil {
				errs = append(errs, fmt.Errorf("register tenant_gw_table entry: %w", err))
			} else {
				written.TenantGateway++
			}
		}
	}

	return written, errors.Join(errs...)
}

// RemoveInterfaceRows removes the rows keyed by ifindex that written, as
// FillInterface returned it, records were written. A caller uses it when the
// interface turns out to have been deleted while those rows were written.
func (m *Maps) RemoveInterfaceRows(ifindex uint32, written Counts) error {
	var errs []error
	if written.IfindexVRF > 0 {
		if err := m.IfindexVRF.Unregister(ifindex); err != nil {
			errs = append(errs, err)
		}
	}
	if written.EgressKind > 0 && m.EgressKind != nil {
		if err := m.EgressKind.Unregister(ifindex); err != nil {
			errs = append(errs, err)
		}
	}
	if written.TenantGateway > 0 && m.Gateway != nil {
		if err := m.Gateway.Unregister(ifindex); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
