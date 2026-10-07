// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package attachreg

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"

	"go.datum.net/galactic/internal/config"
	"go.datum.net/galactic/internal/plumbing/ebpf/attach"
	"go.datum.net/galactic/internal/plumbing/ebpf/egressroutemap"
	"go.datum.net/galactic/internal/plumbing/ebpf/ifindexvrfmap"
	"go.datum.net/galactic/internal/plumbing/ebpf/uformat"
	"go.datum.net/galactic/internal/plumbing/ebpf/usidmap"
	"go.datum.net/galactic/internal/plumbing/intf"
	"go.datum.net/galactic/internal/plumbing/srv6"
	"go.datum.net/galactic/internal/plumbing/vrf"
)

// InterfaceTypeVeth and InterfaceTypeTap are the attachment interface types
// EgressKindForInterfaceType accepts.
const (
	InterfaceTypeVeth = "veth"
	InterfaceTypeTap  = "tap"
)

// Node is this node's SRv6 identity, from its BGPRouter. A zero Locator or
// NodeID means SRv6 is deliberately not configured for it.
type Node struct {
	Locator string
	NodeID  int32
}

// Configured reports whether n carries an SRv6 identity at all.
func (n Node) Configured() bool {
	return n.Locator != "" && n.NodeID != 0
}

// Block validates n's Node-ID range and derives the uSID Block from its
// locator.
func (n Node) Block() (uint64, error) {
	if n.NodeID < uformat.NodeIDMin || n.NodeID > uformat.NodeIDMax {
		return 0, fmt.Errorf("eBPF registration: nodeID %d out of range [%#x,%#x]",
			n.NodeID, uint16(uformat.NodeIDMin), uint16(uformat.NodeIDMax))
	}
	prefix, err := netip.ParsePrefix(n.Locator)
	if err != nil {
		return 0, fmt.Errorf("parse SRv6 locator %q for eBPF registration: %w", n.Locator, err)
	}
	block, err := uformat.Block(prefix.Addr())
	if err != nil {
		return 0, fmt.Errorf("derive eBPF uSID Block from locator %q: %w", n.Locator, err)
	}
	return block, nil
}

// EgressConfig is the fabric-wide egress configuration a tenant VRF's shard
// routes are built from, as the raw comma-separated values the host conflist
// carries. The zero value configures no shard.
type EgressConfig struct {
	ShardSIDs   string
	NAT64Prefix string
}

// Registration is one attachment's CNI ADD-time input to RegisterDatapath.
type Registration struct {
	Node          Node
	VPC           string
	VPCAttachment string
	// InterfaceType is InterfaceTypeVeth or InterfaceTypeTap.
	InterfaceType string
	// Argument is the attachment's VRFID, its 12-bit uSID Argument.
	Argument uint16
	// LocalPrefixes are the attachment's guest CIDRs and gateway host
	// addresses. Each is registered as a local pass-through
	// egress_route_table entry in the VPC's VRF, so local destinations outrank
	// the VRF's ::/0 NAT66 default. Empty is valid and registers nothing.
	LocalPrefixes []string
	Egress        EgressConfig
}

// RegisterDatapath registers one attachment against the eBPF uSID datapath's
// pinned maps under pinDir. registered is false with a nil error only when
// r.Node has no SRv6 locator or node ID configured, meaning SRv6 is
// deliberately not set up for it. Any other failure returns an error.
func RegisterDatapath(pinDir string, r Registration) (registered bool, err error) {
	if !r.Node.Configured() {
		return false, nil
	}

	block, err := r.Node.Block()
	if err != nil {
		return false, err
	}

	egressKind, err := EgressKindForInterfaceType(r.InterfaceType)
	if err != nil {
		return false, fmt.Errorf("determine eBPF egress kind: %w", err)
	}

	vrfTableID, err := vrf.TableID(r.VPC)
	if err != nil {
		return false, fmt.Errorf("look up VRF table id for eBPF registration: %w", err)
	}

	// Installs or refreshes this VRF's NAT66 default egress route. The
	// optional routing plugin in this chain may be absent from a given
	// conflist, and this route must exist wherever a shard is configured, so
	// it is written here.
	if err := installEgressRoutes(pinDir, vrfTableID, r.Argument, r.Egress); err != nil {
		return false, fmt.Errorf("install NAT66 default egress route: %w", err)
	}

	if err := registerLocalEgressRoutes(pinDir, vrfTableID, r.LocalPrefixes); err != nil {
		return false, fmt.Errorf("register local pass-through egress route: %w", err)
	}

	// The host-side interface's ifindex keys this attachment's
	// ifindex_vrf_table row, and only the host side's deterministic name is
	// known here.
	hostIfindex, err := HostInterfaceIndex(r.VPC, r.VPCAttachment)
	if err != nil {
		return false, fmt.Errorf("resolve host interface ifindex for eBPF registration: %w", err)
	}

	registry, closer, err := usidmap.OpenPinnedRegistry(pinDir)
	if err != nil {
		return false, fmt.Errorf("open pinned eBPF uSID maps: %w", err)
	}
	defer func() { _ = closer.Close() }()

	if err := registry.Locator.Register(block, uint16(r.Node.NodeID)); err != nil {
		return false, fmt.Errorf("register eBPF locator_table entry: %w", err)
	}
	if err := registry.Function.Register(block, uformat.FunctionEndDT46); err != nil {
		return false, fmt.Errorf("register eBPF function_table entry: %w", err)
	}

	if err := registry.VRF.Register(block, r.Argument, vrfTableID, egressKind); err != nil {
		return false, fmt.Errorf("register eBPF vrf_table entry: %w", err)
	}

	// Attribute this (block, argument) to its VPC/VPCAttachment for byte
	// accounting, keyed identically to the vrf_table row just registered.
	// Non-fatal: forwarding is unaffected, and only attribution for this
	// attachment is degraded until the next ADD or repair.
	vpcNum, vpcAttachmentNum, err := DecodeVPCIdentifiers(r.VPC, r.VPCAttachment)
	if err != nil {
		slog.Warn("ADD: could not decode VPC/VPCAttachment for byte-accounting attribution; "+
			"vrf_table counters for this entry will report unattributed until the next ADD/DEL",
			"vpc", r.VPC, "vpcAttachment", r.VPCAttachment, "err", err)
	} else if err := registry.VPCAttribution.Register(block, r.Argument, vpcNum, vpcAttachmentNum); err != nil {
		slog.Warn("ADD: could not register eBPF vpc_attribution_table entry; "+
			"vrf_table counters for this entry will report unattributed until the next ADD/DEL",
			"vpc", r.VPC, "vpcAttachment", r.VPCAttachment, "err", err)
	}

	ifindexTable, ifindexCloser, err := ifindexvrfmap.OpenPinned(pinDir)
	if err != nil {
		return false, fmt.Errorf("open pinned eBPF ifindex_vrf_table: %w", err)
	}
	defer func() { _ = ifindexCloser.Close() }()
	if err := ifindexTable.Register(hostIfindex, block, r.Argument); err != nil {
		return false, fmt.Errorf("register eBPF ifindex_vrf_table entry: %w", err)
	}
	if err := registerEgressKind(pinDir, hostIfindex, egressKind); err != nil {
		return false, err
	}

	// Attach usid_egress to this attachment's host-side interface. This is
	// what translates a reply's source address on the way back out.
	hostName := intf.GenerateInterfaceNameHost(r.VPC, r.VPCAttachment)
	if err := attachUsidEgress(pinDir, hostName); err != nil {
		return false, fmt.Errorf("attach eBPF usid_egress to host interface %q: %w", hostName, err)
	}

	// Register this node's own SRv6 SID base. A per-node constant rather than
	// a per-attachment one, but idempotent and cheap enough to redo on every
	// ADD instead of adding a once-per-node lifecycle hook.
	//
	// Non-fatal, unlike the registrations above: usid_egress fails open while
	// the entry is missing, and failing every pod attach is worse than only
	// traffic needing encapsulation failing.
	if err := registerNodeSourceAddress(pinDir, r.Node.Locator, r.Node.NodeID); err != nil {
		slog.Warn("ADD: could not register this node's own SRv6 SID; "+
			"egress routing will fail open until this succeeds", "err", err)
	}

	// Register this node's fabric-uplink next hop. Same per-node,
	// redo-on-every-ADD, non-fatal shape as registerNodeSourceAddress above,
	// for the same reason: resolving it needs a converged underlay neighbor.
	// usid_egress falls through to egress_route_table while the entry is
	// absent.
	if err := registerPublicUplink(pinDir); err != nil {
		slog.Warn("ADD: could not register this node's own public uplink; "+
			"a DSR backend's VIP-sourced reply traffic will fail open to egress_route_table until this succeeds",
			"err", err)
	}

	return true, nil
}

// DecodeVPCIdentifiers decodes vpc and vpcAttachment, the base62 identifiers
// CNI configuration carries, into the fixed-width numeric form
// vpc_attribution_table stores: 48-bit VPC, 16-bit VPCAttachment. Leading
// zero digits, as an interface name pads them with, do not change the result.
func DecodeVPCIdentifiers(vpc, vpcAttachment string) (vpcNum uint64, vpcAttachmentNum uint32, err error) {
	vpcHex, err := intf.Base62ToHex(vpc)
	if err != nil {
		return 0, 0, fmt.Errorf("decode vpc %q: %w", vpc, err)
	}
	vpcNum, err = strconv.ParseUint(vpcHex, 16, 48)
	if err != nil {
		return 0, 0, fmt.Errorf("parse decoded vpc %q (hex %q) as uint48: %w", vpc, vpcHex, err)
	}

	vpcAttachmentHex, err := intf.Base62ToHex(vpcAttachment)
	if err != nil {
		return 0, 0, fmt.Errorf("decode vpcAttachment %q: %w", vpcAttachment, err)
	}
	vpcAttachmentNum64, err := strconv.ParseUint(vpcAttachmentHex, 16, 16)
	if err != nil {
		return 0, 0, fmt.Errorf("parse decoded vpcAttachment %q (hex %q) as uint16: %w",
			vpcAttachment, vpcAttachmentHex, err)
	}
	return vpcNum, uint32(vpcAttachmentNum64), nil
}

// NodeSourceAddress returns the value node_src_addr_table holds for a node
// with this locator and nodeID: its own End.DT46 SID base, which usid_egress
// completes with the packet's Argument and stamps into every outer header it
// pushes. Only a SID is both routable across the fabric and decapsulated on
// arrival, which a shard's reply needs.
func NodeSourceAddress(locator string, nodeID int32) (net.IP, error) {
	sid, err := srv6.NodeSIDBase(locator, nodeID)
	if err != nil {
		return nil, fmt.Errorf("derive node SID base: %w", err)
	}
	return net.IP(sid.AsSlice()), nil
}

// registerNodeSourceAddress writes NodeSourceAddress(locator, nodeID) into
// the node_src_addr_table pinned under pinDir. While the entry is missing,
// every egress_route_table hit fails open instead of encapsulating.
func registerNodeSourceAddress(pinDir, locator string, nodeID int32) error {
	addr, err := NodeSourceAddress(locator, nodeID)
	if err != nil {
		return err
	}
	nodeSrc, closer, err := egressroutemap.OpenPinnedNodeSourceAddress(pinDir)
	if err != nil {
		return fmt.Errorf("open pinned node_src_addr_table: %w", err)
	}
	defer func() { _ = closer.Close() }()
	return nodeSrc.Set(addr)
}

// registerPublicUplink resolves this node's fabric-uplink next hop and writes
// it into the public_uplink_table pinned under pinDir: where usid_egress
// redirects a DSR backend's VIP-sourced reply once apply_vip_xlat has
// rewritten its source, bypassing egress_route_table's NAT66 default.
func registerPublicUplink(pinDir string) error {
	linkIndex, dmac, smac, err := srv6.ResolvePublicUplink()
	if err != nil {
		return fmt.Errorf("resolve public uplink: %w", err)
	}
	uplink, closer, err := egressroutemap.OpenPinnedPublicUplink(pinDir)
	if err != nil {
		return fmt.Errorf("open pinned public_uplink_table: %w", err)
	}
	defer func() { _ = closer.Close() }()
	return uplink.Set(linkIndex, dmac, smac)
}

// attachUsidEgress loads usid_egress from its pin and attaches it to
// ifaceName's TC ingress hook. Without it a reply leaves with its source
// address untranslated and the client discards it. Idempotent.
func attachUsidEgress(pinDir, ifaceName string) error {
	program, err := ebpf.LoadPinnedProgram(filepath.Join(pinDir, attach.UsidEgressPinName), nil)
	if err != nil {
		return fmt.Errorf("load pinned usid_egress program: %w", err)
	}
	defer func() { _ = program.Close() }()

	return attach.AttachEgress(program, ifaceName)
}

// HostPrefix returns ip as a host prefix, "/32" for IPv4 and "/128" for IPv6,
// in the CIDR string form LocalPrefixes carries.
func HostPrefix(ip net.IP) string {
	if ip.To4() != nil {
		return ip.String() + "/32"
	}
	return ip.String() + "/128"
}

// registerLocalEgressRoutes registers each of prefixes as a local
// pass-through egress_route_table entry in Linux VRF table vrfTableID, in the
// map pinned under pinDir. Idempotent.
func registerLocalEgressRoutes(pinDir string, vrfTableID uint32, prefixes []string) error {
	if len(prefixes) == 0 {
		return nil
	}
	table, closer, err := egressroutemap.OpenPinnedEgressRouteTable(pinDir)
	if err != nil {
		return fmt.Errorf("open pinned egress_route_table: %w", err)
	}
	defer func() { _ = closer.Close() }()

	_, err = registerLocalEgressRoutesIn(table, vrfTableID, prefixes, nil)
	return err
}

// routeExistsFn reports whether egress_route_table already holds an entry for
// a prefix, letting a caller skip it. A nil routeExistsFn skips nothing.
type routeExistsFn func(prefix *net.IPNet) (bool, error)

// registerLocalEgressRoutesIn registers each of prefixes not skipped by exists
// as a local pass-through entry in Linux VRF table vrfTableID, and returns the
// prefixes it wrote. A prefix that does not parse is a hard error rather than a
// silent skip: every caller builds them with a CIDR String or HostPrefix.
func registerLocalEgressRoutesIn(
	table *egressroutemap.EgressRouteTable, vrfTableID uint32, prefixes []string, exists routeExistsFn,
) ([]*net.IPNet, error) {
	var written []*net.IPNet
	for _, p := range prefixes {
		_, prefix, err := net.ParseCIDR(p)
		if err != nil {
			return written, fmt.Errorf("parse prefix %q: %w", p, err)
		}
		if exists != nil {
			found, err := exists(prefix)
			if err != nil {
				return written, err
			}
			if found {
				continue
			}
		}
		if err := table.RegisterPassThrough(vrfTableID, prefix); err != nil {
			return written, fmt.Errorf("register local pass-through route for %s: %w", p, err)
		}
		written = append(written, prefix)
	}
	return written, nil
}

// installEgressRoutes installs or refreshes vrfTableID's egress routes toward
// the configured shards, in the egress_route_table pinned under pinDir: the
// ::/0 default that reaches the IPv6 internet and, where this fabric has
// NAT64, a more-specific route for each NAT64 prefix. Idempotent.
//
// argument is this attachment's VRFID, written into every shard SID these
// routes encapsulate toward. A shard reads it back out of the outer
// destination to tell one tenant on this node from another; without it two
// tenants with overlapping inner tuples would share one connection row. Both
// routes point at the same shard SID, since a shard picks the translation from
// the inner destination.
//
// No shard configured is not an error and installs nothing. A shard SID that
// is invalid, or that has no reachable route yet, is an error.
func installEgressRoutes(pinDir string, vrfTableID uint32, argument uint16, cfg EgressConfig) error {
	tenantSIDs, err := tenantShardSIDs(cfg, argument)
	if err != nil || len(tenantSIDs) == 0 {
		return err
	}
	table, closer, err := egressroutemap.OpenPinnedEgressRouteTable(pinDir)
	if err != nil {
		return fmt.Errorf("open pinned egress_route_table: %w", err)
	}
	defer func() { _ = closer.Close() }()

	_, err = installEgressRoutesIn(table, vrfTableID, tenantSIDs, cfg.NAT64Prefix, nil)
	return err
}

// tenantShardSIDs parses cfg's shard list and writes argument into every SID.
// An empty list returns none and no error.
func tenantShardSIDs(cfg EgressConfig, argument uint16) ([]net.IP, error) {
	shardSIDs, err := config.ParseEgressShardSIDs(cfg.ShardSIDs)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", config.EnvCNIEgressShardSIDs, err)
	}
	if len(shardSIDs) == 0 {
		return nil, nil
	}
	tenantSIDs, err := ShardSIDsForTenant(shardSIDs, argument)
	if err != nil {
		return nil, fmt.Errorf("apply tenant argument to %s: %w", config.EnvCNIEgressShardSIDs, err)
	}
	return tenantSIDs, nil
}

// egressPrefixRouteAddFn is a variable so tests can observe route installs
// without resolving a real shard.
var egressPrefixRouteAddFn = srv6.EgressPrefixRouteAddTo

// installEgressRoutesIn installs vrfTableID's ::/0 route and then one route per
// NAT64 prefix in nat64Raw, each toward tenantSIDs, skipping any prefix exists
// reports present. It returns how many routes it wrote. An unset NAT64 list
// means this fabric has no NAT64; a set but invalid one is an error, returned
// after the ::/0 route is installed.
func installEgressRoutesIn(
	table *egressroutemap.EgressRouteTable, vrfTableID uint32, tenantSIDs []net.IP, nat64Raw string,
	exists routeExistsFn,
) (int, error) {
	written := 0
	add := func(prefix *net.IPNet) error {
		if exists != nil {
			found, err := exists(prefix)
			if err != nil || found {
				return err
			}
		}
		if err := egressPrefixRouteAddFn(table, vrfTableID, prefix, tenantSIDs); err != nil {
			return err
		}
		written++
		return nil
	}

	if err := add(egressroutemap.DefaultPrefix); err != nil {
		return written, err
	}
	prefixes, err := config.ParseNAT64Prefixes(nat64Raw)
	if err != nil {
		return written, fmt.Errorf("parse %s: %w", config.EnvCNINAT64Prefix, err)
	}
	for _, prefix := range prefixes {
		if err := add(prefix); err != nil {
			return written, err
		}
	}
	return written, nil
}

// ShardSIDsForTenant returns sids with each SID's 12-bit Argument replaced by
// argument, leaving Block, Node-ID and Function as configured. Whatever
// Argument an operator configured is overwritten: one configured value is
// shared by every VRF on every node, so it identifies no tenant.
//
// A SID that is not a well-formed uFMT 48+16 address is an error rather than
// passed through, since writing an Argument into it would produce a
// plausible-looking destination that addresses nothing. An IPv4 entry is
// unmapped first so it fails as "not an IPv6 address".
func ShardSIDsForTenant(sids []net.IP, argument uint16) ([]net.IP, error) {
	out := make([]net.IP, 0, len(sids))
	for _, sid := range sids {
		addr, ok := netip.AddrFromSlice(sid.To16())
		if !ok {
			return nil, fmt.Errorf("egress shard SID %s is not a 16-byte address", sid)
		}
		fields, err := uformat.Decode(addr.Unmap())
		if err != nil {
			return nil, fmt.Errorf("decode egress shard SID %s: %w", sid, err)
		}
		fields.Argument = argument
		tenant, err := uformat.Encode(fields)
		if err != nil {
			return nil, fmt.Errorf("encode egress shard SID %s with argument %#x: %w", sid, argument, err)
		}
		out = append(out, net.IP(tenant.AsSlice()))
	}
	return out, nil
}

// HostInterfaceIndex resolves an attachment's host-side veth or tap
// interface's kernel ifindex by the deterministic name the master plugin
// created it under.
func HostInterfaceIndex(vpc, vpcAttachment string) (uint32, error) {
	hostName := intf.GenerateInterfaceNameHost(vpc, vpcAttachment)
	link, err := netlink.LinkByName(hostName)
	if err != nil {
		return 0, fmt.Errorf("look up host interface %q: %w", hostName, err)
	}
	return uint32(link.Attrs().Index), nil
}

// registerEgressKind records, in the ifindex_egress_kind_table pinned under
// pinDir, which redirect helper usid_ingress uses to deliver into the host-side
// interface hostIfindex.
//
// A map that is not pinned yet is logged, not returned: the CNI binary is
// replaced before the datapath that pins the map reloads, and the datapath's
// fallback for a missing entry, a plain redirect, still delivers to both
// kinds.
func registerEgressKind(pinDir string, hostIfindex, egressKind uint32) error {
	table, closer, err := ifindexvrfmap.OpenPinnedEgressKind(pinDir)
	if errors.Is(err, os.ErrNotExist) {
		slog.Warn("ADD: eBPF ifindex_egress_kind_table is not pinned yet; "+
			"delivery to this attachment uses the plain-redirect fallback until its next ADD",
			"hostIfindex", hostIfindex, "err", err)
		return nil
	}
	if err != nil {
		return fmt.Errorf("open pinned eBPF ifindex_egress_kind_table: %w", err)
	}
	defer func() { _ = closer.Close() }()
	if err := table.Register(hostIfindex, egressKind); err != nil {
		return fmt.Errorf("register eBPF ifindex_egress_kind_table entry: %w", err)
	}
	return nil
}

// Gateways are an attachment's IPAM gateway addresses. Either may be nil,
// meaning no gateway in that family.
type Gateways struct {
	IPv6 net.IP
	IPv4 net.IP
}

// registerGateways writes gw into tenant_gw_table for hostIfindex, the
// addresses usid_egress sends an ICMP Packet Too Big or Fragmentation Needed
// from.
func registerGateways(table *ifindexvrfmap.GatewayTable, hostIfindex uint32, gw Gateways) error {
	gw6, _ := netip.AddrFromSlice(gw.IPv6)
	gw4, _ := netip.AddrFromSlice(gw.IPv4)
	return table.Register(hostIfindex, gw6, gw4.Unmap())
}

// RegisterTenantGateway records an attachment's IPAM gateways in the
// tenant_gw_table pinned under pinDir. A nil gw, an attachment with no IPAM
// result such as a tap workload managing its own addressing, removes the
// entry instead, so a reused ifindex never keeps another attachment's
// gateway.
//
// Every failure is logged, not returned. Without an entry the datapath drops
// an oversized packet with no error and counts it, which is not worth failing
// the attach over.
func RegisterTenantGateway(pinDir, vpc, vpcAttachment string, gw *Gateways) {
	hostIfindex, err := HostInterfaceIndex(vpc, vpcAttachment)
	if err != nil {
		slog.Warn("ADD: could not resolve host interface for eBPF tenant_gw_table; "+
			"packets too big for the fabric get no ICMP error until the next ADD", "err", err)
		return
	}
	table, closer, err := ifindexvrfmap.OpenPinnedGateway(pinDir)
	if err != nil {
		slog.Warn("ADD: could not open eBPF tenant_gw_table; "+
			"packets too big for the fabric get no ICMP error until the next ADD",
			"hostIfindex", hostIfindex, "err", err)
		return
	}
	defer func() { _ = closer.Close() }()

	if gw == nil {
		if err := table.Unregister(hostIfindex); err != nil {
			slog.Warn("ADD: could not clear eBPF tenant_gw_table entry", "hostIfindex", hostIfindex, "err", err)
		}
		return
	}
	if err := registerGateways(table, hostIfindex, *gw); err != nil {
		slog.Warn("ADD: could not register eBPF tenant_gw_table entry; "+
			"packets too big for the fabric get no ICMP error until the next ADD",
			"hostIfindex", hostIfindex, "err", err)
	}
}

// EgressKindForInterfaceType maps InterfaceTypeVeth or InterfaceTypeTap to the
// egress kind the datapath uses to choose between bpf_redirect_peer, which
// crosses into the container's netns, and plain bpf_redirect, which does not.
func EgressKindForInterfaceType(ifaceType string) (uint32, error) {
	switch ifaceType {
	case InterfaceTypeVeth:
		return usidmap.EgressKindVeth, nil
	case InterfaceTypeTap:
		return usidmap.EgressKindTap, nil
	default:
		return 0, fmt.Errorf("unknown interface type %q", ifaceType)
	}
}

// InterfaceTypeForLink returns the attachment interface type of a host-side
// link read back from the kernel: InterfaceTypeTap for a tuntap device and
// InterfaceTypeVeth for a veth. ok is false for any other link type.
func InterfaceTypeForLink(link netlink.Link) (ifaceType string, ok bool) {
	switch link.Type() {
	case "tuntap":
		return InterfaceTypeTap, true
	case "veth":
		return InterfaceTypeVeth, true
	default:
		return "", false
	}
}
