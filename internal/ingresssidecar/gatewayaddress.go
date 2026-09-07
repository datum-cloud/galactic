// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package ingresssidecar

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/vishvananda/netlink"

	"go.datum.net/galactic/internal/plumbing/intf"
)

// gatewayAssignmentMu guards gatewayPrefix and gatewayNodeID.
var (
	gatewayAssignmentMu sync.Mutex
	gatewayPrefix       *net.IPNet
	gatewayNodeID       string
)

// SetGatewayAddressAssignment enables assignment of this node's return-path
// gateway address to the VRF-slave veth created for usid_egress, for every VPC
// this sidecar reconciles a VRF for.
//
// prefix is the reserved CIDR addresses are derived inside; nil disables
// assignment, leaving NetlinkGatewayAddressResolver returning
// ErrGatewayAddressNotProvisioned. nodeID must be stable and unique per node:
// it is hashed into the address, so an empty or shared value makes every
// replica derive the same address for a given VPC.
//
// The value is process-global (one node, one prefix, one identity) rather than
// Backend state, so it is set here rather than threaded through EnsureVRF.
func SetGatewayAddressAssignment(prefix *net.IPNet, nodeID string) {
	gatewayAssignmentMu.Lock()
	defer gatewayAssignmentMu.Unlock()
	gatewayPrefix = prefix
	gatewayNodeID = nodeID
}

// gatewayAddressAssignment returns the configured prefix and nodeID. A nil
// prefix means assignment is disabled. Callers must not mutate the returned
// *net.IPNet.
func gatewayAddressAssignment() (*net.IPNet, string) {
	gatewayAssignmentMu.Lock()
	defer gatewayAssignmentMu.Unlock()
	return gatewayPrefix, gatewayNodeID
}

// DeriveGatewayAddress computes this node's return-path gateway address for
// vpc inside prefix. The result depends only on its inputs, so any component
// holding (prefix, vpc, nodeID) derives the same address without coordinating.
//
// prefix must be a byte-aligned IPv6 CIDR with host bits left over, and must
// be disjoint from every tenant VPC subnet. Tenant space is allocated by a
// system outside this repo, so a prefix that no IPAM is ever handed as a pool
// is the only collision guarantee available. vpc is base62-encoded; nodeID is
// any caller-stable per-node identity. Returns the full 128-bit address, or an
// error if prefix is unusable or vpc is not valid base62.
//
// Host bits come from sha256(vpcHex + "|" + nodeID) truncated to fit, so the
// address is collision-safe with high probability rather than unique by
// construction. Nothing contends for a specific value here, so there is no
// "already claimed" state to race against, only two hashes landing on the same
// bytes.
func DeriveGatewayAddress(prefix *net.IPNet, vpc, nodeID string) (net.IP, error) {
	vpcHex, err := intf.Base62ToHex(vpc)
	if err != nil {
		return nil, fmt.Errorf("convert vpc %q to hex: %w", vpc, err)
	}
	if prefix == nil {
		return nil, errors.New("gateway prefix is nil")
	}
	ones, bits := prefix.Mask.Size()
	if bits != net.IPv6len*8 {
		return nil, fmt.Errorf("gateway prefix %s is not an IPv6 prefix", prefix)
	}
	if ones%8 != 0 {
		return nil, fmt.Errorf("gateway prefix %s must be byte-aligned (a multiple of /8)", prefix)
	}
	networkBytes := ones / 8
	hostBytes := net.IPv6len - networkBytes
	if hostBytes == 0 {
		return nil, fmt.Errorf("gateway prefix %s leaves no host bits to derive an address into", prefix)
	}

	base := prefix.IP.To16()
	if base == nil {
		return nil, fmt.Errorf("gateway prefix %s has no valid IPv6 network address", prefix)
	}

	sum := sha256.Sum256([]byte(vpcHex + "|" + nodeID))
	addr := make(net.IP, net.IPv6len)
	copy(addr, base[:networkBytes])
	copy(addr[networkBytes:], sum[:hostBytes])
	return addr, nil
}

// ensureGatewayAddress assigns vpc's derived gateway address to inner, the
// VRF-slave veth end already enslaved into vpc's VRF. Placing it there is what
// lets NetlinkGatewayAddressResolver find it, since that scans interfaces
// enslaved to a VPC's VRF for a global-scope address.
//
// Returns nil when assignment is not configured. Callers must treat that as
// success.
func ensureGatewayAddress(vpc, inner string) error {
	prefix, nodeID := gatewayAddressAssignment()
	if prefix == nil {
		return nil
	}

	addr, err := DeriveGatewayAddress(prefix, vpc, nodeID)
	if err != nil {
		return fmt.Errorf("derive gateway address for vpc %s: %w", vpc, err)
	}

	link, err := netlink.LinkByName(inner)
	if err != nil {
		return fmt.Errorf("look up %q: %w", inner, err)
	}

	// A host route, matching what GatewayPublisher.PublishGateway advertises,
	// rather than a claim on the whole prefix.
	nladdr := &netlink.Addr{IPNet: &net.IPNet{IP: addr, Mask: net.CIDRMask(net.IPv6len*8, net.IPv6len*8)}}
	if err := netlink.AddrReplace(link, nladdr); err != nil {
		return fmt.Errorf("assign gateway address %s to %q: %w", addr, inner, err)
	}

	return ensureGatewayVRFRoute(vpc, addr)
}

// ensureGatewayVRFRoute pulls traffic for vpc's gateway address into that
// VPC's VRF, by routing addr at the VRF device in the main table.
//
// Assigning the address is not enough to receive on it. It lands on a veth
// enslaved to the VPC's VRF, so it is local only within that VRF's table,
// while a reply redirected in by usid_ingress arrives on the pod's primary
// interface, which is in no VRF. The input lookup then runs in the main table,
// finds nothing local, and drops the packet silently: Ip6InReceives advances,
// Ip6InDelivers does not, and no error counter moves.
//
// A route at the VRF device makes the VRF driver redirect the lookup into its
// own table, where the address is local. It belongs in the main table, not the
// VRF's: a lookup that already entered the VRF table finds the address without
// it.
func ensureGatewayVRFRoute(vpc string, addr net.IP) error {
	vrfName := intf.GenerateInterfaceNameVRF(vpc)
	vrfLink, err := netlink.LinkByName(vrfName)
	if err != nil {
		return fmt.Errorf("look up VRF interface %q to route gateway address %s into it: %w",
			vrfName, addr, err)
	}

	route := &netlink.Route{
		Dst:       &net.IPNet{IP: addr, Mask: net.CIDRMask(net.IPv6len*8, net.IPv6len*8)},
		LinkIndex: vrfLink.Attrs().Index,
	}
	if err := netlink.RouteReplace(route); err != nil {
		return fmt.Errorf("route gateway address %s into VRF %q: %w", addr, vrfName, err)
	}
	return nil
}
