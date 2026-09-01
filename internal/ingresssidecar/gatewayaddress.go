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

// gatewayAssignmentMu guards gatewayPrefix/gatewayNodeID -- the same
// package-level-var-as-configuration-seam pattern internal/plumbing/srv6's
// own pinDir and this package's own ebpfPinDir already use, chosen over
// threading a new parameter through Backend/kernelBackend's existing
// signatures (see SetGatewayAddressAssignment's own doc comment for why).
var (
	gatewayAssignmentMu sync.Mutex
	gatewayPrefix       *net.IPNet
	gatewayNodeID       string
)

// SetGatewayAddressAssignment enables ensureEgressDatapath to assign this
// node's own deterministic return-path gateway address (see
// DeriveGatewayAddress) to the VRF-slave veth it already creates for
// usid_egress, for every VPC this sidecar subsequently reconciles a VRF
// for. nodeID must be stable and unique per node (cmd/galactic-vrf passes
// its own cfg.NodeName, the same identity GatewayPublisher already
// attributes its BGPAdvertisements to) -- see DeriveGatewayAddress's own
// doc comment for why an empty or shared nodeID would make every replica
// of this sidecar collide on the identical address for a given VPC.
//
// prefix == nil (the default, never called) leaves address assignment
// disabled entirely: ensureEgressDatapath's own call site no-ops, and
// NetlinkGatewayAddressResolver keeps returning
// ErrGatewayAddressNotProvisioned exactly as it does today -- this is
// purely additive to the existing opt-in GatewayPublisher wiring, not a
// replacement for it; both must be configured for the return path to
// actually work end to end.
//
// A package-level setter rather than a new Backend/kernelBackend
// constructor parameter: ensureEgressDatapath(vpc, tableID) is an
// unexported function called from exactly one production site
// (kernelBackend.EnsureVRF) with no vpc-scoped Backend state to carry this
// through today, and adding a stateful field to kernelBackend (currently
// the empty struct{} NewKernelBackend returns) to thread one optional,
// process-wide value through every EnsureVRF call is more invasive than
// this seam, for a value that is genuinely process-global (one node, one
// prefix, one identity) exactly like ebpfPinDir already is.
func SetGatewayAddressAssignment(prefix *net.IPNet, nodeID string) {
	gatewayAssignmentMu.Lock()
	defer gatewayAssignmentMu.Unlock()
	gatewayPrefix = prefix
	gatewayNodeID = nodeID
}

// gatewayAddressAssignment returns the currently configured prefix/nodeID
// pair -- prefix == nil means disabled. Callers must not mutate the
// returned *net.IPNet.
func gatewayAddressAssignment() (*net.IPNet, string) {
	gatewayAssignmentMu.Lock()
	defer gatewayAssignmentMu.Unlock()
	return gatewayPrefix, gatewayNodeID
}

// DeriveGatewayAddress deterministically computes this node's own
// return-path gateway address for vpc inside prefix, a reserved,
// byte-aligned IPv6 CIDR that is disjoint by construction from any tenant
// address space -- see internal/config.VRFConfig's GatewayPrefix doc
// comment for why it must never be carved out of, or derived from, a real
// tenant VPC's own subnet: that space is allocated by a system this repo
// has no visibility into (confirmed live: a real tenant address's own bit
// layout does not match this repo's own internal/cni/ipam allocator), so
// the only structural collision-safety guarantee available here is a
// prefix that no tenant IPAM -- this repo's own or the external one --
// is ever handed as a pool to allocate from in the first place.
//
// The host bits (everything after prefix's own mask) are filled from
// sha256(vpcHex + "|" + nodeID), truncated to fit -- collision-safe against
// another VPC's own derived address, or another node's own address for the
// same VPC, with overwhelming probability for any realistic (vpc, nodeID)
// cardinality (a birthday bound over the mask's own free bit width), not
// deterministically unique the way galactic-ipam's on-disk-marker
// allocator is. That's an acceptable tradeoff here specifically because
// nothing else ever contends for a specific value the way a live IPAM
// allocation call does -- there is no "already claimed by someone else"
// state to race against, only two independent hashes landing on the same
// bytes.
//
// vpc is base62-encoded (the same form crdnames/gateway.go's own
// vpcRouteTarget already takes); nodeID is any caller-stable per-node
// identity string (SetGatewayAddressAssignment's own doc comment).
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

// ensureGatewayAddress assigns this node's derived gateway address for vpc
// (DeriveGatewayAddress) to the named interface -- ensureEgressDatapath's
// own VRF-slave veth (ensureEgressVeth's inner end), already enslaved into
// vpc's VRF for usid_egress's own attachment. Doing so is what lets
// NetlinkGatewayAddressResolver (gateway.go) find a global-scope address
// there with no further wiring: it already scans every interface enslaved
// to a VPC's VRF for exactly this.
//
// No-ops (returns nil) when address assignment isn't configured
// (SetGatewayAddressAssignment never called) -- callers must treat that
// identically to success, matching ensureNodeSourceAddress's own
// non-fatal-on-not-yet-available stance just above it in
// ensureEgressDatapath.
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

	// /128, matching exactly what GatewayPublisher.PublishGateway
	// advertises (gateway.go's own addr.String()+"/128") -- a host route,
	// not a claim on prefix's own subnet as a whole.
	nladdr := &netlink.Addr{IPNet: &net.IPNet{IP: addr, Mask: net.CIDRMask(net.IPv6len*8, net.IPv6len*8)}}
	if err := netlink.AddrReplace(link, nladdr); err != nil {
		return fmt.Errorf("assign gateway address %s to %q: %w", addr, inner, err)
	}
	return nil
}
