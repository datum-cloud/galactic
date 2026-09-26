// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package egressroutes programs a tenant VRF's routes toward the node's egress
// shards. Two writers share it: the CNI plugin at ADD, which installs or
// withdraws routes from the attachment's own declaration so the network is
// usable when ADD returns, and the installer's claim sweep, which keeps a
// running VRF in step with the claims the cell records against this node.
package egressroutes

import (
	"errors"
	"fmt"
	"net"
	"net/netip"

	"go.datum.net/galactic/internal/plumbing/ebpf/uformat"
	"go.datum.net/galactic/internal/plumbing/srv6"
)

// TenantShardSIDs returns sids with each Argument rewritten to argument,
// leaving Block, Node-ID and Function as the operator configured them.
// Whatever Argument an operator baked into a configured SID is therefore
// overwritten rather than honoured; it identifies no tenant and never could,
// one configured value being shared by every VRF on every node.
//
// The argument is what makes a shard able to tell one tenant on this node
// from another: the shard reads it back out of the outer destination and
// composes it with the encapsulation source into its session table key.
// Without it every VRF on this node encapsulates toward a byte-identical
// destination, and two tenants whose inner tuples also match, an ordinary
// occurrence with overlapping RFC 4193 ULAs, share one connection row and one
// masquerade port, so the second tenant's replies are delivered to the first.
//
// A SID that is not a well-formed uFMT 48+16 address fails here rather than
// being passed through unchanged. uformat.Decode's padding check is what
// catches it: an address with anything in bits 81-128 is not a uSID, and
// writing an Argument into it would produce a plausible-looking destination
// that addresses nothing. An IPv4 entry is unmapped first so it fails as "not
// an IPv6 address" rather than as stray padding, which is what it actually is.
//
// The shard must have a route covering its whole Block and Node-ID for these
// destinations to be reachable, not just a host route for the one SID the
// operator configured. EgressShardReconciler advertises that /64.
func TenantShardSIDs(sids []net.IP, argument uint16) ([]net.IP, error) {
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

// Install writes VRF table tableID's egress routes toward shardSIDs: the ::/0
// default that reaches the IPv6 internet and, when nat64Prefix is set, a
// more-specific route for the NAT64 prefix. Idempotent.
//
// Both routes point at the same shard SID, argument included. A shard decides
// which translation a packet gets from its inner destination, so the second
// route exists to make the NAT64 prefix reachable at all rather than to steer
// it somewhere else. The two are independent: a fabric may offer NAT64
// without NAT66, and then no default route exists for this traffic to fall
// into.
//
// An empty shardSIDs is refused. A node that names no shard cannot give a
// VRF egress, and the caller decides whether that fails an ADD or is logged
// by a sweep.
func Install(tableID uint32, argument uint16, shardSIDs []net.IP, nat64Prefix *net.IPNet) error {
	if len(shardSIDs) == 0 {
		return errors.New("this node names no egress shard")
	}
	tenantSIDs, err := TenantShardSIDs(shardSIDs, argument)
	if err != nil {
		return fmt.Errorf("apply tenant argument to the egress shard list: %w", err)
	}
	if err := srv6.EgressDefaultRouteAdd(tableID, tenantSIDs); err != nil {
		return err
	}
	if nat64Prefix == nil {
		return nil
	}
	return srv6.EgressPrefixRouteAdd(tableID, nat64Prefix, tenantSIDs)
}

// Withdraw removes VRF table tableID's egress routes, so a network whose
// declaration withdrew egress, or never declared it, carries none however the
// node is configured. Idempotent, and a no-op on a node whose datapath has not
// loaded.
func Withdraw(tableID uint32, nat64Prefix *net.IPNet) error {
	if err := srv6.EgressDefaultRouteWithdraw(tableID); err != nil {
		return fmt.Errorf("withdraw default egress route: %w", err)
	}
	if nat64Prefix == nil {
		return nil
	}
	if err := srv6.EgressPrefixRouteWithdraw(tableID, nat64Prefix); err != nil {
		return fmt.Errorf("withdraw NAT64 egress route: %w", err)
	}
	return nil
}
