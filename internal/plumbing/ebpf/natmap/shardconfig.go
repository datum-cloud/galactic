// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package natmap

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"

	"github.com/cilium/ebpf"

	"go.datum.net/galactic/internal/plumbing/ebpf/natprog"
)

// shardConfigKey is shard_config_table's single fixed key. The map is a
// one-entry array, so there is exactly one valid key.
const shardConfigKey uint32 = 0

// ShardConfig is shard_config_table's decoded single row: this shard's
// operator-supplied identity, already validated by config parsing. See the
// datapath's header comment for what each address is used for.
type ShardConfig struct {
	// ShardSID is this shard's own SRv6 uSID: the outer destination a tenant's
	// egress packet is encapsulated toward, and the re-encapsulation source used
	// on the way back.
	ShardSID netip.Addr

	// ShardPubAddr6 is this shard's publicly routable IPv6 masquerade source.
	// Every NAT66 flow this shard translates is given an address and port
	// within it. Unset means this shard does not perform NAT66.
	ShardPubAddr6 netip.Addr

	// ShardPubAddr4 is this shard's publicly routable IPv4 masquerade source,
	// the address an IPv4-only destination sees. Unset means this shard does
	// not perform NAT64.
	ShardPubAddr4 netip.Addr

	// NAT64Prefix is the IPv6 /96 whose synthesized addresses this shard
	// translates to IPv4 -- one Datum-operated Network-Specific Prefix, shared
	// fabric-wide, never per-tenant. Required whenever ShardPubAddr4 is set.
	NAT64Prefix netip.Prefix
}

// nat64PrefixLen is the only NAT64 prefix length this datapath supports. RFC
// 6052 defines six, but a /96 is the one that places the embedded IPv4 address
// in a single aligned four-byte run, which is what lets the datapath extract it
// without a bit-shuffle on the hot path.
const nat64PrefixLen = 96

// v4ToWire converts an IPv4 address into the word shard_config.shard_pub_addr4
// holds. The datapath copies that word straight onto the wire, so its native
// byte order must already be the on-wire order; reading it big-endian would put
// the address on the wire reversed on any little-endian host.
func v4ToWire(addr netip.Addr) uint32 {
	a := addr.As4()
	return binary.NativeEndian.Uint32(a[:])
}

func v4FromWire(word uint32) netip.Addr {
	var a [4]byte
	binary.NativeEndian.PutUint32(a[:], word)
	return netip.AddrFrom4(a)
}

// ShardConfigTable is the read/write API for shard_config_table.
type ShardConfigTable struct {
	table Table
}

// NewShardConfigTable wraps table as a ShardConfigTable. Production callers pass
// a kernel table over the loaded map; tests pass a fake.
func NewShardConfigTable(table Table) *ShardConfigTable {
	return &ShardConfigTable{table: table}
}

// validateAddr rejects anything that is not a native IPv6 address, this datapath
// being IPv6-only.
func validateAddr(field string, addr netip.Addr) error {
	if !addr.Is6() || addr.Is4In6() {
		return fmt.Errorf("%s %s is not a native IPv6 address (phase 1 is IPv6-only)", field, addr)
	}
	return nil
}

// Set writes, or overwrites, the single entry with cfg. A blind overwrite
// rather than a read-modify-write: this map carries no counters or other
// datapath-owned fields to preserve, and so has none of the race a
// read-modify-write would risk on a map the datapath itself increments.
func (t *ShardConfigTable) Set(cfg ShardConfig) error {
	value, err := cfg.toWire()
	if err != nil {
		return fmt.Errorf("natmap: shard_config_table: set: %w", err)
	}
	if err := t.table.Put(shardConfigKey, value); err != nil {
		return fmt.Errorf("natmap: shard_config_table: set: %w", err)
	}
	return nil
}

// toWire validates cfg and encodes it for the datapath.
//
// A shard must serve at least one family: writing a config that serves neither
// loads a datapath that claims no packet at all, which presents as a silent
// blackhole rather than as the misconfiguration it is.
func (c ShardConfig) toWire() (natprog.NatShardConfig, error) {
	if err := validateAddr("shard SID", c.ShardSID); err != nil {
		return natprog.NatShardConfig{}, err
	}

	value := natprog.NatShardConfig{
		ShardSid: c.ShardSID.As16(),
	}

	if c.ShardPubAddr6.IsValid() {
		if err := validateAddr("shard public address", c.ShardPubAddr6); err != nil {
			return natprog.NatShardConfig{}, err
		}
		value.ShardPubAddr6 = c.ShardPubAddr6.As16()
		value.ServesV6 = 1
	}

	if c.ShardPubAddr4.IsValid() {
		if !c.ShardPubAddr4.Is4() {
			return natprog.NatShardConfig{}, fmt.Errorf(
				"shard public IPv4 address %s is not an IPv4 address", c.ShardPubAddr4)
		}
		if !c.NAT64Prefix.IsValid() {
			return natprog.NatShardConfig{}, errors.New(
				"a shard public IPv4 address needs a NAT64 prefix to translate for")
		}
		if err := validateAddr("NAT64 prefix", c.NAT64Prefix.Addr()); err != nil {
			return natprog.NatShardConfig{}, err
		}
		if c.NAT64Prefix.Bits() != nat64PrefixLen {
			return natprog.NatShardConfig{}, fmt.Errorf(
				"NAT64 prefix %s must be a /%d", c.NAT64Prefix, nat64PrefixLen)
		}
		if c.NAT64Prefix.Masked() != c.NAT64Prefix {
			return natprog.NatShardConfig{}, fmt.Errorf(
				"NAT64 prefix %s has bits set below its prefix length", c.NAT64Prefix)
		}
		value.Nat64Prefix = c.NAT64Prefix.Addr().As16()
		value.ShardPubAddr4 = v4ToWire(c.ShardPubAddr4)
		value.ServesV4 = 1
	} else if c.NAT64Prefix.IsValid() {
		return natprog.NatShardConfig{}, errors.New(
			"a NAT64 prefix needs a shard public IPv4 address to translate into")
	}

	if value.ServesV6 == 0 && value.ServesV4 == 0 {
		return natprog.NatShardConfig{}, errors.New(
			"a shard must serve at least one address family")
	}
	return value, nil
}

// Get reads the single entry and reports whether it has been written yet. Until
// it has, the datapath fails open and claims no packets.
func (t *ShardConfigTable) Get() (ShardConfig, bool, error) {
	var value natprog.NatShardConfig
	if err := t.table.Lookup(shardConfigKey, &value); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return ShardConfig{}, false, nil
		}
		return ShardConfig{}, false, fmt.Errorf("natmap: shard_config_table: get: %w", err)
	}
	cfg := ShardConfig{
		ShardSID: netip.AddrFrom16(value.ShardSid),
	}
	if value.ServesV6 != 0 {
		cfg.ShardPubAddr6 = netip.AddrFrom16(value.ShardPubAddr6)
	}
	if value.ServesV4 != 0 {
		cfg.ShardPubAddr4 = v4FromWire(value.ShardPubAddr4)
		cfg.NAT64Prefix = netip.PrefixFrom(netip.AddrFrom16(value.Nat64Prefix), nat64PrefixLen)
	}
	return cfg, true, nil
}
