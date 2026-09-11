// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package nat66map

import (
	"errors"
	"fmt"
	"net/netip"

	"github.com/cilium/ebpf"

	"go.datum.net/galactic/internal/plumbing/ebpf/nat66prog"
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

	// ShardPubAddr is this shard's publicly routable masquerade source. Every
	// flow this shard translates is given an address and port within it.
	ShardPubAddr netip.Addr
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
	if err := validateAddr("shard SID", cfg.ShardSID); err != nil {
		return fmt.Errorf("nat66map: shard_config_table: set: %w", err)
	}
	if err := validateAddr("shard public address", cfg.ShardPubAddr); err != nil {
		return fmt.Errorf("nat66map: shard_config_table: set: %w", err)
	}

	value := nat66prog.Nat66ShardConfig{
		ShardSid:     cfg.ShardSID.As16(),
		ShardPubAddr: cfg.ShardPubAddr.As16(),
	}
	if err := t.table.Put(shardConfigKey, value); err != nil {
		return fmt.Errorf("nat66map: shard_config_table: set: %w", err)
	}
	return nil
}

// Get reads the single entry and reports whether it has been written yet. Until
// it has, the datapath fails open and claims no packets.
func (t *ShardConfigTable) Get() (ShardConfig, bool, error) {
	var value nat66prog.Nat66ShardConfig
	if err := t.table.Lookup(shardConfigKey, &value); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return ShardConfig{}, false, nil
		}
		return ShardConfig{}, false, fmt.Errorf("nat66map: shard_config_table: get: %w", err)
	}
	return ShardConfig{
		ShardSID:     netip.AddrFrom16(value.ShardSid),
		ShardPubAddr: netip.AddrFrom16(value.ShardPubAddr),
	}, true, nil
}
