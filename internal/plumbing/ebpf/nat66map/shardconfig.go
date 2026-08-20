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

// shardConfigKey is shard_config_table's single, fixed key (nat66.c's
// `__u32 cfg_key = 0`) -- this map is a BPF_MAP_TYPE_ARRAY with
// max_entries=1, so there is exactly one valid key, ever.
const shardConfigKey uint32 = 0

// ShardConfig is shard_config_table's fully decoded single row: this
// shard's own operator-supplied identity (internal/config.NAT66Config's
// ShardSID/ShardPubAddr, already validated there). See nat66.c's header
// comment for what each address is used for.
type ShardConfig struct {
	// ShardSID is this shard's own SRv6 uSID (uFMT 48+16) -- the outer
	// destination a tenant's egress packet is encapsulated toward, and the
	// re-encap source handle_return uses on the way back.
	ShardSID netip.Addr

	// ShardPubAddr is this shard's own publicly-routable masquerade source
	// address -- every flow this shard NATs is SNAT'd to an address:port
	// within it.
	ShardPubAddr netip.Addr
}

// ShardConfigTable is the read/write API for shard_config_table.
type ShardConfigTable struct {
	table Table
}

// NewShardConfigTable wraps table as a ShardConfigTable. Production callers
// pass a KernelTable wrapping a loaded *nat66prog.Nat66Objects's
// ShardConfigTable map; tests pass a fake Table.
func NewShardConfigTable(table Table) *ShardConfigTable {
	return &ShardConfigTable{table: table}
}

// validateAddr rejects anything that isn't a native IPv6 address --
// phase 1 is IPv6-only, matching every other table in this codebase's own
// convention (e.g. edgemap.toWireKey's identical check).
func validateAddr(field string, addr netip.Addr) error {
	if !addr.Is6() || addr.Is4In6() {
		return fmt.Errorf("%s %s is not a native IPv6 address (phase 1 is IPv6-only)", field, addr)
	}
	return nil
}

// Set writes (or overwrites) shard_config_table's single entry with cfg.
// This is a blind overwrite, not a read-modify-write: shard_config_table
// carries no counters or other datapath-owned fields to preserve across a
// re-write (unlike, e.g., edgemap.VIPTable's own vip_table/vip_stats_table
// split -- see that package's Register doc comment for the race a
// read-modify-write would otherwise risk here; shard_config_table has no
// such risk because it has nothing the datapath itself increments).
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

// Get reads shard_config_table's single entry, reporting whether it has
// been written yet (nat66_ingress fails open -- XDP_PASS, not claimed --
// on every packet until it has, per nat66.c's header comment).
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
