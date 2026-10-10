// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package egressroutemap

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"net"
	"net/netip"

	"go.datum.net/galactic/internal/plumbing/ebpf/prog"
	"go.datum.net/galactic/internal/plumbing/ebpf/uformat"
)

// RegisterGroup installs or replaces egress_route_table's entry for prefix in
// Linux VRF table tableID as a shard group sentinel: usid_egress picks one of
// groupID's shards per packet and writes argument, the tenant's VRFID, into
// its SID. Nothing is resolved here; the group's shards carry their own next
// hops.
func (t *EgressRouteTable) RegisterGroup(tableID uint32, prefix *net.IPNet, groupID uint32, argument uint16) error {
	key, err := buildKey(tableID, prefix)
	if err != nil {
		return fmt.Errorf("egressroutemap: egress_route_table: register group: %w", err)
	}
	if groupID >= MaxShardGroups {
		return fmt.Errorf("egressroutemap: egress_route_table: register group: group %d out of range", groupID)
	}
	if argument < uformat.ArgumentMin || argument > uformat.ArgumentMax {
		return fmt.Errorf("egressroutemap: egress_route_table: register group: %w", uformat.ValidateArgument(argument))
	}
	if err := t.table.Put(key, groupSentinel(groupID, argument)); err != nil {
		return fmt.Errorf("egressroutemap: egress_route_table: register group table=%d prefix=%s: %w",
			tableID, prefix, err)
	}
	return nil
}

// groupSentinel builds the sentinel value for groupID and argument. See struct
// egress_route_value's sentinel comment in usid.c for the layout.
func groupSentinel(groupID uint32, argument uint16) prog.UsidEgressRouteValue {
	value := prog.UsidEgressRouteValue{LinkIfindex: groupSentinelIfindex}
	binary.NativeEndian.PutUint32(value.Sid[0:4], groupID)
	value.Sid[8] = byte(argument>>8) & 0x0F
	value.Sid[9] = byte(argument)
	return value
}

// isGroupSentinel reports whether value names a shard group.
func isGroupSentinel(value prog.UsidEgressRouteValue) bool {
	return value.LinkIfindex == groupSentinelIfindex
}

// sentinelGroup returns the group and tenant Argument a sentinel carries.
func sentinelGroup(value prog.UsidEgressRouteValue) (groupID uint32, argument uint16) {
	return binary.NativeEndian.Uint32(value.Sid[0:4]), uint16(value.Sid[8]&0x0F)<<8 | uint16(value.Sid[9])
}

// ShardPinKey is the input the datapath hashes to place a packet, and the key
// it pins the result under. It mirrors struct egress_shard_pin_key.
type ShardPinKey struct {
	TableID uint32
	GroupID uint32
	// Src and Dst are the packet's inner addresses. Dst, Protocol and the
	// ports are read only in flow mode.
	Src, Dst netip.Addr
	Protocol uint8
	// SrcPort and DstPort are zero for a fragment and for any protocol but
	// TCP and UDP, as the datapath leaves them.
	SrcPort, DstPort uint16
}

// Bytes returns k laid out as struct egress_shard_pin_key for mode, with the
// fields mode does not read zeroed as the datapath zeroes them.
func (k ShardPinKey) Bytes(mode HashMode) []byte {
	key := prog.UsidEgressShardPinKey{TableId: k.TableID, Group: uint8(k.GroupID)} //nolint:gosec // < MaxShardGroups
	if k.Src.Is4() {
		key.Family = egressRouteFamilyINET4
		v4 := k.Src.As4()
		copy(key.Saddr[:4], v4[:])
	} else {
		key.Family = egressRouteFamilyINET6
		key.Saddr = k.Src.As16()
	}
	if mode == HashFlow {
		key.Protocol = k.Protocol
		if k.Dst.Is4() {
			v4 := k.Dst.As4()
			copy(key.Daddr[:4], v4[:])
		} else if k.Dst.IsValid() {
			key.Daddr = k.Dst.As16()
		}
		// The datapath copies the ports straight out of the header, so
		// they sit in the key in network byte order.
		var ports [4]byte
		binary.BigEndian.PutUint16(ports[0:2], k.SrcPort)
		binary.BigEndian.PutUint16(ports[2:4], k.DstPort)
		key.Sport = binary.NativeEndian.Uint16(ports[0:2])
		key.Dport = binary.NativeEndian.Uint16(ports[2:4])
	}
	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.NativeEndian, key) // a fixed-size struct cannot fail to encode
	return buf.Bytes()
}

// ShardHash is the hash usid_egress computes over key: 32-bit FNV-1a.
func ShardHash(key []byte) uint32 {
	h := fnv.New32a()
	_, _ = h.Write(key)
	return h.Sum32()
}
