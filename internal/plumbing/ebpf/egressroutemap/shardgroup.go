// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package egressroutemap

import (
	"fmt"
	"math"
	"net"
	"net/netip"
	"sort"
	"sync"
	"time"

	"go.datum.net/galactic/internal/maglev"
	"go.datum.net/galactic/internal/plumbing/ebpf/prog"
	"go.datum.net/galactic/internal/plumbing/ebpf/uformat"
)

// The shard group layout, mirroring usid.c's USID_EGRESS_* constants. bpf2go
// generates no symbol for a #define, so each value is named once here.
const (
	// NAT66ShardGroup is the group serving the ::/0 route. NAT64 prefixes
	// take the groups after it, in the order they are configured.
	NAT66ShardGroup uint32 = 0

	// MaxShardGroups is how many groups egress_shard_groups holds: NAT66 and
	// up to MaxNAT64Groups NAT64 prefixes.
	MaxShardGroups = 4

	// MaxNAT64Groups is how many NAT64 prefixes hashed mode can serve.
	MaxNAT64Groups = MaxShardGroups - 1

	// MaxShardsPerGroup is how many shards one group holds.
	MaxShardsPerGroup = 32

	// ShardMaglevTableSize is the number of slots in a group's Maglev table.
	ShardMaglevTableSize = 1021

	// groupSentinelIfindex marks an egress_route_table entry that names a
	// shard group rather than one shard.
	groupSentinelIfindex uint32 = math.MaxUint32

	// shardSlotNone marks a Maglev slot with no shard.
	shardSlotNone uint8 = 0xFF

	groupFlagEnabled  uint32 = 1 << 0
	groupFlagHashFlow uint32 = 1 << 1
	groupFlagClosing  uint32 = 1 << 2

	shardFlagAlive    uint32 = 1 << 0
	shardFlagDraining uint32 = 1 << 1

	classKindNAT66 uint8 = 1
	classKindNAT64 uint8 = 2
)

// DefaultPinIdle is how long a tenant address stays pinned to its shard after
// its last packet: the egress shard's longest idle timeout, the 2 h 4 min
// RFC 5382 asks for an established TCP session. A pin then never outlives the
// shard session it protects.
const DefaultPinIdle = 2*time.Hour + 4*time.Minute

// WellKnownPrefix is the RFC 6052 NAT64 Well-Known Prefix, which a shard
// translates when its status says translatesWellKnownPrefix.
var WellKnownPrefix = netip.MustParsePrefix("64:ff9b::/96")

// HashMode selects what a shard group hashes to place a packet.
type HashMode uint8

const (
	// HashSource hashes the tenant's source address, so every connection
	// from one address uses one shard and one public address (RFC 4787
	// REQ-2, paired pooling). The default.
	HashSource HashMode = iota

	// HashFlow hashes the 5-tuple, spreading one heavy tenant address over
	// every shard. It gives up paired pooling: one address appears from
	// several public addresses.
	HashFlow
)

// String returns the mode's configuration spelling.
func (m HashMode) String() string {
	if m == HashFlow {
		return "flow"
	}
	return "source"
}

// TranslationClass is what a group translates: NAT66, for the ::/0 route, or
// NAT64 toward one prefix, for that prefix's route. A group's members are only
// the shards that can translate its class.
type TranslationClass struct {
	// NAT64 is false for NAT66.
	NAT64 bool
	// Prefix is the NAT64 /96. Unset for NAT66.
	Prefix netip.Prefix
}

// NAT66Class is the class of the ::/0 route.
var NAT66Class = TranslationClass{}

// NAT64Class is the class of the route toward prefix.
func NAT64Class(prefix netip.Prefix) TranslationClass {
	return TranslationClass{NAT64: true, Prefix: prefix.Masked()}
}

// String returns the class as a metric label: nat66, or nat64:<prefix>.
func (c TranslationClass) String() string {
	if !c.NAT64 {
		return "nat66"
	}
	return "nat64:" + c.Prefix.String()
}

func (c TranslationClass) encode(value *prog.UsidEgressShardGroupValue) {
	value.ClassKind = classKindNAT66
	value.ClassPrefix = [16]byte{}
	if c.NAT64 {
		value.ClassKind = classKindNAT64
		value.ClassPrefix = c.Prefix.Addr().As16()
	}
}

func decodeClass(value prog.UsidEgressShardGroupValue) (TranslationClass, bool) {
	switch value.ClassKind {
	case classKindNAT66:
		return NAT66Class, true
	case classKindNAT64:
		return NAT64Class(netip.PrefixFrom(netip.AddrFrom16(value.ClassPrefix), 96)), true
	}
	return TranslationClass{}, false
}

// ClassForRoute returns the class an egress route toward prefix needs: NAT66
// for the IPv6 default, NAT64 for any other IPv6 prefix.
func ClassForRoute(prefix *net.IPNet) (TranslationClass, bool) {
	addr, ok := netip.AddrFromSlice(prefix.IP)
	if !ok {
		return TranslationClass{}, false
	}
	ones, bits := prefix.Mask.Size()
	if bits != 128 || addr.Unmap().Is4() {
		return TranslationClass{}, false
	}
	if ones == 0 {
		return NAT66Class, true
	}
	return NAT64Class(netip.PrefixFrom(addr, ones)), true
}

// GroupPolicy is how a shard group places tenants and what it translates.
type GroupPolicy struct {
	Class TranslationClass
	Hash  HashMode
	// PinIdle is how long a pin outlives its last packet. Zero turns pins
	// off, leaving placement to the Maglev table alone.
	PinIdle time.Duration
	// Closing marks the group as being retired; see ShardGroupTable.Close.
	Closing bool
	// Ineligible is how many of the cluster's shards cannot translate Class.
	// Recorded for the metrics only.
	Ineligible int
}

// ShardCandidate is one shard a group may use. SID's Argument is ignored: the
// group stores each shard's base SID and the datapath writes each tenant's
// Argument into it per packet.
type ShardCandidate struct {
	SID net.IP
	// Draining keeps the shard out of the Maglev table, so it takes no new
	// tenant address, while its pins keep working.
	Draining bool
}

// ShardState reports one group member.
type ShardState struct {
	// SID is the shard's base SID.
	SID netip.Addr
	// Slot is the shard's index within its group.
	Slot int
	// Generation identifies the shard's tenure of its slot.
	Generation uint32
	// Alive reports that the SID resolved to an uplink neighbor.
	Alive bool
	// Draining echoes the candidate's Draining.
	Draining bool
	// Err is why the SID did not resolve, when it did not.
	Err error
	// Assigned reports that this Apply gave the shard its slot, so nothing
	// counted in the slot before belongs to it.
	Assigned bool
}

// Active reports whether the shard takes new tenant addresses.
func (s ShardState) Active() bool { return s.Alive && !s.Draining }

// GroupResult reports what Apply found and published.
type GroupResult struct {
	// Changed reports that Apply published a new snapshot.
	Changed bool
	// Generation is the group's publication count after Apply.
	Generation uint32
	// Shards is every candidate, ordered by base SID.
	Shards []ShardState
}

// Active counts the shards taking new tenant addresses.
func (r GroupResult) Active() int {
	n := 0
	for _, s := range r.Shards {
		if s.Active() {
			n++
		}
	}
	return n
}

// GroupStatus is a group's published state, as CNI ADD and the metrics read
// it.
type GroupStatus struct {
	// Present reports that a snapshot has ever been published for the group.
	Present bool
	// Enabled reports that the group carries traffic.
	Enabled bool
	// Closing reports that the cluster is moving back to ordered mode: no
	// new route should name the group.
	Closing bool
	// Class is what the group translates.
	Class TranslationClass
	// Candidates counts the shards eligible for Class.
	Candidates int
	// Active counts the shards taking new tenant addresses.
	Active int
	// Ineligible counts the cluster's shards that cannot translate Class.
	Ineligible int
	// Generation is the publication count.
	Generation uint32
}

// Open reports whether a new route may name the group.
func (s GroupStatus) Open() bool { return s.Enabled && !s.Closing }

// GroupStore reads and publishes whole group snapshots. Publish must make the
// new snapshot visible to the datapath in one step, or not at all.
type GroupStore interface {
	// Load returns groupID's published snapshot, and false when none has
	// been published.
	Load(groupID uint32) (prog.UsidEgressShardGroupValue, bool, error)
	// Publish replaces groupID's snapshot with value.
	Publish(groupID uint32, value prog.UsidEgressShardGroupValue) error
}

// ShardGroupTable builds and publishes the egress shard groups. galactic-cni's
// installer is the only writer; CNI ADD and the metrics only read.
//
// Slot generations. Every member slot carries a generation identifying the
// shard's tenure of it, and a pin is honoured only while the slot still
// carries the generation it recorded. A generation is allocated from the
// group's next_slot_generation, which is published in the snapshot, and from
// highWater, which also counts generations allocated for snapshots this
// process built but failed to publish. Neither ever goes down: disabling a
// group keeps next_slot_generation, and a restarted process starts from the
// published value. A generation the published value does not cover was only
// ever in a snapshot that was never published, so no packet saw it and no pin
// can hold it. The counter is 32 bits and skips 0 on wrap, which takes four
// billion slot assignments; a pin lives at most PinIdle, so a wrapped value
// cannot meet a pin still holding it.
type ShardGroupTable struct {
	store GroupStore

	mu        sync.Mutex
	highWater [MaxShardGroups]uint32
}

// NewShardGroupTable wraps store. Production callers use
// OpenPinnedShardGroupTable; tests pass a fake.
func NewShardGroupTable(store GroupStore) *ShardGroupTable {
	return &ShardGroupTable{store: store}
}

// BaseShardSID returns sid with its Argument and Slot cleared: the identity a
// group stores a shard under. An address that is not a well-formed uSID is an
// error.
func BaseShardSID(sid net.IP) (netip.Addr, error) {
	fields, err := decodeSID(sid)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("egress shard SID %s: %w", sid, err)
	}
	fields.Argument, fields.Slot = 0, 0
	base, err := uformat.Encode(fields)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("egress shard SID %s: %w", sid, err)
	}
	return base, nil
}

func checkGroup(groupID uint32) error {
	if groupID >= MaxShardGroups {
		return fmt.Errorf("egressroutemap: shard group %d out of range", groupID)
	}
	return nil
}

// load reads groupID's snapshot, an absent one reading as the zero value.
func (g *ShardGroupTable) load(groupID uint32) (prog.UsidEgressShardGroupValue, bool, error) {
	if err := checkGroup(groupID); err != nil {
		return prog.UsidEgressShardGroupValue{}, false, err
	}
	value, ok, err := g.store.Load(groupID)
	if err != nil {
		return prog.UsidEgressShardGroupValue{}, false, fmt.Errorf("egressroutemap: read shard group %d: %w", groupID, err)
	}
	return value, ok, nil
}

// Status reads groupID's published state.
func (g *ShardGroupTable) Status(groupID uint32) (GroupStatus, error) {
	value, ok, err := g.load(groupID)
	if err != nil || !ok {
		return GroupStatus{}, err
	}
	class, _ := decodeClass(value)
	return GroupStatus{
		Present:    true,
		Enabled:    value.Flags&groupFlagEnabled != 0,
		Closing:    value.Flags&groupFlagClosing != 0,
		Class:      class,
		Candidates: int(value.Candidates),
		Active:     int(value.Active),
		Ineligible: int(value.Ineligible),
		Generation: value.Generation,
	}, nil
}

// FindClass returns the group whose published class is class.
func (g *ShardGroupTable) FindClass(class TranslationClass) (uint32, GroupStatus, bool, error) {
	for id := range uint32(MaxShardGroups) {
		status, err := g.Status(id)
		if err != nil {
			return 0, GroupStatus{}, false, err
		}
		if status.Present && status.Class == class {
			return id, status, true, nil
		}
	}
	return 0, GroupStatus{}, false, nil
}

// AnyOpen reports whether any group may take new routes: hashed mode is in
// force on this node.
func (g *ShardGroupTable) AnyOpen() (bool, error) {
	for id := range uint32(MaxShardGroups) {
		status, err := g.Status(id)
		if err != nil {
			return false, err
		}
		if status.Open() {
			return true, nil
		}
	}
	return false, nil
}

// Members returns groupID's occupied slots, ordered by slot.
func (g *ShardGroupTable) Members(groupID uint32) ([]ShardState, error) {
	value, _, err := g.load(groupID)
	if err != nil {
		return nil, err
	}
	var members []ShardState
	for i, s := range value.Shards {
		if !slotOccupied(s) {
			continue
		}
		members = append(members, ShardState{
			SID:        netip.AddrFrom16(s.Sid),
			Slot:       i,
			Generation: s.Generation,
			Alive:      s.Flags&shardFlagAlive != 0,
			Draining:   s.Flags&shardFlagDraining != 0,
		})
	}
	return members, nil
}

func slotOccupied(s prog.UsidEgressShardMember) bool {
	return s.Sid != [16]byte{}
}

// shardBackend is one active shard as a Maglev backend.
type shardBackend struct {
	sid  netip.Addr
	slot int
}

func (b shardBackend) Key() string { return b.sid.String() }

// allocator hands out slot generations for one build: from the larger of the
// published counter and this process's high-water mark, never 0.
type allocator struct{ next uint32 }

func (a *allocator) take() uint32 {
	if a.next == 0 {
		a.next = 1
	}
	g := a.next
	a.next++
	return g
}

// Apply makes groupID serve exactly candidates under policy and publishes the
// result as one snapshot.
//
// Every candidate's SID is resolved to an uplink next hop here, as Register
// does for a single shard, and only a shard that resolves is alive. The Maglev
// table spreads tenant addresses over the alive shards that are not draining.
// Every node computes the same table from the same set, whatever slots the
// shards occupy locally.
//
// A shard keeps its slot, and the slot keeps its generation, for as long as
// the shard stays a candidate of the same class, so a rebuild leaves its pins
// intact. A new shard takes the lowest free slot under a fresh generation.
// Nothing is published when nothing changed.
func (g *ShardGroupTable) Apply(groupID uint32, policy GroupPolicy, candidates []ShardCandidate) (GroupResult, error) {
	wanted, err := canonicalCandidates(candidates)
	if err != nil {
		return GroupResult{}, err
	}
	if len(wanted) > MaxShardsPerGroup {
		return GroupResult{}, fmt.Errorf("egressroutemap: %d egress shards exceed the group limit of %d",
			len(wanted), MaxShardsPerGroup)
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	current, _, err := g.load(groupID)
	if err != nil {
		return GroupResult{}, err
	}
	previous := current.Shards
	if class, ok := decodeClass(current); ok && class.String() != policy.Class.String() {
		// A group that changes class starts afresh: no member keeps its
		// slot, so no pin made for the old class survives.
		previous = [MaxShardsPerGroup]prog.UsidEgressShardMember{}
	}
	alloc := allocator{next: max(current.NextSlotGeneration, g.highWater[groupID])}

	assignment := assignSlots(previous, wanted)
	resolved := resolveShards(wanted)

	var (
		value    prog.UsidEgressShardGroupValue
		result   = GroupResult{Generation: current.Generation}
		backends []maglev.Backend
	)
	for _, c := range wanted {
		slot := assignment[c.sid]
		hop := resolved[c.sid]
		member := prog.UsidEgressShardMember{Sid: c.sid.As16(), Generation: previous[slot].Generation}
		assigned := !slotOccupied(previous[slot]) || netip.AddrFrom16(previous[slot].Sid) != c.sid ||
			member.Generation == 0
		if assigned {
			member.Generation = alloc.take()
		}
		if hop.err == nil {
			member.Flags |= shardFlagAlive
			member.LinkIfindex = uint32(hop.hop.link) //nolint:gosec // a kernel ifindex
			copy(member.Dmac[:], hop.hop.dmac)
			copy(member.Smac[:], hop.hop.smac)
		}
		if c.draining {
			member.Flags |= shardFlagDraining
		}
		value.Shards[slot] = member

		state := ShardState{
			SID: c.sid, Slot: slot, Generation: member.Generation, Alive: hop.err == nil,
			Draining: c.draining, Err: hop.err, Assigned: assigned,
		}
		result.Shards = append(result.Shards, state)
		if state.Active() {
			backends = append(backends, shardBackend{sid: c.sid, slot: slot})
		}
	}
	// The high-water mark moves before publishing, so a failed publication
	// never hands the same generation out twice.
	g.highWater[groupID] = alloc.next

	if err := fillGroupValue(&value, policy, len(wanted), backends); err != nil {
		return GroupResult{}, err
	}
	value.NextSlotGeneration = alloc.next
	value.Generation = current.Generation
	if value == current {
		return result, nil
	}
	value.Generation = current.Generation + 1
	if err := g.store.Publish(groupID, value); err != nil {
		return result, fmt.Errorf("egressroutemap: publish shard group %d: %w", groupID, err)
	}
	result.Generation = value.Generation
	result.Changed = true
	return result, nil
}

// Close marks groupID as being retired, for the move back to ordered mode. The
// datapath keeps forwarding through it, with its members' next hops
// re-resolved, so a route still naming it works; CNI ADD sees it closing and
// writes no new route naming it. A group that is not enabled is left alone.
// It reports whether the group is closing afterwards.
func (g *ShardGroupTable) Close(groupID uint32) (bool, error) {
	value, ok, err := g.load(groupID)
	if err != nil || !ok || value.Flags&groupFlagEnabled == 0 {
		return false, err
	}
	class, _ := decodeClass(value)
	policy := GroupPolicy{
		Class:      class,
		PinIdle:    time.Duration(value.PinIdleSec) * time.Second,
		Closing:    true,
		Ineligible: int(value.Ineligible),
	}
	if value.Flags&groupFlagHashFlow != 0 {
		policy.Hash = HashFlow
	}
	var candidates []ShardCandidate
	for _, s := range value.Shards {
		if slotOccupied(s) {
			candidates = append(candidates, ShardCandidate{
				SID: net.IP(netip.AddrFrom16(s.Sid).AsSlice()), Draining: s.Flags&shardFlagDraining != 0,
			})
		}
	}
	if _, err := g.Apply(groupID, policy, candidates); err != nil {
		return false, err
	}
	return true, nil
}

// Disable publishes groupID with no members and traffic off, which is what
// ordered mode leaves behind. A route still naming it drops until Refresh
// moves it back onto a single shard, so callers disable a group only once no
// route names it. The class and the generation counter are kept. It reports
// whether anything changed.
func (g *ShardGroupTable) Disable(groupID uint32) (bool, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	current, ok, err := g.load(groupID)
	if err != nil || !ok {
		return false, err
	}
	disabled := prog.UsidEgressShardGroupValue{
		Generation:         current.Generation,
		NextSlotGeneration: max(current.NextSlotGeneration, g.highWater[groupID]),
		ClassKind:          current.ClassKind,
		ClassPrefix:        current.ClassPrefix,
	}
	for i := range disabled.Maglev {
		disabled.Maglev[i] = shardSlotNone
	}
	if disabled == current {
		return false, nil
	}
	disabled.Generation = current.Generation + 1
	if err := g.store.Publish(groupID, disabled); err != nil {
		return false, fmt.Errorf("egressroutemap: disable shard group %d: %w", groupID, err)
	}
	return true, nil
}

// candidate is a ShardCandidate reduced to its base SID.
type candidate struct {
	sid      netip.Addr
	draining bool
}

// canonicalCandidates reduces candidates to base SIDs, ordered by SID. A
// shard listed twice is draining if either listing says so.
func canonicalCandidates(candidates []ShardCandidate) ([]candidate, error) {
	bySID := map[netip.Addr]bool{}
	for _, c := range candidates {
		base, err := BaseShardSID(c.SID)
		if err != nil {
			return nil, fmt.Errorf("egressroutemap: %w", err)
		}
		bySID[base] = bySID[base] || c.Draining
	}
	out := make([]candidate, 0, len(bySID))
	for sid, draining := range bySID {
		out = append(out, candidate{sid: sid, draining: draining})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].sid.Less(out[j].sid) })
	return out, nil
}

// assignSlots keeps every wanted shard already in a slot there, and gives each
// new one the lowest slot no wanted shard holds.
func assignSlots(slots [MaxShardsPerGroup]prog.UsidEgressShardMember, wanted []candidate) map[netip.Addr]int {
	assignment := make(map[netip.Addr]int, len(wanted))
	taken := map[int]bool{}
	isWanted := make(map[netip.Addr]bool, len(wanted))
	for _, c := range wanted {
		isWanted[c.sid] = true
	}
	for i, s := range slots {
		sid := netip.AddrFrom16(s.Sid)
		if slotOccupied(s) && isWanted[sid] {
			if _, dup := assignment[sid]; !dup {
				assignment[sid] = i
				taken[i] = true
			}
		}
	}
	next := 0
	for _, c := range wanted {
		if _, ok := assignment[c.sid]; ok {
			continue
		}
		for taken[next] {
			next++
		}
		assignment[c.sid] = next
		taken[next] = true
	}
	return assignment
}

// resolveShards resolves every wanted shard's next hop.
func resolveShards(wanted []candidate) map[netip.Addr]resolution {
	out := make(map[netip.Addr]resolution, len(wanted))
	for _, c := range wanted {
		link, dmac, smac, err := resolveLinkAndL2Fn(net.IP(c.sid.AsSlice()))
		out[c.sid] = resolution{hop: nextHop{link: link, dmac: dmac, smac: smac}, err: err}
	}
	return out
}

// fillGroupValue fills an enabled group's header and Maglev table over
// backends. With no backend every slot is shardSlotNone.
func fillGroupValue(
	value *prog.UsidEgressShardGroupValue, policy GroupPolicy, candidates int, backends []maglev.Backend,
) error {
	value.Flags = groupFlagEnabled
	if policy.Hash == HashFlow {
		value.Flags |= groupFlagHashFlow
	}
	if policy.Closing {
		value.Flags |= groupFlagClosing
	}
	policy.Class.encode(value)
	value.Candidates = uint16(candidates)                             //nolint:gosec // bounded by MaxShardsPerGroup
	value.Active = uint16(len(backends))                              //nolint:gosec // bounded by MaxShardsPerGroup
	value.Ineligible = uint16(min(policy.Ineligible, math.MaxUint16)) //nolint:gosec // clamped
	value.PinIdleSec = uint32(policy.PinIdle / time.Second)           //nolint:gosec // a configured duration
	for i := range value.Maglev {
		value.Maglev[i] = shardSlotNone
	}
	if len(backends) == 0 {
		return nil
	}
	table, err := maglev.New(backends, ShardMaglevTableSize)
	if err != nil {
		return fmt.Errorf("egressroutemap: build shard Maglev table: %w", err)
	}
	for i := range value.Maglev {
		value.Maglev[i] = uint8(table.Lookup(uint64(i)).(shardBackend).slot) //nolint:gosec // slot < MaxShardsPerGroup
	}
	return nil
}
