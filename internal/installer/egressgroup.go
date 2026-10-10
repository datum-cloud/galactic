// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package installer

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/client-go/rest"
	toolscache "k8s.io/client-go/tools/cache"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"go.datum.net/galactic/internal/config"
	"go.datum.net/galactic/internal/plumbing/ebpf/attach"
	"go.datum.net/galactic/internal/plumbing/ebpf/egressroutemap"
	"go.datum.net/galactic/internal/plumbing/ebpf/metrics"
	"go.datum.net/galactic/internal/plumbing/ebpf/prog"
	"go.datum.net/galactic/internal/plumbing/ebpf/usidmap"
	bgpv1alpha1 "go.datum.net/network/api/v1alpha1"
)

// egressGroupDebounce is how long a burst of route, neighbor or EgressShard
// events is collected before one sweep handles all of it. A BGP withdrawal
// removes a shard's route and then its neighbor in quick succession, and a
// sweep for each would only repeat the work.
var egressGroupDebounce = 250 * time.Millisecond

// egressGroup keeps egress_route_table and the egress shard groups in line
// with the configured egress mode.
//
// In ordered mode it re-resolves every entry and keeps each VRF on the first
// reachable shard of the static list, as the egress route sweep always has.
// Leaving hashed mode takes three steps, each only after the one before it
// succeeded in full: every enabled group is marked closing, so no CNI ADD
// writes a new route naming it while it keeps forwarding; every route naming
// a group is moved onto the static list; and only once a sweep that started
// after the groups closed has moved every one, and found none left, are the
// groups disabled. A failed scan or write leaves the groups forwarding.
//
// In hashed mode there is one group per translation class: NAT66 for ::/0,
// and one per NAT64 prefix. A class's members are the cluster's EgressShards
// that can translate it, read from a watch, and a member is alive only while
// its SID resolves to an uplink neighbor. Every VRF route bound to a shard is
// moved onto its class's group, after which usid_egress picks a shard per
// tenant address.
//
// All of it runs on one goroutine, started by run, and is triggered by kick:
// on the egress route ticker, on any EgressShard change, and on any route or
// neighbor change that can move a shard's reachability, so a withdrawn shard
// leaves the group as soon as BGP withdraws its route rather than at the next
// tick. A kick during a sweep queues exactly one more.
type egressGroup struct {
	cfg        config.EgressGroupConfig
	staticSIDs []net.IP
	pinDir     string
	trigger    chan struct{}

	// classes are the translation classes this node's VRFs need, in group
	// order: NAT66, then each configured NAT64 prefix.
	classes []egressroutemap.TranslationClass

	// shards lists the cluster's EgressShards. Nil in ordered mode, and in
	// hashed mode until the watch has started.
	shards egressShardLister

	// counters is egress_shard_counters, whose slots Apply hands to new
	// shards. Nil when the datapath is a test fake.
	counters *ebpf.Map

	// ctl reports the control loop's state. Nil in tests.
	ctl *metrics.EgressControl

	// locators is the set of /64 locators the groups' candidates live in,
	// for the netlink filter. Written by the sweep goroutine.
	locators atomic.Pointer[[]netip.Prefix]

	mu sync.Mutex
	// active and ineligible are each class's last applied counts, for
	// logging a change once rather than every sweep.
	active     map[string]int
	ineligible map[string]string
}

// egressShardLister reads the cluster's EgressShards. synced is false until
// the first full list has arrived; an unsynced lister's empty answer is not
// "no shards".
type egressShardLister interface {
	ListEgressShards(ctx context.Context) (shards []bgpv1alpha1.EgressShard, synced bool, err error)
}

// newEgressGroup builds the sweep for cfg. staticSIDs is the conflist's shard
// list, which ordered mode places VRFs on, and which hashed mode still
// recognizes so a VRF written in ordered mode moves onto a group. nat64 is the
// conflist's NAT64 prefix list, which decides the classes.
func newEgressGroup(
	cfg config.EgressGroupConfig, staticSIDs []net.IP, nat64 []netip.Prefix, pinDir string,
) *egressGroup {
	classes := make([]egressroutemap.TranslationClass, 0, 1+len(nat64))
	classes = append(classes, egressroutemap.NAT66Class)
	for _, p := range nat64 {
		classes = append(classes, egressroutemap.NAT64Class(p))
	}
	return &egressGroup{
		cfg: cfg, staticSIDs: staticSIDs, pinDir: pinDir, classes: classes, trigger: make(chan struct{}, 1),
		active: map[string]int{}, ineligible: map[string]string{},
	}
}

// checkEgressClasses refuses a hashed-mode configuration with more NAT64
// prefixes than there are shard groups for.
func checkEgressClasses(cfg config.EgressGroupConfig, nat64 []netip.Prefix) error {
	if cfg.Mode == config.EgressModeHashed && len(nat64) > egressroutemap.MaxNAT64Groups {
		return fmt.Errorf("hashed egress mode serves at most %d NAT64 prefixes, and %s lists %d",
			egressroutemap.MaxNAT64Groups, config.EnvCNINAT64Prefix, len(nat64))
	}
	return nil
}

// kick asks for a sweep without blocking.
func (g *egressGroup) kick() {
	select {
	case g.trigger <- struct{}{}:
	default:
	}
}

// run sweeps on every kick until ctx ends.
func (g *egressGroup) run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-g.trigger:
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(egressGroupDebounce):
		}
		g.sweep(ctx)
	}
}

// policy is the group policy cfg asks for, for class.
func (g *egressGroup) policy(class egressroutemap.TranslationClass, ineligible int) egressroutemap.GroupPolicy {
	policy := egressroutemap.GroupPolicy{Class: class, PinIdle: g.cfg.PinIdle, Ineligible: ineligible}
	if g.cfg.Hash == config.EgressHashFlow {
		policy.Hash = egressroutemap.HashFlow
	}
	return policy
}

// sweep runs one pass. A missing pinned map means the datapath is not loaded
// on this node, and there is nothing to do.
//
// The ingress sidecar shares these maps from inside a pod network namespace,
// so the sweep first reads back which VRF routing tables that writer owns and
// leaves them alone. Failing to read that set skips the whole sweep: a sweep
// that cannot tell the two writers apart rewrites the sidecar's entries to
// host interfaces the pod does not have, and a stale next hop is recoverable
// where that is not.
func (g *egressGroup) sweep(ctx context.Context) {
	table, closer, err := egressroutemap.OpenPinnedEgressRouteTable(g.pinDir)
	if err != nil {
		return
	}
	defer func() { _ = closer.Close() }()

	registry, registryCloser, err := usidmap.OpenPinnedRegistry(g.pinDir)
	if err != nil {
		return
	}
	defer func() { _ = registryCloser.Close() }()

	foreignTableIDs, err := egressroutemap.SidecarOwnedTableIDs(registry.VRF)
	if err != nil {
		slog.Error("egress_route_table refresh sweep skipped: could not resolve entry ownership", "err", err)
		return
	}

	groups, groupsCloser, err := egressroutemap.OpenPinnedShardGroupTable(g.pinDir)
	if err != nil {
		// A datapath older than the shard group map: ordered mode is all it
		// can run.
		if !errors.Is(err, os.ErrNotExist) {
			slog.Error("egress shard groups unavailable; running the egress route sweep in ordered mode", "err", err)
		}
		groups = nil
	} else {
		defer func() { _ = groupsCloser.Close() }()
	}

	if err := g.sweepWith(ctx, table, groups, foreignTableIDs); err == nil {
		g.ctl.SweepSucceeded(time.Now())
	}
}

// sweepWith is one sweep against already-open maps. groups is nil on a
// datapath without the shard group map. It returns the first error, after
// counting it.
func (g *egressGroup) sweepWith(
	ctx context.Context, table *egressroutemap.EgressRouteTable, groups *egressroutemap.ShardGroupTable,
	foreignTableIDs map[uint32]struct{},
) error {
	if groups == nil {
		_, err := g.refresh(table, foreignTableIDs, g.staticSIDs)
		return err
	}
	if g.cfg.Mode == config.EgressModeHashed {
		return g.sweepHashed(ctx, table, groups, foreignTableIDs)
	}
	return g.sweepOrdered(table, groups, foreignTableIDs)
}

// sweepOrdered moves every route off the shard groups and retires them.
//
// The groups are marked closing before the scan that moves routes off them,
// and disabled only if that scan read the whole table and wrote every move,
// and found no route still naming a group. A CNI ADD that read the groups
// before they closed checks again after writing its routes and rewrites them
// in ordered mode if they closed meanwhile, so no route naming a group is
// written after a scan that started after they closed. A scan that fails, or
// leaves a route it could not move, leaves the groups forwarding, and the
// next sweep tries again.
func (g *egressGroup) sweepOrdered(
	table *egressroutemap.EgressRouteTable, groups *egressroutemap.ShardGroupTable,
	foreignTableIDs map[uint32]struct{},
) error {
	var enabled []uint32
	closed := true
	for id := range uint32(egressroutemap.MaxShardGroups) {
		status, err := groups.Status(id)
		if err != nil {
			g.ctl.SweepError("close")
			return fmt.Errorf("read egress shard group %d: %w", id, err)
		}
		if !status.Enabled {
			continue
		}
		enabled = append(enabled, id)
		if ok, err := groups.Close(id); err != nil || !ok {
			g.ctl.SweepError("close")
			slog.Error("Failed to mark an egress shard group closing; it stays enabled", "group", id, "err", err)
			closed = false
		}
	}

	result, err := g.refresh(table, foreignTableIDs, g.staticSIDs)
	if err != nil {
		return err
	}
	if len(enabled) == 0 {
		return nil
	}
	if !closed || result.SentinelRoutes() > 0 {
		slog.Info("Egress shard groups stay enabled while routes still name them",
			"routes", result.SentinelRoutes(), "allClosed", closed)
		return nil
	}
	for _, id := range enabled {
		if changed, err := groups.Disable(id); err != nil {
			g.ctl.SweepError("disable")
			return fmt.Errorf("disable egress shard group %d: %w", id, err)
		} else if changed {
			slog.Info("Egress shard group disabled: ordered egress mode, no route names it", "group", id)
		}
	}
	return nil
}

// sweepHashed applies the cluster's shards to each class's group and moves
// every VRF route onto its class's group. Until the watch has listed the
// cluster once, each group keeps whatever it last held: an empty answer then
// means "not known yet", and applying it would drop the cluster's egress.
func (g *egressGroup) sweepHashed(
	ctx context.Context, table *egressroutemap.EgressRouteTable, groups *egressroutemap.ShardGroupTable,
	foreignTableIDs map[uint32]struct{},
) error {
	recognized := append([]net.IP(nil), g.staticSIDs...)
	var firstErr error
	if g.shards == nil {
		g.ctl.SetWatchSynced(false)
	} else {
		shards, synced, err := g.shards.ListEgressShards(ctx)
		g.ctl.SetWatchSynced(synced && err == nil)
		switch {
		case err != nil:
			g.ctl.SweepError("watch")
			slog.Error("Failed to list EgressShards; the egress shard groups keep their members", "err", err)
			firstErr = err
		case synced:
			sids, err := g.applyClasses(groups, shards)
			recognized = append(recognized, sids...)
			if err != nil {
				firstErr = err
			}
		}
	}

	// Each route goes to its class's group only while that group is open and
	// has a candidate. Until then a route keeps the shard ordered mode gave
	// it, rather than be moved onto a group with nothing to send it to.
	byClass := map[string]uint32{}
	for id := range uint32(egressroutemap.MaxShardGroups) {
		status, err := groups.Status(id)
		if err != nil {
			return errors.Join(firstErr, err)
		}
		if status.Open() && status.Candidates > 0 {
			byClass[status.Class.String()] = id
		}
	}
	groupFor := func(prefix *net.IPNet) (uint32, bool) {
		class, ok := egressroutemap.ClassForRoute(prefix)
		if !ok {
			return 0, false
		}
		id, ok := byClass[class.String()]
		return id, ok
	}
	var opts []egressroutemap.RefreshOption
	if len(byClass) > 0 {
		opts = append(opts, egressroutemap.WithShardGroups(groupFor))
	}
	if _, err := g.refresh(table, foreignTableIDs, recognized, opts...); err != nil {
		return errors.Join(firstErr, err)
	}
	return firstErr
}

// applyClasses publishes each class's group from the cluster's shards and
// returns every candidate's SID.
func (g *egressGroup) applyClasses(
	groups *egressroutemap.ShardGroupTable, shards []bgpv1alpha1.EgressShard,
) ([]net.IP, error) {
	var (
		sids     []net.IP
		locators []netip.Prefix
		errs     []error
	)
	for i, class := range g.classes {
		eligible, ineligible := egressShardCandidates(shards, class)
		g.reportIneligible(class, ineligible)
		result, err := groups.Apply(uint32(i), g.policy(class, len(ineligible)), eligible) //nolint:gosec // < 4
		if err != nil {
			g.ctl.SweepError("apply")
			slog.Error("Failed to publish an egress shard group", "class", class.String(), "err", err)
			errs = append(errs, err)
			continue
		}
		for _, s := range result.Shards {
			locators = append(locators, netip.PrefixFrom(s.SID, 64).Masked())
			if s.Assigned {
				g.resetCounter(uint32(i), s.Slot) //nolint:gosec // < 4
			}
		}
		for _, c := range eligible {
			sids = append(sids, c.SID)
		}
		g.logApplied(class, result)
	}
	g.locators.Store(&locators)
	return sids, errors.Join(errs...)
}

// reportIneligible logs the shards that cannot serve class, once per change.
func (g *egressGroup) reportIneligible(class egressroutemap.TranslationClass, ineligible []string) {
	key := fmt.Sprint(ineligible)
	g.mu.Lock()
	previous, seen := g.ineligible[class.String()]
	g.ineligible[class.String()] = key
	g.mu.Unlock()
	if seen && previous == key {
		return
	}
	if len(ineligible) > 0 {
		slog.Warn("EgressShards that cannot translate this class are kept out of its group",
			"class", class.String(), "shards", ineligible)
	}
}

// logApplied logs a group's membership when it changed.
func (g *egressGroup) logApplied(class egressroutemap.TranslationClass, result egressroutemap.GroupResult) {
	g.mu.Lock()
	previous, seen := g.active[class.String()]
	g.active[class.String()] = result.Active()
	g.mu.Unlock()
	if !result.Changed && seen && previous == result.Active() {
		return
	}
	for _, s := range result.Shards {
		if s.Err != nil {
			slog.Warn("Egress shard unreachable; it takes no tenant until its SID resolves",
				"class", class.String(), "sid", s.SID, "slot", s.Slot, "err", s.Err)
		}
	}
	slog.Info("Egress shard group updated", "class", class.String(),
		"generation", result.Generation, "candidates", len(result.Shards), "active", result.Active(),
		"hash", g.cfg.Hash, "pinIdle", g.cfg.PinIdle)
}

// resetCounter zeroes a slot's per-CPU packet and byte counters, so a shard
// that takes a slot does not inherit its previous occupant's share.
func (g *egressGroup) resetCounter(group uint32, slot int) {
	if g.counters == nil {
		return
	}
	cpus, err := ebpf.PossibleCPU()
	if err != nil {
		slog.Warn("Could not reset an egress shard slot's counters", "slot", slot, "err", err)
		return
	}
	key := group*egressroutemap.MaxShardsPerGroup + uint32(slot) //nolint:gosec // < 32
	if err := g.counters.Put(key, make([]prog.UsidEgressShardCounter, cpus)); err != nil {
		slog.Warn("Could not reset an egress shard slot's counters", "slot", slot, "err", err)
	}
}

// refresh runs one Refresh pass, logs anything it did, and records how many
// routes still name each class's group. Refresh's error is returned, never
// swallowed: a caller deciding whether a group can be retired must know the
// scan was complete.
func (g *egressGroup) refresh(
	table *egressroutemap.EgressRouteTable, foreignTableIDs map[uint32]struct{}, shardSIDs []net.IP,
	opts ...egressroutemap.RefreshOption,
) (egressroutemap.RefreshResult, error) {
	result, err := table.Refresh(foreignTableIDs, shardSIDs, opts...)
	if err != nil {
		g.ctl.SweepError("refresh")
		slog.Error("egress_route_table refresh sweep failed", "err", err,
			"scanned", result.Scanned, "refreshed", result.Refreshed)
		return result, err
	}
	if result.Refreshed > 0 || result.Unresolved > 0 {
		slog.Info("egress_route_table refresh sweep complete",
			"scanned", result.Scanned, "refreshed", result.Refreshed, "reselected", result.Reselected,
			"grouped", result.Grouped, "ungrouped", result.Ungrouped, "inGroup", result.InGroup,
			"unresolved", result.Unresolved, "skipped", result.Skipped)
	}
	byClass := map[string]int{}
	for i, class := range g.classes {
		byClass[class.String()] = result.GroupRoutes[uint32(i)] //nolint:gosec // < 4
	}
	g.ctl.SetGroupRoutes(byClass)
	return result, nil
}

// egressShardCandidates returns the cluster's EgressShards that can serve
// class as group candidates, and the names of those that are candidates in
// every other respect but cannot translate class.
//
// A shard is a candidate once its datapath reports the SID it translates with,
// in status, and both Programmed and Ready are true: the same evidence the
// shard's own advertisement is built from. Status rather than spec, since only
// status says what the shard's datapath claims. A status gone stale on a dead
// node is caught by liveness instead: its route is withdrawn with its BGP
// session, and a candidate whose SID does not resolve takes no tenant.
//
// It can serve NAT66 when its status carries an IPv6 masquerade address, and
// NAT64 toward a prefix when it carries an IPv4 one and translates that
// prefix: its own nat64Prefix, or the Well-Known Prefix when it says it
// translates that too.
//
// One with spec.drain set is draining. One being deleted is no candidate at
// all: deletion withdraws its advertisement and clears its translation at
// once, so it has nothing to drain with.
func egressShardCandidates(
	shards []bgpv1alpha1.EgressShard, class egressroutemap.TranslationClass,
) (eligible []egressroutemap.ShardCandidate, ineligible []string) {
	for i := range shards {
		shard := &shards[i]
		if !shard.DeletionTimestamp.IsZero() || shard.Status.ShardSID == "" ||
			!meta.IsStatusConditionTrue(shard.Status.Conditions, bgpv1alpha1.ConditionTypeProgrammed) ||
			!meta.IsStatusConditionTrue(shard.Status.Conditions, bgpv1alpha1.ConditionTypeReady) {
			continue
		}
		sid := net.ParseIP(shard.Status.ShardSID)
		if sid == nil {
			slog.Warn("Ignoring EgressShard with an unparseable status.shardSID",
				"egressShard", shard.Namespace+"/"+shard.Name, "shardSID", shard.Status.ShardSID)
			continue
		}
		if !translates(shard.Status, class) {
			ineligible = append(ineligible, shard.Name)
			continue
		}
		eligible = append(eligible, egressroutemap.ShardCandidate{SID: sid, Draining: shard.Spec.Drain})
	}
	return eligible, ineligible
}

// translates reports whether a shard with status can translate class.
func translates(status bgpv1alpha1.EgressShardStatus, class egressroutemap.TranslationClass) bool {
	if !class.NAT64 {
		return status.ShardAddressIPv6 != ""
	}
	if status.ShardAddressIPv4 == "" {
		return false
	}
	if p, err := netip.ParsePrefix(status.NAT64Prefix); err == nil && p.Masked() == class.Prefix {
		return true
	}
	return class.Prefix == egressroutemap.WellKnownPrefix && status.TranslatesWellKnownPrefix
}

// newRestConfigFn is an override point so tests can avoid an in-cluster
// config.
var newRestConfigFn = rest.InClusterConfig

// startEgressShardWatchFn starts the EgressShard watch hashed mode reads its
// members from, calling onChange on every add, update and delete. A variable
// so tests can substitute a fake lister.
var startEgressShardWatchFn = startEgressShardWatch

// cacheShardLister lists EgressShards from a controller-runtime cache.
type cacheShardLister struct {
	reader    client.Reader
	namespace string
	synced    atomic.Bool
}

func (l *cacheShardLister) ListEgressShards(ctx context.Context) ([]bgpv1alpha1.EgressShard, bool, error) {
	if !l.synced.Load() {
		return nil, false, nil
	}
	var list bgpv1alpha1.EgressShardList
	if err := l.reader.List(ctx, &list, client.InNamespace(l.namespace)); err != nil {
		return nil, true, fmt.Errorf("list EgressShards in %s: %w", l.namespace, err)
	}
	return list.Items, true, nil
}

// startEgressShardWatch starts an informer on namespace's EgressShards for the
// life of ctx. It returns once the informer is registered, not once it has
// synced; the lister reports synced from then on.
func startEgressShardWatch(ctx context.Context, namespace string, onChange func()) (egressShardLister, error) {
	restConfig, err := newRestConfigFn()
	if err != nil {
		return nil, fmt.Errorf("load in-cluster config: %w", err)
	}
	c, err := cache.New(restConfig, cache.Options{
		Scheme:            scheme,
		DefaultNamespaces: map[string]cache.Config{namespace: {}},
	})
	if err != nil {
		return nil, fmt.Errorf("create EgressShard cache: %w", err)
	}
	informer, err := c.GetInformer(ctx, &bgpv1alpha1.EgressShard{}, cache.BlockUntilSynced(false))
	if err != nil {
		return nil, fmt.Errorf("get EgressShard informer: %w", err)
	}
	if _, err := informer.AddEventHandler(toolscache.ResourceEventHandlerFuncs{
		AddFunc:    func(any) { onChange() },
		UpdateFunc: func(any, any) { onChange() },
		DeleteFunc: func(any) { onChange() },
	}); err != nil {
		return nil, fmt.Errorf("watch EgressShards: %w", err)
	}

	lister := &cacheShardLister{reader: c, namespace: namespace}
	go func() {
		if err := c.Start(ctx); err != nil {
			slog.Error("EgressShard watch stopped", "err", err)
		}
	}()
	go func() {
		if c.WaitForCacheSync(ctx) {
			lister.synced.Store(true)
			onChange()
		}
	}()
	return lister, nil
}

// watchShardReachability kicks g whenever a route or neighbor changes in a way
// that can move a group member's reachability: a route into one of the
// members' /64 locators, the default route, or any IPv6 neighbor on an SRv6
// uplink. Subscription errors are logged and the subscription retried, since
// the egress route ticker still covers the gap.
func (g *egressGroup) watchShardReachability(ctx context.Context) {
	for ctx.Err() == nil {
		if err := g.subscribeReachability(ctx); err != nil {
			slog.Warn("Egress shard reachability watch failed; retrying", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}
	}
}

// subscribeReachability runs one route and neighbor subscription until ctx
// ends or either closes.
func (g *egressGroup) subscribeReachability(ctx context.Context) error {
	done := make(chan struct{})
	defer close(done)

	routes := make(chan netlink.RouteUpdate, 64)
	if err := netlink.RouteSubscribe(routes, done); err != nil {
		return fmt.Errorf("subscribe to route updates: %w", err)
	}
	neighs := make(chan netlink.NeighUpdate, 64)
	if err := netlink.NeighSubscribe(neighs, done); err != nil {
		return fmt.Errorf("subscribe to neighbor updates: %w", err)
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case update, ok := <-routes:
			if !ok {
				return errors.New("route subscription closed")
			}
			if g.routeAffectsShards(update.Dst) {
				g.kick()
			}
		case update, ok := <-neighs:
			if !ok {
				return errors.New("neighbor subscription closed")
			}
			if update.Family == netlink.FAMILY_V6 && isUplink(update.LinkIndex) {
				g.kick()
			}
		}
	}
}

// routeAffectsShards reports whether a route to dst can change how a group
// member resolves: the default route, or any prefix overlapping a member's
// locator.
func (g *egressGroup) routeAffectsShards(dst *net.IPNet) bool {
	if dst == nil {
		return true
	}
	addr, ok := netip.AddrFromSlice(dst.IP)
	if !ok {
		return false
	}
	ones, _ := dst.Mask.Size()
	prefix := netip.PrefixFrom(addr.Unmap(), ones)
	if prefix.Bits() == 0 {
		return true
	}
	locators := g.locators.Load()
	if locators == nil {
		return false
	}
	for _, l := range *locators {
		if l.Overlaps(prefix) {
			return true
		}
	}
	return false
}

// isUplink reports whether ifindex is an interface the SRv6 datapath is
// attached to. A lookup failure answers true, so a neighbor change is never
// missed for want of the uplink set.
func isUplink(ifindex int) bool {
	uplinks, err := attach.UplinkIndexes()
	if err != nil {
		return true
	}
	_, ok := uplinks[ifindex]
	return ok
}
