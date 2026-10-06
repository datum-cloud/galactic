// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/safchain/ethtool"

	"go.datum.net/galactic/internal/config"
	"go.datum.net/galactic/internal/controller"
	"go.datum.net/galactic/internal/plumbing/ebpf/natattach"
	"go.datum.net/galactic/internal/plumbing/ebpf/natmap"
	"go.datum.net/galactic/internal/plumbing/ebpf/natprog"
	"go.datum.net/galactic/internal/plumbing/ebpf/xdpattach"
	"go.datum.net/galactic/internal/plumbing/ebpf/xdpdispatch"
	"go.datum.net/galactic/internal/plumbing/nicstats"
	"go.datum.net/galactic/internal/plumbing/sysctl"
)

// natDatapathKeepAlive holds the loaded objects and the attached link for the
// life of this process, once the attach path succeeds.
//
// Nothing here is closed explicitly, but a value not stored somewhere reachable
// is as good as closed: the eBPF program, map, and link types all register a
// finalizer that closes the underlying descriptor once the garbage collector
// sees nothing pointing at them, with no error surfaced anywhere.
//
// Without this var, the programs and the link, the two things keeping this
// shard's XDP attachment live on the wire, would eventually be collected and
// silently detached while the shard's Ready condition still reported healthy.
var natDatapathKeepAlive struct {
	objs     *natprog.NatObjects
	set      *xdpattach.Set
	dispatch *xdpdispatch.Dispatcher
}

// natDatapath is this node's attached egress translation datapath, as
// controller.EgressShardReconciler drives it (controller.EgressDatapath).
//
// Attachment starts at startup and needs no identity: until Program writes
// one, shard_config_table holds a row serving no family and the datapath claims
// no packet. watchUplinks keeps it current from then on, so uplinks and missing
// change under the reconciler's feet, hence the mutex.
type natDatapath struct {
	shardConfig *natmap.ShardConfigTable
	// echoResponder is process configuration written alongside every identity
	// Program writes, not part of the identity itself.
	echoResponder bool

	mu       sync.Mutex
	attached bool
	// uplinks is the most recently resolved uplink set, and configured the
	// ones whose forwarding sysctls have been applied.
	uplinks    []string
	configured map[string]bool
	// missing is the resolved uplinks the datapath does not cover.
	missing []string
	// nat64 is whether the programmed identity serves NAT64, which an uplink
	// found later needs IPv4 forwarding for, as Program gives the rest.
	nat64 bool
}

// Attached reports whether startup completed its load and attach pass. It is
// set once and never cleared; MissingUplinks is what reports a gap since.
func (d *natDatapath) Attached() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.attached
}

// MissingUplinks reports the resolved uplinks the datapath does not cover: not
// attached in direct mode, not reaching this shard's dispatcher slot in
// dispatch mode, not hooked by the edge gateway in chain mode.
func (d *natDatapath) MissingUplinks() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.missing)
}

// Uplinks reports the most recently resolved uplink set.
func (d *natDatapath) Uplinks() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.uplinks)
}

// setMissing records missing, reporting whether it changed.
func (d *natDatapath) setMissing(missing []string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if slices.Equal(d.missing, missing) {
		return false
	}
	d.missing = slices.Clone(missing)
	return true
}

// adoptUplinks records uplinks as the current set and applies the forwarding
// sysctls to every one not configured yet. It returns the uplinks safe to run
// the datapath on: one whose sysctls failed is left out, and retried on the
// next call, since the datapath's FIB lookup would refuse every packet on it.
func (d *natDatapath) adoptUplinks(uplinks []string) []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.uplinks = slices.Clone(uplinks)

	ready := make([]string, 0, len(uplinks))
	for _, iface := range uplinks {
		if !d.configured[iface] {
			if err := configureUplinkSysctls(iface, d.nat64); err != nil {
				slog.Error("Cannot configure forwarding on uplink; leaving it uncovered", "interface", iface, "err", err)
				continue
			}
			d.configured[iface] = true
		}
		ready = append(ready, iface)
	}
	return ready
}

// configureUplinkSysctls applies the forwarding sysctls the datapath's FIB
// lookup needs on iface: always IPv6, and IPv4 too once NAT64 is served.
func configureUplinkSysctls(iface string, nat64 bool) error {
	if err := sysctl.ConfigureFIBLookupUplinkSysctls(iface); err != nil {
		return fmt.Errorf("configure IPv6 forwarding on uplink interface %q: %w", iface, err)
	}
	if nat64 {
		if err := sysctl.ConfigureFIBLookupUplinkSysctlsIPv4(iface); err != nil {
			return fmt.Errorf("configure IPv4 forwarding on uplink interface %q: %w", iface, err)
		}
	}
	return nil
}

// Program writes identity into shard_config_table. A blind overwrite: see
// natmap.ShardConfigTable.Set.
func (d *natDatapath) Program(identity controller.EgressShardIdentity) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	// The IPv4 counterpart of the forwarding sysctls startup sets, needed for
	// the same reason on the one leg that leaves this datapath as IPv4: a
	// NAT64 forward packet resolves its next hop with an IPv4 FIB lookup,
	// which a kernel with IPv4 forwarding off refuses. The datapath counts
	// that refusal, but a shard whose every IPv4 flow dies at the last
	// instruction is a shard that does not work. Set only once a shard
	// actually serves NAT64, so a node that never does keeps IPv4
	// forwarding as it was.
	if identity.ShardAddressIPv4.IsValid() {
		for _, iface := range d.uplinks {
			if err := sysctl.ConfigureFIBLookupUplinkSysctlsIPv4(iface); err != nil {
				return fmt.Errorf("configure IPv4 forwarding on uplink interface %q: %w", iface, err)
			}
		}
		d.nat64 = true
	}

	cfg := natmap.ShardConfig{
		ShardSID:      identity.ShardSID,
		ShardPubAddr6: identity.ShardAddressIPv6,
		ShardPubAddr4: identity.ShardAddressIPv4,
		NAT64Prefix:   identity.NAT64Prefix,
		EchoResponder: d.echoResponder,

		TranslateWellKnownPrefix: identity.TranslateWellKnownPrefix,
	}
	if current, ok, err := d.shardConfig.Get(); err == nil && ok && current == cfg {
		return nil
	}
	if err := d.shardConfig.Set(cfg); err != nil {
		return err
	}
	slog.Info("Egress translation datapath programmed",
		"shardSID", identity.ShardSID,
		"nat66", identity.ShardAddressIPv6.IsValid(),
		"nat64", identity.ShardAddressIPv4.IsValid(),
		"wellKnownPrefix", identity.TranslateWellKnownPrefix,
		"echoResponder", d.echoResponder,
	)
	return nil
}

// Clear removes the programmed identity, so the datapath claims no packet.
func (d *natDatapath) Clear() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if _, ok, err := d.shardConfig.Get(); err == nil && !ok {
		return nil
	}
	if err := d.shardConfig.Clear(); err != nil {
		return err
	}
	slog.Info("Egress translation datapath cleared; claiming no packets")
	return nil
}

// Programmed reads back the identity shard_config_table holds. A read failure
// reports no identity, which publishes as an empty status rather than as one
// the datapath might not be translating with.
func (d *natDatapath) Programmed() (controller.EgressShardIdentity, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()

	cfg, ok, err := d.shardConfig.Get()
	if err != nil || !ok {
		return controller.EgressShardIdentity{}, false
	}
	return controller.EgressShardIdentity{
		ShardSID:         cfg.ShardSID,
		ShardAddressIPv6: cfg.ShardPubAddr6,
		ShardAddressIPv4: cfg.ShardPubAddr4,
		NAT64Prefix:      cfg.NAT64Prefix,

		TranslateWellKnownPrefix: cfg.TranslateWellKnownPrefix,
	}, true
}

// setupNatDatapath loads and attaches the egress translation datapath to every
// one of this node's uplinks and registers this shard's metrics. It returns
// the datapath the reconciler programs from the node's EgressShard.
//
// Uplinks come from natattach.ResolveUplinks: the override when one is
// configured, otherwise the same auto-detection the CNI's SRv6 datapath uses.
// Every one is attached, not only the one this node's traffic uses today: a
// packet arriving on an uplink with no program reaches no translation at all
// and leaves untranslated and uncounted, so a multi-homed shard node that
// attached to one uplink would lose the shard role the moment routing moved.
// The startup attach is all-or-nothing -- natattach.Attach unwinds its own
// partial work -- so a shard that cannot claim every uplink it starts with
// fails to start rather than running with a hole in its coverage.
//
// Startup is only the first pass. Auto-detection reads routes, so a shard that
// starts before BGP converges resolves some of its uplinks or none. With none
// it waits for the first (waitForUplinks); with some, watchUplinks attaches
// the rest as routing reveals them. onCoverage is called whenever the set of
// uplinks the datapath misses changes, which MissingUplinks then reports.
//
// In dispatch mode (config.NATXDPAttachDispatch) the program is not attached
// either. It fills this shard's slot in the node's shared XDP dispatcher, whose
// pinned root holds every uplink, and the slot's lease is renewed for the life
// of the process. The root and the slot outlive the process, so a restart
// never detaches anything; the next process swaps its program into the slot.
// Nothing here is all-or-nothing: an uplink the dispatcher cannot hold yet is
// reported missing and retried.
//
// In direct mode, an idle dispatcher on the resolved uplinks is released
// first (releaseIdleDispatcher).
//
// The loaded objects and the attachment set are stashed in
// natDatapathKeepAlive rather than closed here: they, and the attachment
// itself, must survive for the life of this process.
func setupNatDatapath(ctx context.Context, cfg *config.NATConfig,
	metricsReg prometheus.Registerer, onCoverage func()) (*natDatapath, error) {
	uplinks, err := waitForUplinks(ctx, cfg.UplinkInterfaces)
	if err != nil {
		return nil, err
	}

	// Required for the FIB lookup in both the forward and return paths to
	// succeed on the interface the program actually runs on. The lookup uses
	// the ingress interface, meaning whichever uplink the packet arrived on, so
	// this must be applied to every one of them rather than to a primary:
	// once an uplink is a bond, its slaves rather than the master are what the
	// kernel reports as ingress, and uplinks already holds the slaves.
	d := &natDatapath{configured: map[string]bool{}, echoResponder: cfg.EchoResponder}
	for _, iface := range uplinks {
		if err := configureUplinkSysctls(iface, false); err != nil {
			return nil, err
		}
		d.configured[iface] = true
	}
	d.uplinks = uplinks

	objs, err := natattach.Load(natattach.PinDir)
	if err != nil {
		return nil, fmt.Errorf("load egress translation eBPF datapath: %w", err)
	}

	// Before the attach, not after: the dispatcher tail-calls into these, and a
	// packet arriving at an empty slot passes through untranslated.
	if err := natattach.PopulateProgArray(objs); err != nil {
		_ = objs.Close()
		return nil, fmt.Errorf("populate egress translation tail-call array: %w", err)
	}

	// shard_config_table is deliberately not written here. Its pinned row is
	// whatever this node's previous process programmed, so a restart keeps
	// translating established flows until the first reconcile re-derives it
	// from the EgressShard spec -- or clears it, if that shard is gone.
	d.shardConfig = natmap.NewShardConfigTable(natmap.KernelTable{Map: objs.ShardConfigTable})

	var (
		set         *xdpattach.Set
		dispatchSet *xdpattach.DispatchSet
		dispatcher  *xdpdispatch.Dispatcher
		xdpLinks    []link.Link
	)
	switch cfg.XDPAttach {
	case config.NATXDPAttachDispatch:
		// The lease runs for the life of the process, so its done channel
		// is not needed here.
		if dispatcher, dispatchSet, _, err = joinDispatcher(ctx, xdpdispatch.PinDir, objs.NatIngress); err != nil {
			_ = objs.Close()
			return nil, err
		}
		d.missing = dispatchSet.Reconcile(ctx, uplinks)
	default:
		if err := releaseIdleDispatcher(ctx, xdpdispatch.PinDir, uplinks); err != nil {
			_ = objs.Close()
			return nil, err
		}
		xdpLinks, err = natattach.Attach(objs.NatIngress, uplinks)
		if err != nil {
			_ = objs.Close()
			return nil, fmt.Errorf("attach egress translation datapath to uplink interfaces %v: %w", uplinks, err)
		}
		if set, err = xdpattach.NewSet(objs.NatIngress, uplinks, xdpLinks); err != nil {
			closeAll(xdpLinks)
			_ = objs.Close()
			return nil, err
		}
	}

	collector := newNatCollector(objs)
	if err := metricsReg.Register(collector); err != nil {
		closeAll(xdpLinks)
		_ = objs.Close()
		return nil, fmt.Errorf("register egress shard metrics collector: %w", err)
	}

	registerUplinkQueueStats(metricsReg, d)

	natDatapathKeepAlive.objs = objs
	natDatapathKeepAlive.set = set
	natDatapathKeepAlive.dispatch = dispatcher

	slog.Info("Egress translation datapath attached",
		"interfaces", uplinks,
		"autoDetected", len(cfg.UplinkInterfaces) == 0,
		"xdpAttach", cfg.XDPAttach,
	)

	d.attached = true
	go d.watchUplinks(ctx, cfg.UplinkInterfaces, coverageFor(ctx, set, dispatchSet), onCoverage)
	return d, nil
}

// registerUplinkQueueStats exports the per-queue receive counters of every
// uplink d currently resolves. A single stalled NIC receive queue drops packets
// before the datapath sees them, so drops_total stays flat through it (#673);
// these counters are what show it. Failing to set them up costs only those
// counters, so it is logged rather than failing the shard.
func registerUplinkQueueStats(metricsReg prometheus.Registerer, d *natDatapath) {
	et, err := ethtool.NewEthtool()
	if err != nil {
		slog.Warn("Cannot open ethtool; uplink receive queue metrics are disabled", "err", err)
		return
	}
	if err := metricsReg.Register(nicstats.NewCollector(metricsNamespace, et, d.Uplinks)); err != nil {
		et.Close()
		slog.Warn("Cannot register uplink receive queue metrics", "err", err)
	}
}

// joinDispatcher opens the node's XDP dispatcher, fills this shard's slot with
// program, and starts renewing the slot's lease for the life of ctx. It
// returns the set that keeps the dispatcher on the uplinks, and a channel
// closed once the lease loop has stopped, which a caller waits on before
// closing the dispatcher.
func joinDispatcher(ctx context.Context, pinDir string, program *ebpf.Program) (
	*xdpdispatch.Dispatcher, *xdpattach.DispatchSet, <-chan struct{}, error,
) {
	dispatcher, err := xdpdispatch.Open(ctx, pinDir)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("open the node's XDP dispatcher: %w", err)
	}
	lock, err := dispatcher.Lock(ctx)
	if err != nil {
		_ = dispatcher.Close()
		return nil, nil, nil, err
	}
	err = lock.Fill(xdpdispatch.SlotNAT, program)
	lock.Unlock()
	if err != nil {
		_ = dispatcher.Close()
		return nil, nil, nil, fmt.Errorf("install egress translation datapath in the XDP dispatcher: %w", err)
	}
	set, err := xdpattach.NewDispatchSet(dispatcher, xdpdispatch.SlotNAT, xdpdispatch.RoleEgress, program)
	if err != nil {
		_ = dispatcher.Close()
		return nil, nil, nil, err
	}

	// A lapsed lease shows as missing uplinks within one coverage resync,
	// since every Reconcile reads the lease back.
	leaseDone := make(chan struct{})
	go func() {
		defer close(leaseDone)
		dispatcher.Lease(ctx, xdpdispatch.SlotNAT, func(err error) {
			slog.Error("Cannot renew the egress translation slot's lease in the XDP dispatcher; "+
				"the dispatcher skips the slot once it lapses", "err", err)
		})
	}()
	slog.Info("Egress translation datapath installed in the XDP dispatcher", "pinDir", pinDir)
	return dispatcher, set, leaseDone, nil
}

// releaseIdleDispatcher detaches an idle XDP dispatcher from uplinks before a
// direct attach (xdpattach.ReleaseIdleDispatcher), refusing while another
// datapath's slot is live there.
func releaseIdleDispatcher(ctx context.Context, pinDir string, uplinks []string) error {
	if err := xdpattach.ReleaseIdleDispatcher(ctx, pinDir, uplinks, xdpdispatch.SlotNAT); err != nil {
		return fmt.Errorf("%w; set %s=%s", err, config.EnvNATXDPAttach, config.NATXDPAttachDispatch)
	}
	return nil
}

// coverageFor returns how watchUplinks brings the ready uplinks under the
// datapath and reads back which it covers: through set in direct mode, and
// dispatchSet in dispatch mode.
func coverageFor(ctx context.Context, set *xdpattach.Set, dispatchSet *xdpattach.DispatchSet) func([]string) []string {
	if set != nil {
		return func(ready []string) []string {
			set.Reconcile(ready)
			return set.Attached()
		}
	}
	return func(ready []string) []string {
		return uncovered(ready, dispatchSet.Reconcile(ctx, ready))
	}
}

// uplinkRetryInterval is how often waitForUplinks resolves again while none
// resolve.
const uplinkRetryInterval = 2 * time.Second

// waitForUplinks resolves this node's uplinks, waiting while auto-detection
// finds none: a shard that starts before its node has learned any fabric
// route is ordinary, and the startup probe bounds the wait. Any other failure,
// and every failure of an override, is returned at once: retrying cannot fix a
// configuration error.
func waitForUplinks(ctx context.Context, override []string) ([]string, error) {
	logged := false
	for {
		uplinks, err := natattach.ResolveUplinks(override)
		if err == nil {
			return uplinks, nil
		}
		if len(override) != 0 || !errors.Is(err, natattach.ErrNoUplinks) {
			return nil, fmt.Errorf("resolve uplink interfaces: %w", err)
		}
		if !logged {
			slog.Info("Waiting for a fabric route to auto-detect an uplink from")
			logged = true
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("waiting for an uplink to auto-detect: %w", ctx.Err())
		case <-time.After(uplinkRetryInterval):
		}
	}
}

// watchUplinks keeps the datapath on every uplink ResolveUplinks returns, for
// the life of ctx, re-resolving on every netlink link or route change. cover
// brings the ready uplinks under the datapath and returns the ones it covers
// (coverageFor). onCoverage is called whenever the missing uplinks change.
func (d *natDatapath) watchUplinks(ctx context.Context, override []string, cover func([]string) []string,
	onCoverage func(),
) {
	xdpattach.OnNetlinkChange(ctx, func() {
		uplinks, err := natattach.ResolveUplinks(override)
		if err != nil {
			slog.Warn("Re-resolve uplink interfaces failed; keeping current coverage", "err", err)
			return
		}
		ready := d.adoptUplinks(uplinks)

		missing := uncovered(uplinks, cover(ready))

		if !d.setMissing(missing) {
			return
		}
		switch {
		case len(missing) == 0:
			slog.Info("Egress translation datapath covers every uplink", "uplinks", uplinks)
		default:
			slog.Warn("Egress translation datapath does not cover every uplink; traffic arriving on these "+
				"leaves untranslated", "missing", missing)
		}
		if onCoverage != nil {
			onCoverage()
		}
	})
}

// uncovered returns every one of uplinks not in covered, in uplinks' order.
func uncovered(uplinks, covered []string) []string {
	var out []string
	for _, u := range uplinks {
		if !slices.Contains(covered, u) {
			out = append(out, u)
		}
	}
	return out
}

// closeAll best-effort closes every link, to unwind a partially set-up datapath
// when attaching succeeded but a later step failed.
func closeAll(links []link.Link) {
	for _, l := range links {
		_ = l.Close()
	}
}

// disabledDatapath is the datapath of a shard turned off by configuration
// (config.EnvNATDatapathEnabled). It holds nothing and translates nothing, and
// reports no missing uplinks, so the pod stays ready while the EgressShard
// reports the shard as disabled.
type disabledDatapath struct{}

func (disabledDatapath) Attached() bool           { return false }
func (disabledDatapath) MissingUplinks() []string { return nil }
func (disabledDatapath) Clear() error             { return nil }

func (disabledDatapath) Program(controller.EgressShardIdentity) error {
	return errors.New("the egress translation datapath is turned off")
}

func (disabledDatapath) Programmed() (controller.EgressShardIdentity, bool) {
	return controller.EgressShardIdentity{}, false
}

// turnOffDatapath turns this node's shard off; the shard then runs with
// disabledDatapath. A dispatch-mode
// predecessor left the shard's program in the XDP dispatcher with a live
// lease, so the slot is emptied here and the dispatcher passes the shard's
// traffic on at once rather than once the lease lapses. Every other slot, and
// the dispatcher itself, are left alone. A direct-mode predecessor's
// attachment ended with its process, so there is nothing to undo for it.
//
// A failure to empty the slot is logged, not returned: the shard is meant to
// be off, the lease lapses on its own within xdpdispatch.LeaseTTL, and a
// shard that crash-looped instead would keep its advertisement up no longer
// but would page for nothing.
func turnOffDatapath(ctx context.Context, pinDir string) {
	if err := xdpattach.ClearDispatcherSlots(ctx, pinDir, xdpdispatch.SlotNAT); err != nil {
		slog.Error("Cannot empty the egress translation slot in the XDP dispatcher; "+
			"it stops claiming packets once its lease lapses", "lease", xdpdispatch.LeaseTTL, "err", err)
	}
	slog.Info("Egress translation datapath is turned off; this shard attaches nothing and translates nothing",
		"env", config.EnvNATDatapathEnabled)
}
