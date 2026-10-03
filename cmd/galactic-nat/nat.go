// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/prometheus/client_golang/prometheus"

	"go.datum.net/galactic/internal/config"
	"go.datum.net/galactic/internal/controller"
	"go.datum.net/galactic/internal/plumbing/ebpf/natattach"
	"go.datum.net/galactic/internal/plumbing/ebpf/natmap"
	"go.datum.net/galactic/internal/plumbing/ebpf/natprog"
	"go.datum.net/galactic/internal/plumbing/ebpf/xdpattach"
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
	objs *natprog.NatObjects
	set  *xdpattach.Set
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
// attached in direct mode, not hooked by the edge gateway in chain mode.
func (d *natDatapath) MissingUplinks() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.missing)
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
// In chain mode (config.NATXDPAttachChain) nothing is attached: the program is
// installed in the edge gateway's xdp_chain slot instead, waiting for the
// gateway to create it, and kept there for the life of the process by
// keepChain. The uplinks are still resolved, for the forwarding sysctls and to
// report any the gateway does not hook as missing.
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
		set      *xdpattach.Set
		xdpLinks []link.Link
	)
	if cfg.XDPAttach == config.NATXDPAttachChain {
		if err := waitForChain(ctx, objs.NatIngress, natattach.EdgeChainMapPath); err != nil {
			_ = objs.Close()
			return nil, err
		}
		go keepChain(ctx, objs.NatIngress, natattach.EdgeChainMapPath)
	} else {
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

	natDatapathKeepAlive.objs = objs
	natDatapathKeepAlive.set = set

	slog.Info("Egress translation datapath attached",
		"interfaces", uplinks,
		"autoDetected", len(cfg.UplinkInterfaces) == 0,
		"xdpAttach", cfg.XDPAttach,
	)

	d.attached = true
	go d.watchUplinks(ctx, cfg.UplinkInterfaces, set, onCoverage)
	return d, nil
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
// the life of ctx, re-resolving on every netlink link or route change. In
// direct mode set holds the attachments and an uplink found later is attached
// to it; in chain mode set is nil and the gateway owns the hook, so an uplink
// it does not cover can only be reported. Either way, onCoverage is called
// whenever the missing uplinks change.
func (d *natDatapath) watchUplinks(ctx context.Context, override []string, set *xdpattach.Set, onCoverage func()) {
	xdpattach.OnNetlinkChange(ctx, func() {
		uplinks, err := natattach.ResolveUplinks(override)
		if err != nil {
			slog.Warn("Re-resolve uplink interfaces failed; keeping current coverage", "err", err)
			return
		}
		ready := d.adoptUplinks(uplinks)

		var covered []string
		if set != nil {
			set.Reconcile(ready)
			covered = set.Attached()
		} else {
			covered = uncovered(ready, natattach.UnhookedUplinks(ready))
		}
		missing := uncovered(uplinks, covered)

		if !d.setMissing(missing) {
			return
		}
		switch {
		case len(missing) == 0:
			slog.Info("Egress translation datapath covers every uplink", "uplinks", uplinks)
		case set == nil:
			slog.Warn("Uplinks carry no XDP program, so the chained shard sees none of their traffic; "+
				"the edge gateway is not attached to them", "missing", missing)
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

// chainRetryInterval is how often waitForChain looks for the gateway's map,
// and chainCheckInterval how often keepChain confirms the slot still holds
// this process's program.
const (
	chainRetryInterval = 2 * time.Second
	chainCheckInterval = 10 * time.Second
)

// waitForChain installs program in the gateway's xdp_chain at mapPath,
// retrying while the map does not exist yet -- the gateway loading after this
// process on a fresh node is ordinary, and the startup probe bounds the wait.
// Any other failure, an incompatible program above all, is returned at once:
// retrying cannot fix it.
func waitForChain(ctx context.Context, program *ebpf.Program, mapPath string) error {
	logged := false
	for {
		err := natattach.AttachChain(program, mapPath)
		if err == nil {
			slog.Info("Egress translation datapath installed in the edge gateway's XDP chain", "map", mapPath)
			return nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("install egress translation datapath in the edge gateway's XDP chain: %w", err)
		}
		if !logged {
			slog.Info("Waiting for the edge gateway to create its XDP chain map", "map", mapPath)
			logged = true
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("waiting for the edge gateway's XDP chain map %q: %w", mapPath, ctx.Err())
		case <-time.After(chainRetryInterval):
		}
	}
}

// keepChain re-installs program whenever the slot stops holding it, until ctx
// is done. A gateway restart normally reuses its pinned map and leaves the
// slot alone, but one that had to recreate the map (a layout change) leaves it
// empty, and without this the shard would stop translating with nothing
// reporting it.
func keepChain(ctx context.Context, program *ebpf.Program, mapPath string) {
	ticker := time.NewTicker(chainCheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		held, err := natattach.ChainHolds(program, mapPath)
		if err != nil {
			slog.Warn("Cannot read the edge gateway's XDP chain slot", "map", mapPath, "err", err)
			continue
		}
		if held {
			continue
		}
		if err := natattach.AttachChain(program, mapPath); err != nil {
			slog.Error("Egress translation datapath is out of the edge gateway's XDP chain and cannot be "+
				"re-installed; this shard translates nothing until it is", "map", mapPath, "err", err)
			continue
		}
		slog.Warn("Re-installed the egress translation datapath in the edge gateway's XDP chain", "map", mapPath)
	}
}

// closeAll best-effort closes every link, to unwind a partially set-up datapath
// when attaching succeeded but a later step failed.
func closeAll(links []link.Link) {
	for _, l := range links {
		_ = l.Close()
	}
}
