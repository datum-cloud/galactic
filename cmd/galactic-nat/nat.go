// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/prometheus/client_golang/prometheus"

	"go.datum.net/galactic/internal/config"
	"go.datum.net/galactic/internal/plumbing/ebpf/natattach"
	"go.datum.net/galactic/internal/plumbing/ebpf/natmap"
	"go.datum.net/galactic/internal/plumbing/ebpf/natprog"
	"go.datum.net/galactic/internal/plumbing/sysctl"
)

// sessionResyncInterval is how often the per-tenant session counts are
// recomputed from the connection table. See runSessionResync for why they need
// recomputing at all.
const sessionResyncInterval = 30 * time.Second

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
	link link.Link
}

// natDatapathStatus reports whether setup has completed a successful load,
// attach, and configure pass. The flag is set true once, after every step
// succeeds, and never cleared: there is no runtime detach detection, the
// datapath being expected to survive the process's whole lifetime. That makes
// an atomic sufficient, it being written once and read concurrently by every
// later reconcile.
type natDatapathStatus struct {
	attached atomic.Bool
}

func (s *natDatapathStatus) Attached() bool { return s.attached.Load() }

// shardConfigFromFlags translates validated process configuration into the row
// the datapath reads. Config validation has already rejected a half-configured
// family, so an unset address here means that family is genuinely off rather
// than missing.
func shardConfigFromFlags(cfg *config.NATConfig) (natmap.ShardConfig, error) {
	sidAddr, err := netip.ParseAddr(cfg.ShardSID)
	if err != nil {
		return natmap.ShardConfig{}, fmt.Errorf("parse shard SID %q: %w", cfg.ShardSID, err)
	}

	shardCfg := natmap.ShardConfig{
		ShardSID:            sidAddr,
		DefaultSessionLimit: uint32(cfg.SessionLimit),
	}

	if cfg.ServesNAT66() {
		pubAddr, err := netip.ParseAddr(cfg.ShardPubAddr)
		if err != nil {
			return natmap.ShardConfig{}, fmt.Errorf("parse shard public address %q: %w", cfg.ShardPubAddr, err)
		}
		shardCfg.ShardPubAddr = pubAddr
	}

	if cfg.ServesNAT64() {
		pubAddr4, err := netip.ParseAddr(cfg.ShardPubAddr4)
		if err != nil {
			return natmap.ShardConfig{}, fmt.Errorf(
				"parse shard public IPv4 address %q: %w", cfg.ShardPubAddr4, err)
		}
		prefix, err := netip.ParsePrefix(cfg.NAT64Prefix)
		if err != nil {
			return natmap.ShardConfig{}, fmt.Errorf("parse NAT64 prefix %q: %w", cfg.NAT64Prefix, err)
		}
		shardCfg.ShardPubAddr4 = pubAddr4
		shardCfg.NAT64Prefix = prefix
	}

	return shardCfg, nil
}

// setupNatDatapath loads and attaches the egress translation datapath to this
// shard's uplink, writes its identity into the config map, and registers this
// shard's metrics. It returns the health reporter the reconciler uses for its
// Ready condition.
//
// The loaded objects and the returned link are stashed in natDatapathKeepAlive
// rather than closed here: they, and the attachment itself, must survive for the
// life of this process.
func setupNatDatapath(cfg *config.NATConfig, metricsReg prometheus.Registerer) (*natDatapathStatus, error) {
	shardCfg, err := shardConfigFromFlags(cfg)
	if err != nil {
		return nil, err
	}

	// Required for the FIB lookup in both the forward and return paths to
	// succeed on this interface. Best-effort and non-fatal, matching how the
	// gateway binary configures the same sysctls.
	if err := sysctl.ConfigureFIBLookupUplinkSysctls(cfg.UplinkInterface); err != nil {
		return nil, fmt.Errorf("configure IPv6 forwarding on uplink interface %q: %w", cfg.UplinkInterface, err)
	}
	// A NAT64 forward leg hands the kernel a translated IPv4 packet to route,
	// exactly as the NAT66 leg hands it an IPv6 one. Without IPv4 forwarding on
	// this interface the kernel drops every translated packet after the
	// datapath has already counted it as successfully translated, which reads
	// as a working shard with a silently broken path.
	if cfg.ServesNAT64() {
		if err := sysctl.ConfigureFIBLookupUplinkSysctlsIPv4(cfg.UplinkInterface); err != nil {
			return nil, fmt.Errorf(
				"configure IPv4 forwarding on uplink interface %q: %w", cfg.UplinkInterface, err)
		}
	}

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

	shardConfigTable := natmap.NewShardConfigTable(natmap.KernelTable{Map: objs.ShardConfigTable})
	if err := shardConfigTable.Set(shardCfg); err != nil {
		_ = objs.Close()
		return nil, fmt.Errorf("write shard_config_table: %w", err)
	}

	xdpLink, err := natattach.Attach(objs.NatIngress, cfg.UplinkInterface)
	if err != nil {
		_ = objs.Close()
		return nil, fmt.Errorf("attach egress translation datapath to uplink interface %q: %w",
			cfg.UplinkInterface, err)
	}

	collector := newNatCollector(objs)
	if err := metricsReg.Register(collector); err != nil {
		_ = xdpLink.Close()
		_ = objs.Close()
		return nil, fmt.Errorf("register egress shard metrics collector: %w", err)
	}

	natDatapathKeepAlive.objs = objs
	natDatapathKeepAlive.link = xdpLink

	slog.Info("Egress translation datapath attached",
		"interface", cfg.UplinkInterface,
		"shardSID", cfg.ShardSID,
		"nat66", cfg.ServesNAT66(),
		"nat64", cfg.ServesNAT64(),
		"sessionLimit", cfg.SessionLimit,
	)

	status := &natDatapathStatus{}
	status.attached.Store(true)
	return status, nil
}

// runSessionResync periodically recomputes every tenant's live session count
// from the connection table, until ctx is cancelled.
//
// The datapath cannot keep that count accurate on its own. nat_conn_table is an
// LRU map, so the kernel evicts rows under pressure with nothing to decrement,
// and no datapath path ages an idle flow out. Left alone the count only climbs,
// and every tenant eventually reads as over limit and stops being able to open
// connections at all -- a per-tenant ceiling degrading into a dead shard.
//
// A resync failure is logged and retried on the next tick rather than being
// fatal: the counts it corrects drift slowly, and taking the process down would
// stop translating traffic that is otherwise fine.
func runSessionResync(ctx context.Context, objs *natprog.NatObjects) {
	conns := natmap.NewConnTable(natmap.KernelTable{Map: objs.NatConnTable})
	tenants := natmap.NewTenantStateTable(natmap.KernelTable{Map: objs.TenantStateTable})

	ticker := time.NewTicker(sessionResyncInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			states, err := tenants.Resync(conns)
			if err != nil {
				slog.Error("Resync per-tenant session counts", "err", err)
				continue
			}
			slog.Debug("Resynced per-tenant session counts", "tenants", len(states))
		}
	}
}
