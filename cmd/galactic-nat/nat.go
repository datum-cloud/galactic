// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"log/slog"
	"net/netip"
	"sync/atomic"

	"github.com/cilium/ebpf/link"
	"github.com/prometheus/client_golang/prometheus"

	"go.datum.net/galactic/internal/config"
	"go.datum.net/galactic/internal/plumbing/ebpf/natattach"
	"go.datum.net/galactic/internal/plumbing/ebpf/natmap"
	"go.datum.net/galactic/internal/plumbing/ebpf/natprog"
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
	objs  *natprog.NatObjects
	links []link.Link
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
		ShardSID: sidAddr,
	}

	if cfg.ServesNAT66() {
		pubAddr, err := netip.ParseAddr(cfg.ShardPubAddr6)
		if err != nil {
			return natmap.ShardConfig{}, fmt.Errorf("parse shard public address %q: %w", cfg.ShardPubAddr6, err)
		}
		shardCfg.ShardPubAddr6 = pubAddr
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

// setupNatDatapath loads and attaches the egress translation datapath to every
// one of this shard's uplinks, writes its identity into the config map, and
// registers this shard's metrics. It returns the health reporter the reconciler
// uses for its Ready condition.
//
// Every configured uplink is attached, not only the one this node's traffic
// uses today: a packet arriving on an uplink with no program reaches no
// translation at all and leaves untranslated and uncounted, so a multi-homed
// shard node that attached to one uplink would lose the shard role the moment
// routing moved. Attachment is all-or-nothing -- natattach.Attach unwinds its
// own partial work -- so a shard that cannot claim every uplink fails to start
// rather than running with a hole in its coverage.
//
// The loaded objects and every returned link are stashed in natDatapathKeepAlive
// rather than closed here: they, and the attachment itself, must survive for the
// life of this process.
func setupNatDatapath(cfg *config.NATConfig, metricsReg prometheus.Registerer) (*natDatapathStatus, error) {
	shardCfg, err := shardConfigFromFlags(cfg)
	if err != nil {
		return nil, err
	}

	// Required for the FIB lookup in both the forward and return paths to
	// succeed on the interface the program actually runs on. The lookup uses
	// the ingress interface, meaning whichever uplink the packet arrived on, so
	// this must be applied to every one of them rather than to a primary.
	// Best-effort and non-fatal, matching how the gateway binary configures the
	// same sysctls.
	for _, iface := range cfg.UplinkInterfaces {
		if err := sysctl.ConfigureFIBLookupUplinkSysctls(iface); err != nil {
			return nil, fmt.Errorf("configure IPv6 forwarding on uplink interface %q: %w", iface, err)
		}
	}
	// The IPv4 counterpart, needed for the same reason on the one leg that
	// leaves this datapath as IPv4: a NAT64 forward packet resolves its next
	// hop with an IPv4 FIB lookup, which a kernel with IPv4 forwarding off
	// refuses. The datapath counts that refusal, but a shard whose every IPv4
	// flow dies at the last instruction is a shard that does not work.
	if cfg.ServesNAT64() {
		for _, iface := range cfg.UplinkInterfaces {
			if err := sysctl.ConfigureFIBLookupUplinkSysctlsIPv4(iface); err != nil {
				return nil, fmt.Errorf(
					"configure IPv4 forwarding on uplink interface %q: %w", iface, err)
			}
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

	xdpLinks, err := natattach.Attach(objs.NatIngress, cfg.UplinkInterfaces)
	if err != nil {
		_ = objs.Close()
		return nil, fmt.Errorf("attach egress translation datapath to uplink interfaces %v: %w",
			cfg.UplinkInterfaces, err)
	}

	collector := newNatCollector(objs)
	if err := metricsReg.Register(collector); err != nil {
		closeAll(xdpLinks)
		_ = objs.Close()
		return nil, fmt.Errorf("register egress shard metrics collector: %w", err)
	}

	natDatapathKeepAlive.objs = objs
	natDatapathKeepAlive.links = xdpLinks

	slog.Info("Egress translation datapath attached",
		"interfaces", cfg.UplinkInterfaces,
		"shardSID", cfg.ShardSID,
		"nat66", cfg.ServesNAT66(),
		"nat64", cfg.ServesNAT64(),
	)

	status := &natDatapathStatus{}
	status.attached.Store(true)
	return status, nil
}

// closeAll best-effort closes every link, to unwind a partially set-up datapath
// when attaching succeeded but a later step failed.
func closeAll(links []link.Link) {
	for _, l := range links {
		_ = l.Close()
	}
}
