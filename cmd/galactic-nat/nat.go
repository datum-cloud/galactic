// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"sync/atomic"

	"github.com/cilium/ebpf/link"
	"github.com/prometheus/client_golang/prometheus"

	"go.datum.net/galactic/internal/config"
	"go.datum.net/galactic/internal/controller"
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

// natDatapath is the running egress translation datapath: the attachment this
// process makes at startup, plus the shard config row the EgressShard
// reconciler writes into it once a controller assigns this shard an address.
//
// It retains the ShardConfigTable handle for exactly that reason. The row
// cannot be written during setup any more -- there is no address to write
// until an EgressShard spec carries one -- so the handle has to outlive setup
// rather than be dropped once the datapath is attached.
//
// attached is set true once, after load, attach, and metric registration all
// succeed, and never cleared: there is no runtime detach detection, the
// attachment being expected to survive this process's whole lifetime. Whether
// that attached datapath translates anything is a separate question, which
// Program's return value answers.
type natDatapath struct {
	attached atomic.Bool

	table *natmap.ShardConfigTable

	// base is the part of the row this process still supplies: the shard SID,
	// and the NAT64 half wherever an operator configured one. Program composes
	// the assigned address onto it.
	base natmap.ShardConfig

	// mu guards programmed and serializes Program's compose-and-write.
	// Reconciles are serialized by the controller today, so this guards
	// against that changing rather than against a known racer.
	mu sync.Mutex

	// programmed is the row last written successfully, or nil while the
	// datapath holds no row at all. An unwritten row is what makes the XDP
	// program fail open and claim no packet.
	programmed *natmap.ShardConfig
}

func (d *natDatapath) Attached() bool { return d.attached.Load() }

// Program writes addressIPv6 into the shard config row and reports what the
// datapath holds afterwards.
//
// An invalid addressIPv6 means no IPv6 address is assigned to this shard. With
// no configured NAT64 half either that leaves nothing worth writing, so the row
// is left alone -- the datapath stays failed open, claiming nothing -- and the
// reported identity is whatever an earlier call already programmed, that still
// being what the datapath translates with. Nothing here clears a row: the map
// layer has no withdrawal, and an address already on the wire cannot be taken
// back from the flows using it.
//
// The write is unconditional rather than skipped when the row already matches.
// It is a blind overwrite of a one-entry array carrying no datapath-owned
// field, so rewriting costs one map update per reconcile and repairs a row
// that diverged for any reason.
func (d *natDatapath) Program(addressIPv6 netip.Addr) (controller.EgressShardIdentity, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	shardCfg := d.base
	if addressIPv6.IsValid() {
		shardCfg.ShardPubAddr6 = addressIPv6
	}
	if !shardCfg.ShardPubAddr6.IsValid() && !shardCfg.ShardPubAddr4.IsValid() {
		return identityOf(d.programmed), nil
	}

	// The datapath claims a reply by exact match on the address it translated
	// to, so a different address does not add a path, it moves one: every flow
	// established through the previous address loses its return traffic. The
	// API makes the field write-once to prevent this, so this logs rather than
	// drains -- there is no drain to perform.
	if d.programmed != nil && d.programmed.ShardPubAddr6 != shardCfg.ShardPubAddr6 {
		slog.Warn("Egress shard address changed after being programmed, established flows lose their return path",
			"previous", d.programmed.ShardPubAddr6, "assigned", shardCfg.ShardPubAddr6)
	}

	if err := d.table.Set(shardCfg); err != nil {
		return identityOf(d.programmed), fmt.Errorf("write shard_config_table: %w", err)
	}
	d.programmed = &shardCfg

	return identityOf(d.programmed), nil
}

// identityOf renders a programmed row as the identity the reconciler
// publishes. A nil row is a datapath holding nothing, and reports every field
// empty.
func identityOf(shardCfg *natmap.ShardConfig) controller.EgressShardIdentity {
	if shardCfg == nil {
		return controller.EgressShardIdentity{}
	}
	var identity controller.EgressShardIdentity
	if shardCfg.ShardPubAddr6.IsValid() {
		identity.ShardAddressIPv6 = shardCfg.ShardPubAddr6.String()
	}
	if shardCfg.ShardPubAddr4.IsValid() {
		identity.ShardAddressIPv4 = shardCfg.ShardPubAddr4.String()
		identity.NAT64Prefix = shardCfg.NAT64Prefix.String()
	}
	return identity
}

// baseShardConfig translates validated process configuration into the part of
// the datapath's row this process still supplies: the shard SID, plus the
// NAT64 half wherever an operator configured one.
//
// The IPv6 masquerade address is deliberately absent. It arrives in EgressShard
// spec, written by the controller that owns the cell, so this process holds no
// value for it and the reconciler composes it on.
func baseShardConfig(cfg *config.NATConfig) (natmap.ShardConfig, error) {
	sidAddr, err := netip.ParseAddr(cfg.ShardSID)
	if err != nil {
		return natmap.ShardConfig{}, fmt.Errorf("parse shard SID %q: %w", cfg.ShardSID, err)
	}

	shardCfg := natmap.ShardConfig{ShardSID: sidAddr}

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
// one of this shard's uplinks and registers this shard's metrics. It returns
// the datapath the reconciler programs and reads its conditions from.
//
// It no longer writes the shard config row. The masquerade address is assigned
// in EgressShard spec, which this process cannot read until its manager is
// running, so the datapath is attached holding an unwritten row and programmed
// afterwards. That is safe because the XDP program fails open on a row it has
// never been given -- it claims no packet and forwards everything untouched --
// but it is a real state a shard now sits in, reported as Programmed=False
// with reason AddressUnassigned rather than hidden behind an attached-only
// health signal.
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
func setupNatDatapath(cfg *config.NATConfig, metricsReg prometheus.Registerer) (*natDatapath, error) {
	shardCfg, err := baseShardConfig(cfg)
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

	slog.Info("Egress translation datapath attached, awaiting an assigned address",
		"interfaces", cfg.UplinkInterfaces,
		"shardSID", cfg.ShardSID,
		"nat64", cfg.ServesNAT64(),
	)

	datapath := &natDatapath{
		table: natmap.NewShardConfigTable(natmap.KernelTable{Map: objs.ShardConfigTable}),
		base:  shardCfg,
	}
	datapath.attached.Store(true)
	return datapath, nil
}

// closeAll best-effort closes every link, to unwind a partially set-up datapath
// when attaching succeeded but a later step failed.
func closeAll(links []link.Link) {
	for _, l := range links {
		_ = l.Close()
	}
}
