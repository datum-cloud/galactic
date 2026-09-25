// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"log/slog"
	"sync"

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

// natDatapath is this node's attached egress translation datapath, as
// controller.EgressShardReconciler drives it (controller.EgressDatapath).
//
// Attachment happens once, at startup, and needs no identity: until Program
// writes one, shard_config_table holds a row serving no family and the
// datapath claims no packet. Program and Clear are called from the reconciler
// only, but Attached and Programmed are read concurrently with them, hence the
// mutex.
type natDatapath struct {
	uplinks     []string
	shardConfig *natmap.ShardConfigTable

	mu       sync.Mutex
	attached bool
}

// Attached reports whether startup completed its load and attach pass. It is
// set once and never cleared: there is no runtime detach detection, the
// datapath being expected to survive the process's whole lifetime.
func (d *natDatapath) Attached() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.attached
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
	}

	cfg := natmap.ShardConfig{
		ShardSID:      identity.ShardSID,
		ShardPubAddr6: identity.ShardAddressIPv6,
		ShardPubAddr4: identity.ShardAddressIPv4,
		NAT64Prefix:   identity.NAT64Prefix,
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
// Attachment is all-or-nothing -- natattach.Attach unwinds its own partial
// work -- so a shard that cannot claim every uplink fails to start rather than
// running with a hole in its coverage.
//
// The loaded objects and every returned link are stashed in natDatapathKeepAlive
// rather than closed here: they, and the attachment itself, must survive for the
// life of this process.
func setupNatDatapath(cfg *config.NATConfig, metricsReg prometheus.Registerer) (*natDatapath, error) {
	uplinks, err := natattach.ResolveUplinks(cfg.UplinkInterfaces)
	if err != nil {
		return nil, fmt.Errorf("resolve uplink interfaces: %w", err)
	}

	// Required for the FIB lookup in both the forward and return paths to
	// succeed on the interface the program actually runs on. The lookup uses
	// the ingress interface, meaning whichever uplink the packet arrived on, so
	// this must be applied to every one of them rather than to a primary:
	// once an uplink is a bond, its slaves rather than the master are what the
	// kernel reports as ingress, and uplinks already holds the slaves.
	// Best-effort and non-fatal, matching how the gateway binary configures the
	// same sysctls.
	for _, iface := range uplinks {
		if err := sysctl.ConfigureFIBLookupUplinkSysctls(iface); err != nil {
			return nil, fmt.Errorf("configure IPv6 forwarding on uplink interface %q: %w", iface, err)
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

	// shard_config_table is deliberately not written here. Its pinned row is
	// whatever this node's previous process programmed, so a restart keeps
	// translating established flows until the first reconcile re-derives it
	// from the EgressShard spec -- or clears it, if that shard is gone.
	shardConfig := natmap.NewShardConfigTable(natmap.KernelTable{Map: objs.ShardConfigTable})

	xdpLinks, err := natattach.Attach(objs.NatIngress, uplinks)
	if err != nil {
		_ = objs.Close()
		return nil, fmt.Errorf("attach egress translation datapath to uplink interfaces %v: %w", uplinks, err)
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
		"interfaces", uplinks,
		"autoDetected", len(cfg.UplinkInterfaces) == 0,
	)

	return &natDatapath{uplinks: uplinks, shardConfig: shardConfig, attached: true}, nil
}

// closeAll best-effort closes every link, to unwind a partially set-up datapath
// when attaching succeeded but a later step failed.
func closeAll(links []link.Link) {
	for _, l := range links {
		_ = l.Close()
	}
}
