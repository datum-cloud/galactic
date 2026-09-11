// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"net/netip"
	"sync/atomic"

	"github.com/cilium/ebpf/link"
	"github.com/prometheus/client_golang/prometheus"

	"go.datum.net/galactic/internal/plumbing/ebpf/nat66attach"
	"go.datum.net/galactic/internal/plumbing/ebpf/nat66map"
	"go.datum.net/galactic/internal/plumbing/ebpf/nat66prog"
	"go.datum.net/galactic/internal/plumbing/sysctl"
)

// nat66DatapathKeepAlive holds the loaded objects and the attached link for the
// life of this process, once the attach path succeeds.
//
// Nothing here is closed explicitly, but a value not stored somewhere reachable
// is as good as closed: the eBPF program, map, and link types all register a
// finalizer that closes the underlying descriptor once the garbage collector
// sees nothing pointing at them, with no error surfaced anywhere.
//
// Without this var, the program and the link, the two things keeping this
// shard's XDP attachment live on the wire, would eventually be collected and
// silently detached while the shard's Ready condition still reported healthy.
var nat66DatapathKeepAlive struct {
	objs *nat66prog.Nat66Objects
	link link.Link
}

// nat66DatapathStatus reports whether setup has completed a successful load,
// attach, and configure pass. The flag is set true once, after every step
// succeeds, and never cleared: there is no runtime detach detection, the
// datapath being expected to survive the process's whole lifetime. That makes
// an atomic sufficient, it being written once and read concurrently by every
// later reconcile.
type nat66DatapathStatus struct {
	attached atomic.Bool
}

func (s *nat66DatapathStatus) Attached() bool { return s.attached.Load() }

// setupNat66Datapath loads and attaches the NAT66 egress datapath to
// uplinkInterface, writes the shard's SID and public address into its config
// map, and registers this shard's metrics. It returns the health reporter the
// reconciler uses for its Ready condition.
//
// The loaded objects and the returned link are stashed in
// nat66DatapathKeepAlive rather than closed here: they, and the attachment
// itself, must survive for the life of this process.
func setupNat66Datapath(
	uplinkInterface, shardSID, shardPubAddr string, metricsReg prometheus.Registerer,
) (*nat66DatapathStatus, error) {
	sidAddr, err := netip.ParseAddr(shardSID)
	if err != nil {
		return nil, fmt.Errorf("parse shard SID %q: %w", shardSID, err)
	}
	pubAddr, err := netip.ParseAddr(shardPubAddr)
	if err != nil {
		return nil, fmt.Errorf("parse shard public address %q: %w", shardPubAddr, err)
	}

	// Required for the FIB lookup in both the forward and return paths to
	// succeed on this interface. Best-effort and non-fatal, matching how the
	// gateway binary configures the same sysctls.
	if err := sysctl.ConfigureFIBLookupUplinkSysctls(uplinkInterface); err != nil {
		return nil, fmt.Errorf("configure IPv6 forwarding on uplink interface %q: %w", uplinkInterface, err)
	}

	objs, err := nat66attach.Load(nat66attach.PinDir)
	if err != nil {
		return nil, fmt.Errorf("load NAT66 egress eBPF datapath: %w", err)
	}

	xdpLink, err := nat66attach.Attach(objs.Nat66Ingress, uplinkInterface)
	if err != nil {
		_ = objs.Close()
		return nil, fmt.Errorf("attach NAT66 egress datapath to uplink interface %q: %w", uplinkInterface, err)
	}

	shardConfigTable := nat66map.NewShardConfigTable(nat66map.KernelTable{Map: objs.ShardConfigTable})
	if err := shardConfigTable.Set(nat66map.ShardConfig{ShardSID: sidAddr, ShardPubAddr: pubAddr}); err != nil {
		_ = xdpLink.Close()
		_ = objs.Close()
		return nil, fmt.Errorf("write shard_config_table: %w", err)
	}

	collector := newNat66Collector(objs)
	if err := metricsReg.Register(collector); err != nil {
		_ = xdpLink.Close()
		_ = objs.Close()
		return nil, fmt.Errorf("register NAT66 shard metrics collector: %w", err)
	}

	nat66DatapathKeepAlive.objs = objs
	nat66DatapathKeepAlive.link = xdpLink

	status := &nat66DatapathStatus{}
	status.attached.Store(true)
	return status, nil
}
