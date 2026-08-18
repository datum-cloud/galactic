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

// nat66DatapathKeepAlive holds the loaded *nat66prog.Nat66Objects and the
// attached link.Link for the life of this process, once
// setupNat66Datapath's attach path succeeds. Neither is Closed anywhere in
// this file -- mirrors cmd/galactic-gateway/gateway.go's
// gatewayDatapathKeepAlive var and its doc comment's full rationale
// (cilium/ebpf's *ebpf.Program, *ebpf.Map, and link.Link types all
// register a runtime finalizer that closes their underlying fd once the
// garbage collector determines nothing reachable still points at them,
// with no error surfaced anywhere when that happens -- confirmed live the
// first time gatewayDatapathKeepAlive's absence was ever exercised against
// a real interface: ingress traffic for a registered rule was silently
// never intercepted at all). Without an equivalent var here,
// objs.Nat66Ingress (the program) and the link.Link returned by Attach --
// the two things actually keeping this shard's XDP attachment live on the
// wire -- would eventually get GC'd and silently detached, with the
// NAT66Shard's own Ready condition still reporting healthy.
var nat66DatapathKeepAlive struct {
	objs *nat66prog.Nat66Objects
	link link.Link
}

// nat66DatapathStatus implements controller.NAT66DatapathHealth,
// reporting whether setupNat66Datapath has completed a successful
// load+attach+configure pass. attached is only ever set true, once, by
// setupNat66Datapath after every step below succeeds -- there is no
// runtime detach detection here (the datapath is expected to survive for
// this process's whole lifetime, mirroring gatewayDatapathKeepAlive's own
// "attached once at startup, held open forever" convention), so an
// atomic.Bool rather than a mutex-guarded struct is sufficient: it's only
// ever written once and read concurrently by every subsequent
// NAT66ShardReconciler.Reconcile call.
type nat66DatapathStatus struct {
	attached atomic.Bool
}

func (s *nat66DatapathStatus) Attached() bool { return s.attached.Load() }

// setupNat66Datapath loads and attaches the NAT66 egress eBPF datapath to
// uplinkInterface, writes shardSID/shardPubAddr into shard_config_table,
// and registers this shard's Prometheus metrics, returning the
// controller.NAT66DatapathHealth NAT66ShardReconciler uses to report its
// Ready condition.
//
// Mirrors cmd/galactic-gateway/gateway.go's setupGatewayDatapath: the
// loaded *nat66prog.Nat66Objects and the returned link.Link are stashed in
// nat66DatapathKeepAlive (see that var's doc comment for why) rather than
// Closed here -- they, and the XDP attachment itself, must survive for the
// life of this process.
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

	// Required for bpf_fib_lookup() (nat66.c's push_outer_header, used by
	// both the forward and return paths) to ever succeed on this interface
	// -- see sysctl.ConfigureFIBLookupUplinkSysctls's own doc comment for
	// why (a real, previously-undiagnosed blocker, first found against
	// edgedsr.c but equally applicable here since both datapaths share the
	// identical bpf_fib_lookup mechanism). Best-effort/non-fatal, matching
	// cmd/galactic-gateway/gateway.go's identical call.
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
