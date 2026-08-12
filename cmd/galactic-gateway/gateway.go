// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/cilium/ebpf/link"
	"github.com/prometheus/client_golang/prometheus"

	"go.datum.net/galactic/internal/gateway"
	"go.datum.net/galactic/internal/plumbing/ebpf/edgeattach"
	"go.datum.net/galactic/internal/plumbing/ebpf/edgemetrics"
	"go.datum.net/galactic/internal/plumbing/ebpf/edgeprog"
)

// gatewayDatapathKeepAlive holds the loaded *edgeprog.EdgenatObjects and
// the attached link.Link for the life of this process, once
// setupGatewayDatapath's attach path succeeds. Neither is Closed anywhere
// in this file — see setupGatewayDatapath's doc comment for why — but a
// value that isn't stored somewhere reachable is exactly as good as
// Closed: cilium/ebpf's *ebpf.Program, *ebpf.Map, and link.Link types all
// register a runtime finalizer that closes their underlying fd once the
// garbage collector determines nothing reachable still points at them,
// with no error surfaced anywhere when that happens. gateway.KernelDatapath
// only keeps objs.RuleTable (via edgemap.KernelTable) alive on its own, so
// without this package-level var, objs.EdgeNat (the program) and the
// link.Link returned by Attach — the two things actually keeping this
// node's XDP attachment live on the wire — would eventually get GC'd and
// silently detached, with every control-plane signal (the DaemonSet pod
// healthy, ApplyRule succeeding, rule_table metrics populated) still
// looking completely normal. Confirmed live: this is exactly what happened
// the first time this path was ever exercised against a real interface
// (ingress traffic for a registered rule was never intercepted at all,
// bouncing between this node and its transit-facing peer via ordinary
// kernel routing instead) — no unit test exercises this path with a real
// attach for a GC cycle to occur during, and Phase D's "manifests and the
// live pod/eBPF path" validation predates any live underlay BGP peering
// that would have delivered real traffic to notice the gap.
//
// This var, and the rest of this file, moved here unchanged from
// cmd/galactic-router/gateway.go: the edge NAT+LB gateway datapath now
// lives in its own process rather than sharing one with the tenant BGP
// reconcilers.
var gatewayDatapathKeepAlive struct {
	objs *edgeprog.EdgenatObjects
	link link.Link
}

// setupGatewayDatapath loads and attaches the edge NAT+LB eBPF datapath to
// publicInterface and returns the gateway.Datapath this node's Engine
// should use. Unlike cmd/galactic-router's identically-named predecessor
// (now removed), publicInterface and
// srv6Address are both required here, not a jointly-optional pair with a
// gateway.NoopDatapath{} fallback: config.GatewayConfig.Validate already
// rejects either being empty before runCmd ever calls this function, since
// this binary only exists to run the gateway role.
//
// The loaded *edgeprog.EdgenatObjects and the returned link.Link are
// stashed in gatewayDatapathKeepAlive (see that var's doc comment for why)
// rather than Closed here: they, and the XDP attachment itself, must
// survive for the life of this process — same convention as
// internal/plumbing/ebpf/attach.Start's identical choice for the SRv6 uSID
// datapath.
//
// metricsReg additionally gets an edgemetrics.Collector registered against
// it once objs is loaded, reading rule_table/conn_table/drop_reasons live
// at every scrape — see that package's doc comment for why this is a
// pull-based Collector rather than incrementally-updated Gauges.
func setupGatewayDatapath(
	publicInterface, srv6Address string, metricsReg prometheus.Registerer,
) (gateway.Datapath, error) {
	gwAddr, err := netip.ParseAddr(srv6Address)
	if err != nil {
		return nil, fmt.Errorf("parse gateway SRv6 address %q: %w", srv6Address, err)
	}

	objs, err := edgeattach.Load(edgeattach.PinDir)
	if err != nil {
		return nil, fmt.Errorf("load edge gateway eBPF datapath: %w", err)
	}

	xdpLink, err := edgeattach.Attach(objs.EdgeNat, publicInterface)
	if err != nil {
		_ = objs.Close()
		return nil, fmt.Errorf("attach edge gateway datapath to public interface %q: %w", publicInterface, err)
	}

	if _, err := net.InterfaceByName(publicInterface); err != nil {
		_ = xdpLink.Close()
		_ = objs.Close()
		return nil, fmt.Errorf("resolve public interface %q: %w", publicInterface, err)
	}

	datapath, err := gateway.NewKernelDatapath(objs, gwAddr)
	if err != nil {
		_ = xdpLink.Close()
		_ = objs.Close()
		return nil, fmt.Errorf("construct kernel datapath: %w", err)
	}

	if err := metricsReg.Register(edgemetrics.NewCollectorFromObjects(objs)); err != nil {
		_ = xdpLink.Close()
		_ = objs.Close()
		return nil, fmt.Errorf("register edge gateway metrics collector: %w", err)
	}

	gatewayDatapathKeepAlive.objs = objs
	gatewayDatapathKeepAlive.link = xdpLink

	return datapath, nil
}
