// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"net/netip"

	"github.com/cilium/ebpf/link"
	"github.com/prometheus/client_golang/prometheus"

	"go.datum.net/galactic/internal/gateway"
	"go.datum.net/galactic/internal/plumbing/ebpf/edgeattach"
	"go.datum.net/galactic/internal/plumbing/ebpf/edgemetrics"
	"go.datum.net/galactic/internal/plumbing/ebpf/edgeprog"
	"go.datum.net/galactic/internal/plumbing/sysctl"
)

// gatewayDatapathKeepAlive holds the loaded *edgeprog.EdgedsrObjects and
// every attached link.Link (one per public-interface XDP attach target --
// see setupGatewayDatapath's doc comment on why there can be more than one)
// for the life of this process, once setupGatewayDatapath's attach path
// succeeds. Neither is Closed anywhere in this file — see
// setupGatewayDatapath's doc comment for why — but a value that isn't
// stored somewhere reachable is exactly as good as Closed: cilium/ebpf's
// *ebpf.Program, *ebpf.Map, and link.Link types all
// register a runtime finalizer that closes their underlying fd once the
// garbage collector determines nothing reachable still points at them,
// with no error surfaced anywhere when that happens. gateway.KernelDatapath
// only keeps objs.VipTable (via edgemap.KernelTable) alive on its own, so
// without this package-level var, objs.EdgeLb (the program) and the
// link.Link returned by Attach — the two things actually keeping this
// node's XDP attachment live on the wire — would eventually get GC'd and
// silently detached, with every control-plane signal (the DaemonSet pod
// healthy, ApplyRule succeeding, vip_table metrics populated) still looking
// completely normal. Confirmed live: this is exactly what happened the
// first time this path was ever exercised against a real interface
// (ingress traffic for a registered rule was never intercepted at all,
// bouncing between this node and its transit-facing peer via ordinary
// kernel routing instead) — no unit test exercises this path with a real
// attach for a GC cycle to occur during, and this repo's own manifests-only
// validation predates any live underlay BGP peering that would have
// delivered real traffic to notice the gap.
//
// This var, and the rest of this file, moved here unchanged from
// cmd/galactic-router/gateway.go: the edge Maglev/DSR gateway datapath now
// lives in its own process rather than sharing one with the tenant BGP
// reconcilers.
var gatewayDatapathKeepAlive struct {
	objs  *edgeprog.EdgedsrObjects
	links []link.Link
}

// setupGatewayDatapath loads and attaches the edge Maglev/DSR eBPF datapath
// to publicInterface and returns the gateway.Datapath this node's Engine
// should use. Unlike cmd/galactic-router's identically-named predecessor
// (now removed), publicInterface and
// srv6Address are both required here, not a jointly-optional pair with a
// gateway.NoopDatapath{} fallback: config.GatewayConfig.Validate already
// rejects either being empty before runCmd ever calls this function, since
// this binary only exists to run the gateway role.
//
// publicInterface is usually attached to directly, but if it names a Linux
// bonding master, edgeattach.ResolveTargets expands it to that bond's slave
// interfaces instead (native-mode XDP cannot attach to a bonding master at
// all) -- so this may end up loading and attaching to more than one
// interface. Every resulting sysctl configuration and XDP attachment
// targets the same resolved set, not publicInterface itself in that case.
//
// The loaded *edgeprog.EdgedsrObjects and every returned link.Link are
// stashed in gatewayDatapathKeepAlive (see that var's doc comment for why)
// rather than Closed here: they, and the XDP attachment itself, must
// survive for the life of this process — same convention as
// internal/plumbing/ebpf/attach.Start's identical choice for the SRv6 uSID
// datapath.
//
// srv6Address is written into encap_config_table as this node's own plain
// SRv6-reachable encap source -- unlike this datapath's Full-NAT
// predecessor, it is never a NAT/SNAT source and never has return-path
// significance (see edgedsr.c's own header comment).
//
// metricsReg additionally gets an edgemetrics.Collector registered against
// it once objs is loaded, reading vip_table/vip_stats_table/drop_reasons
// live at every scrape — see that package's doc comment for why this is a
// pull-based Collector rather than incrementally-updated Gauges.
func setupGatewayDatapath(
	publicInterface, srv6Address string, metricsReg prometheus.Registerer,
) (gateway.Datapath, error) {
	encapSrc, err := netip.ParseAddr(srv6Address)
	if err != nil {
		return nil, fmt.Errorf("parse gateway SRv6 address %q: %w", srv6Address, err)
	}

	targets, err := edgeattach.ResolveTargets(publicInterface)
	if err != nil {
		return nil, fmt.Errorf("resolve edge gateway public interface %q: %w", publicInterface, err)
	}

	// Required for bpf_fib_lookup() (edgedsr.c's push_outer_header) to
	// ever succeed on the interface the XDP program actually runs on --
	// see ConfigureFIBLookupUplinkSysctls's own doc comment for why (a
	// real, previously-undiagnosed blocker, not a hypothetical one).
	// edgedsr.c looks up ctx->ingress_ifindex, i.e. whichever interface in
	// targets the packet actually arrived on, so this must be applied to
	// every resolved target, not publicInterface itself -- once
	// publicInterface names a bond, its slaves (not the bond master) are
	// what the kernel actually reports as the ingress interface. Best-
	// effort/non-fatal, matching this package's own established
	// sysctl-configuration convention (internal/cni already calls
	// ConfigureInterfaceSysctls the same way for VRF interfaces).
	for _, target := range targets {
		if err := sysctl.ConfigureFIBLookupUplinkSysctls(target); err != nil {
			return nil, fmt.Errorf("configure IPv6 forwarding on public interface %q: %w", target, err)
		}
	}

	objs, err := edgeattach.Load(edgeattach.PinDir)
	if err != nil {
		return nil, fmt.Errorf("load edge gateway eBPF datapath: %w", err)
	}

	xdpLinks, err := edgeattach.Attach(objs.EdgeLb, targets)
	if err != nil {
		_ = objs.Close()
		return nil, fmt.Errorf("attach edge gateway datapath to public interface %q: %w", publicInterface, err)
	}

	datapath, err := gateway.NewKernelDatapath(objs, encapSrc)
	if err != nil {
		closeAll(xdpLinks)
		_ = objs.Close()
		return nil, fmt.Errorf("construct kernel datapath: %w", err)
	}

	if err := metricsReg.Register(edgemetrics.NewCollectorFromObjects(objs)); err != nil {
		closeAll(xdpLinks)
		_ = objs.Close()
		return nil, fmt.Errorf("register edge gateway metrics collector: %w", err)
	}

	gatewayDatapathKeepAlive.objs = objs
	gatewayDatapathKeepAlive.links = xdpLinks

	return datapath, nil
}

// closeAll best-effort Closes every link in links, e.g. to unwind a
// partially-set-up datapath after edgeattach.Attach already succeeded but a
// later setupGatewayDatapath step failed.
func closeAll(links []link.Link) {
	for _, l := range links {
		_ = l.Close()
	}
}
