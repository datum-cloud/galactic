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

// gatewayDatapathKeepAlive holds the loaded objects and every attached link for
// the life of this process, once the attach path succeeds.
//
// Nothing here is closed explicitly, but a value not stored somewhere reachable
// is exactly as good as closed: the eBPF program, map, and link types all
// register a finalizer that closes the underlying descriptor once the garbage
// collector sees nothing pointing at them, with no error surfaced anywhere.
//
// The datapath implementation keeps only the VIP table alive on its own, so
// without this var the program and the link, the two things actually keeping
// this node's XDP attachment live on the wire, would eventually be collected
// and silently detached. Every control-plane signal would still look normal:
// the pod healthy, rules applying, metrics populated, while ingress traffic for
// a registered rule is never intercepted at all and routes past the node
// ordinarily.
var gatewayDatapathKeepAlive struct {
	objs  *edgeprog.EdgedsrObjects
	links []link.Link
}

// setupGatewayDatapath loads and attaches the edge Maglev datapath to
// publicInterface and returns the Datapath this node's engine should use.
//
// publicInterface and srv6Address are both required: configuration validation
// rejects either being empty before this runs, since this binary exists only to
// run the gateway role.
//
// publicInterface is usually attached to directly, but one naming a Linux
// bonding master is expanded to that bond's slaves instead, native-mode XDP
// being unable to attach to a bonding master. Every sysctl and every attachment
// then targets the resolved set rather than the named interface.
//
// The loaded objects and every returned link are stashed in
// gatewayDatapathKeepAlive rather than closed here: they, and the attachment
// itself, must survive for the life of this process.
//
// srv6Address is written into the encapsulation config as this node's plain
// SRv6-reachable source. It is never a translation source and has no
// return-path significance.
//
// metricsReg additionally gets a collector registered against it once the
// objects are loaded, reading the maps live at every scrape.
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

	// Required for the FIB lookup in the datapath's header push to succeed
	// on the interface the program actually runs on. The lookup uses the
	// ingress interface, meaning whichever resolved target the packet
	// arrived on, so this must be applied to every one of them: once the
	// named interface is a bond, its slaves rather than the master are
	// what the kernel reports as ingress. Best-effort and non-fatal,
	// matching how sysctls are configured elsewhere here.
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

// closeAll best-effort closes every link, to unwind a partially set-up datapath
// when attaching succeeded but a later step failed.
func closeAll(links []link.Link) {
	for _, l := range links {
		_ = l.Close()
	}
}
