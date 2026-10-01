// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"sync"

	"github.com/cilium/ebpf/link"
	"github.com/prometheus/client_golang/prometheus"

	"go.datum.net/galactic/internal/gateway"
	"go.datum.net/galactic/internal/plumbing/ebpf/edgeattach"
	"go.datum.net/galactic/internal/plumbing/ebpf/edgemetrics"
	"go.datum.net/galactic/internal/plumbing/ebpf/edgeprog"
	"go.datum.net/galactic/internal/plumbing/ebpf/xdpattach"
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
	objs      *edgeprog.EdgedsrObjects
	publicSet *xdpattach.Set
	returnSet *xdpattach.Set
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
// The loaded objects and both attachment sets are stashed in
// gatewayDatapathKeepAlive rather than closed here: they, and the attachment
// itself, must survive for the life of this process.
//
// The resolution is redone for the life of ctx (watchTargets), so a bond
// member enslaved or replaced after startup gets the datapath too. coverage
// records which resolved targets are still without it.
//
// internalInterfaces name this node's compute-facing links, if any. Each is
// resolved and attached the same way as publicInterface, but with the
// edge_return program: where the compute tier routes through this node, a
// backend's reply to a VIP crosses it as ordinary forwarded traffic, and
// connection tracking has no record of the forward half to judge it against
// (see edgedsr.c's edge_return comment). An empty list attaches nothing and
// leaves the packet path unchanged.
//
// srv6Address is written into the encapsulation config as this node's plain
// SRv6-reachable source. It is never a translation source and is not what makes
// the return path work.
//
// metricsReg additionally gets a collector registered against it once the
// objects are loaded, reading the maps live at every scrape.
func setupGatewayDatapath(
	ctx context.Context, publicInterface string, internalInterfaces []string, srv6Address string,
	metricsReg prometheus.Registerer, coverage *datapathCoverage,
) (gateway.Datapath, error) {
	encapSrc, err := netip.ParseAddr(srv6Address)
	if err != nil {
		return nil, fmt.Errorf("parse gateway SRv6 address %q: %w", srv6Address, err)
	}

	targets, err := edgeattach.ResolveTargets(publicInterface)
	if err != nil {
		return nil, fmt.Errorf("resolve edge gateway public interface %q: %w", publicInterface, err)
	}

	returnTargets, err := resolveReturnTargets(internalInterfaces)
	if err != nil {
		return nil, err
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

	// edge_return calls the same FIB lookup, scoped to the interface the reply
	// arrived on, so every internal interface needs the same sysctls. Without
	// them the lookup returns BPF_FIB_LKUP_RET_NOT_FWDED for every reply and the
	// return path counts a drop per packet.
	for _, target := range returnTargets {
		if err := sysctl.ConfigureFIBLookupUplinkSysctls(target); err != nil {
			return nil, fmt.Errorf("configure IPv6 forwarding on internal interface %q: %w", target, err)
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

	if len(returnTargets) > 0 {
		returnLinks, err := edgeattach.Attach(objs.EdgeReturn, returnTargets)
		if err != nil {
			closeAll(xdpLinks)
			_ = objs.Close()
			return nil, fmt.Errorf("attach edge gateway return datapath to internal interfaces %v: %w",
				internalInterfaces, err)
		}
		xdpLinks = append(xdpLinks, returnLinks...)
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

	publicSet, err := xdpattach.NewSet(objs.EdgeLb, targets, xdpLinks[:len(targets)])
	if err != nil {
		closeAll(xdpLinks)
		_ = objs.Close()
		return nil, err
	}
	var returnSet *xdpattach.Set
	if len(returnTargets) > 0 {
		if returnSet, err = xdpattach.NewSet(objs.EdgeReturn, returnTargets, xdpLinks[len(targets):]); err != nil {
			closeAll(xdpLinks)
			_ = objs.Close()
			return nil, err
		}
	}

	gatewayDatapathKeepAlive.objs = objs
	gatewayDatapathKeepAlive.publicSet = publicSet
	gatewayDatapathKeepAlive.returnSet = returnSet

	for _, target := range append(slices.Clone(targets), returnTargets...) {
		coverage.configured[target] = true
	}
	go watchTargets(ctx, publicInterface, internalInterfaces, publicSet, returnSet, coverage)

	return datapath, nil
}

// datapathCoverage is which of the datapath's resolved targets it is not
// attached to, kept by watchTargets and read by the readiness reporter. Its
// onChange, when set, is called whenever that changes, from watchTargets'
// goroutine.
type datapathCoverage struct {
	onChange func()

	mu      sync.Mutex
	missing []string
	// configured is the targets whose forwarding sysctls have been applied.
	// Only watchTargets touches it once setup returns.
	configured map[string]bool
}

func newDatapathCoverage(onChange func()) *datapathCoverage {
	return &datapathCoverage{onChange: onChange, configured: map[string]bool{}}
}

// Missing reports the resolved targets the datapath is not attached to.
func (c *datapathCoverage) Missing() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.missing)
}

func (c *datapathCoverage) set(missing []string) {
	c.mu.Lock()
	changed := !slices.Equal(c.missing, missing)
	c.missing = slices.Clone(missing)
	c.mu.Unlock()
	if !changed {
		return
	}
	if len(missing) > 0 {
		slog.Warn("Edge gateway datapath is not attached to every resolved interface; traffic arriving on these "+
			"bypasses it", "missing", missing)
	} else {
		slog.Info("Edge gateway datapath is attached to every resolved interface")
	}
	if c.onChange != nil {
		c.onChange()
	}
}

// configure applies the forwarding sysctls the datapath's FIB lookup needs to
// every target not configured yet, returning the targets that have them. One
// that fails is left out, so the datapath is never attached where its lookup
// would refuse every packet, and retried on the next pass.
func (c *datapathCoverage) configure(targets []string) []string {
	ready := make([]string, 0, len(targets))
	for _, target := range targets {
		if !c.configured[target] {
			if err := sysctl.ConfigureFIBLookupUplinkSysctls(target); err != nil {
				slog.Error("Cannot configure forwarding on interface; leaving it without the datapath",
					"interface", target, "err", err)
				continue
			}
			c.configured[target] = true
		}
		ready = append(ready, target)
	}
	return ready
}

// watchTargets re-resolves the public and internal interfaces on every netlink
// link or route change, until ctx is done, and attaches each set's program to
// any resolved target it does not hold yet. A resolution failure, such as a
// bond in the moment between losing a member and enslaving its replacement,
// keeps every attachment and skips that pass.
func watchTargets(ctx context.Context, publicInterface string, internalInterfaces []string,
	publicSet, returnSet *xdpattach.Set, coverage *datapathCoverage,
) {
	xdpattach.OnNetlinkChange(ctx, func() {
		targets, err := edgeattach.ResolveTargets(publicInterface)
		if err != nil {
			slog.Warn("Re-resolve edge gateway public interface failed; keeping current attachments",
				"interface", publicInterface, "err", err)
			return
		}
		var returnTargets []string
		if returnSet != nil {
			if returnTargets, err = resolveReturnTargets(internalInterfaces); err != nil {
				slog.Warn("Re-resolve edge gateway internal interfaces failed; keeping current attachments",
					"err", err)
				return
			}
		}

		publicSet.Reconcile(coverage.configure(targets))
		missing := uncovered(targets, publicSet.Attached())
		if returnSet != nil {
			returnSet.Reconcile(coverage.configure(returnTargets))
			missing = append(missing, uncovered(returnTargets, returnSet.Attached())...)
		}
		coverage.set(missing)
	})
}

// uncovered returns every one of targets not in covered, in targets' order.
func uncovered(targets, covered []string) []string {
	var out []string
	for _, t := range targets {
		if !slices.Contains(covered, t) {
			out = append(out, t)
		}
	}
	return out
}

// resolveReturnTargets expands every configured internal interface the way the
// public interface is expanded, a bonding master resolving to its slaves. The
// result is flattened across all of them, since unlike the public interface
// there can legitimately be several: a compute node dual-homed to two edge
// nodes puts one internal link on each, and an edge node fronting several
// compute racks has one per rack.
func resolveReturnTargets(internalInterfaces []string) ([]string, error) {
	var targets []string
	for _, iface := range internalInterfaces {
		resolved, err := edgeattach.ResolveTargets(iface)
		if err != nil {
			return nil, fmt.Errorf("resolve edge gateway internal interface %q: %w", iface, err)
		}
		targets = append(targets, resolved...)
	}
	return targets, nil
}

// closeAll best-effort closes every link, to unwind a partially set-up datapath
// when attaching succeeded but a later step failed.
func closeAll(links []link.Link) {
	for _, l := range links {
		_ = l.Close()
	}
}
