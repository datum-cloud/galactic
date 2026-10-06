// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"sync"

	"github.com/cilium/ebpf/link"
	"github.com/prometheus/client_golang/prometheus"

	"go.datum.net/galactic/internal/config"
	"go.datum.net/galactic/internal/gateway"
	"go.datum.net/galactic/internal/plumbing/ebpf/edgeattach"
	"go.datum.net/galactic/internal/plumbing/ebpf/edgemetrics"
	"go.datum.net/galactic/internal/plumbing/ebpf/edgeprog"
	"go.datum.net/galactic/internal/plumbing/ebpf/xdpattach"
	"go.datum.net/galactic/internal/plumbing/ebpf/xdpdispatch"
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
	objs       *edgeprog.EdgedsrObjects
	publicSet  targetSet
	returnSet  targetSet
	dispatcher *xdpdispatch.Dispatcher
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
	ctx context.Context, publicInterface string, internalInterfaces []string, srv6Address, attachMode string,
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
	// edge_return forwards anything sourced from a VIP. On a public uplink an
	// external client could source a packet from a VIP and have it forwarded
	// unexamined, so an internal interface may never resolve to a public one.
	if overlap := publicReturnOverlap(targets, returnTargets); len(overlap) > 0 {
		return nil, fmt.Errorf("edge gateway internal interfaces %v resolve to %v, which the public interface %q "+
			"also resolves to; the return program must never run on a public uplink", internalInterfaces,
			overlap, publicInterface)
	}

	// Required for the FIB lookup in the datapath's header push to succeed
	// on the interface the program actually runs on. The lookup uses the
	// ingress interface, meaning whichever resolved target the packet
	// arrived on, so this must be applied to every one of them: once the
	// named interface is a bond, its slaves rather than the master are
	// what the kernel reports as ingress. A target left without forwarding
	// fails startup: the datapath would drop every packet arriving there
	// while the process reported healthy.
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

	var (
		objs                 *edgeprog.EdgedsrObjects
		publicSet, returnSet targetSet
		dispatcher           *xdpdispatch.Dispatcher
	)
	// abandon undoes a dispatcher join when a later setup step fails: the
	// leases stop and the slots are emptied, so a half-set-up gateway never
	// claims packets while the process exits.
	abandon := func() {}
	if attachMode == config.GatewayXDPAttachDispatch {
		leaseCtx, stopLeases := context.WithCancel(ctx)
		var leaseDone <-chan struct{}
		objs, dispatcher, publicSet, returnSet, leaseDone, err = joinDispatcher(leaseCtx, xdpdispatch.PinDir,
			edgeattach.PinDir, len(returnTargets) > 0)
		if err != nil {
			stopLeases()
			return nil, err
		}
		abandon = func() {
			stopLeases()
			<-leaseDone
			if err := xdpattach.ClearDispatcherSlots(ctx, xdpdispatch.PinDir, xdpdispatch.SlotGatewayLB,
				xdpdispatch.SlotGatewayReturn); err != nil {
				slog.Warn("Cannot empty the edge gateway's dispatcher slots after a failed setup", "err", err)
			}
		}
	} else {
		objs, publicSet, returnSet, err = attachDirect(ctx, xdpdispatch.PinDir, edgeattach.PinDir, targets,
			returnTargets)
	}
	if err != nil {
		return nil, err
	}

	datapath, err := gateway.NewKernelDatapath(objs, encapSrc)
	if err != nil {
		abandon()
		return nil, fmt.Errorf("construct kernel datapath: %w", err)
	}
	if err := metricsReg.Register(edgemetrics.NewCollectorFromObjects(objs)); err != nil {
		abandon()
		return nil, fmt.Errorf("register edge gateway metrics collector: %w", err)
	}

	gatewayDatapathKeepAlive.objs = objs
	gatewayDatapathKeepAlive.publicSet = publicSet
	gatewayDatapathKeepAlive.returnSet = returnSet
	gatewayDatapathKeepAlive.dispatcher = dispatcher

	for _, target := range append(slices.Clone(targets), returnTargets...) {
		coverage.configured[target] = true
	}
	missing := publicSet.reconcile(ctx, targets)
	if returnSet != nil {
		missing = append(missing, returnSet.reconcile(ctx, returnTargets)...)
	}
	coverage.set(missing)
	go watchTargets(ctx, publicInterface, internalInterfaces, publicSet, returnSet, coverage)

	return datapath, nil
}

// targetSet keeps one of the gateway's programs on a set of interfaces and
// reports the ones it does not cover: xdpattach.Set in direct mode,
// xdpattach.DispatchSet in dispatch mode.
type targetSet interface {
	reconcile(ctx context.Context, targets []string) (missing []string)
}

type directSet struct{ *xdpattach.Set }

func (s directSet) reconcile(_ context.Context, targets []string) []string {
	s.Reconcile(targets)
	return uncovered(targets, s.Attached())
}

type dispatchSet struct{ *xdpattach.DispatchSet }

func (s dispatchSet) reconcile(ctx context.Context, targets []string) []string {
	return s.Reconcile(ctx, targets)
}

// attachDirect loads the programs with their own dispatcher maps and attaches
// them to the targets themselves, unpinned, after releasing an idle
// dispatcher from those targets. A dispatcher still serving the egress shard
// there is refused rather than taken: detaching it would cut egress.
// Attachment is all-or-nothing, as it has always been in this mode.
func attachDirect(ctx context.Context, dispatchDir, edgeDir string, targets, returnTargets []string) (
	*edgeprog.EdgedsrObjects, targetSet, targetSet, error,
) {
	if err := xdpattach.ReleaseIdleDispatcher(ctx, dispatchDir, append(slices.Clone(targets), returnTargets...),
		xdpdispatch.SlotGatewayLB, xdpdispatch.SlotGatewayReturn); err != nil {
		return nil, nil, nil, fmt.Errorf("%w; set %s=%s", err, config.EnvGatewayXDPAttach,
			config.GatewayXDPAttachDispatch)
	}

	objs, err := edgeattach.Load(edgeDir, nil)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("load edge gateway eBPF datapath: %w", err)
	}

	xdpLinks, err := edgeattach.Attach(objs.EdgeLb, targets)
	if err != nil {
		_ = objs.Close()
		return nil, nil, nil, fmt.Errorf("attach edge gateway datapath to public interfaces %v: %w", targets, err)
	}
	publicSet, err := xdpattach.NewSet(objs.EdgeLb, targets, xdpLinks)
	if err != nil {
		closeAll(xdpLinks)
		_ = objs.Close()
		return nil, nil, nil, err
	}
	if len(returnTargets) == 0 {
		return objs, directSet{publicSet}, nil, nil
	}

	returnLinks, err := edgeattach.Attach(objs.EdgeReturn, returnTargets)
	if err != nil {
		closeAll(xdpLinks)
		_ = objs.Close()
		return nil, nil, nil, fmt.Errorf("attach edge gateway return datapath to internal interfaces %v: %w",
			returnTargets, err)
	}
	returnSet, err := xdpattach.NewSet(objs.EdgeReturn, returnTargets, returnLinks)
	if err != nil {
		closeAll(append(xdpLinks, returnLinks...))
		_ = objs.Close()
		return nil, nil, nil, err
	}
	return objs, directSet{publicSet}, directSet{returnSet}, nil
}

// joinDispatcher opens the node's XDP dispatcher under dispatchDir, loads the
// programs against its maps, with their own maps pinned under edgeDir, fills
// the gateway's slots, and renews both slots' leases for the life of ctx. The
// return slot is filled whether or not this node has internal interfaces:
// without the role on any interface it never runs. Nothing is attached here;
// the returned sets put the dispatcher on the targets and read coverage back.
// The returned channel closes once both lease loops have stopped, which a
// caller waits on before closing the dispatcher.
func joinDispatcher(ctx context.Context, dispatchDir, edgeDir string, withReturn bool) (
	*edgeprog.EdgedsrObjects, *xdpdispatch.Dispatcher, targetSet, targetSet, <-chan struct{}, error,
) {
	dispatcher, err := xdpdispatch.Open(ctx, dispatchDir)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("open the node's XDP dispatcher: %w", err)
	}
	fail := func(err error) (*edgeprog.EdgedsrObjects, *xdpdispatch.Dispatcher, targetSet, targetSet,
		<-chan struct{}, error,
	) {
		_ = dispatcher.Close()
		return nil, nil, nil, nil, nil, err
	}

	objs, err := edgeattach.Load(edgeDir, dispatcher.Maps())
	if err != nil {
		return fail(fmt.Errorf("load edge gateway eBPF datapath: %w", err))
	}
	lock, err := dispatcher.Lock(ctx)
	if err != nil {
		_ = objs.Close()
		return fail(err)
	}
	err = errors.Join(lock.Fill(xdpdispatch.SlotGatewayLB, objs.EdgeLb),
		lock.Fill(xdpdispatch.SlotGatewayReturn, objs.EdgeReturn))
	lock.Unlock()
	if err != nil {
		_ = objs.Close()
		return fail(fmt.Errorf("install edge gateway datapath in the XDP dispatcher: %w", err))
	}

	public, err := xdpattach.NewDispatchSet(dispatcher, xdpdispatch.SlotGatewayLB, xdpdispatch.RolePublicLB,
		objs.EdgeLb)
	if err != nil {
		_ = objs.Close()
		return fail(err)
	}
	var ret targetSet
	if withReturn {
		rs, err := xdpattach.NewDispatchSet(dispatcher, xdpdispatch.SlotGatewayReturn,
			xdpdispatch.RoleInternalReturn, objs.EdgeReturn)
		if err != nil {
			_ = objs.Close()
			return fail(err)
		}
		ret = dispatchSet{rs}
	}

	// A lapsed lease shows as missing interfaces within one coverage resync,
	// since every Reconcile reads the lease back.
	var leases sync.WaitGroup
	for _, slot := range []xdpdispatch.Slot{xdpdispatch.SlotGatewayLB, xdpdispatch.SlotGatewayReturn} {
		leases.Go(func() {
			dispatcher.Lease(ctx, slot, func(err error) {
				slog.Error("Cannot renew an edge gateway slot's lease in the XDP dispatcher; "+
					"the dispatcher skips the slot once it lapses", "slot", slot, "err", err)
			})
		})
	}
	leaseDone := make(chan struct{})
	go func() {
		leases.Wait()
		close(leaseDone)
	}()
	slog.Info("Edge gateway datapath installed in the XDP dispatcher", "pinDir", dispatchDir)
	return objs, dispatcher, dispatchSet{public}, ret, leaseDone, nil
}

// publicReturnOverlap returns the return targets that are also public targets.
func publicReturnOverlap(targets, returnTargets []string) []string {
	var overlap []string
	for _, t := range returnTargets {
		if slices.Contains(targets, t) {
			overlap = append(overlap, t)
		}
	}
	return overlap
}

// turnOffDatapath turns this node's gateway off. A dispatch-mode predecessor
// left the gateway's programs in the XDP dispatcher with live leases, so its
// slots are emptied here and the dispatcher passes their traffic on at once.
// Every other slot, and the dispatcher itself, are left alone. A failure is
// logged, not returned: the leases lapse on their own within
// xdpdispatch.LeaseTTL.
func turnOffDatapath(ctx context.Context, pinDir string) {
	if err := xdpattach.ClearDispatcherSlots(ctx, pinDir, xdpdispatch.SlotGatewayLB,
		xdpdispatch.SlotGatewayReturn); err != nil {
		slog.Error("Cannot empty the edge gateway's slots in the XDP dispatcher; "+
			"they stop claiming packets once their leases lapse", "lease", xdpdispatch.LeaseTTL, "err", err)
	}
	slog.Info("Edge gateway datapath is turned off; this node attaches nothing and advertises no VIP",
		"env", config.EnvGatewayDatapathEnabled)
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
	publicSet, returnSet targetSet, coverage *datapathCoverage,
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
			if overlap := publicReturnOverlap(targets, returnTargets); len(overlap) > 0 {
				slog.Warn("Internal interfaces now resolve to public ones; keeping the return program off them",
					"interfaces", overlap)
				returnTargets = slices.DeleteFunc(returnTargets, func(t string) bool { return slices.Contains(overlap, t) })
			}
		}

		// A target whose forwarding sysctls failed is left out of the set and
		// counted missing; configure retries it on the next pass.
		ready := coverage.configure(targets)
		missing := append(publicSet.reconcile(ctx, ready), uncovered(targets, ready)...)
		if returnSet != nil {
			ready := coverage.configure(returnTargets)
			missing = append(missing, returnSet.reconcile(ctx, ready)...)
			missing = append(missing, uncovered(returnTargets, ready)...)
		}
		coverage.set(dedupe(missing))
	})
}

// dedupe drops repeated names, keeping the first of each.
func dedupe(names []string) []string {
	var out []string
	for _, n := range names {
		if !slices.Contains(out, n) {
			out = append(out, n)
		}
	}
	return out
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
