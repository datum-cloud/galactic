// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package attach

import (
	"errors"
	"fmt"
	"log/slog"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"

	"go.datum.net/galactic/internal/plumbing/ebpf/prog"
)

// linkByNameFn and filterListFn are override points, as elsewhere in this
// package, so Health's tests can simulate an interface losing its attachment
// without root or a live interface.
var (
	linkByNameFn = netlink.LinkByName
	filterListFn = netlink.FilterList
)

// Health reports whether the eBPF uSID datapath is healthy right now: objs is
// non-nil, its program and maps still have live kernel descriptors, and the
// program is still attached to every interface in ifaces through this package's
// TC-BPF ingress filter.
//
// That is deliberately more than "the process is alive". A process can run
// perfectly well while its program has been unloaded from under it, by an
// interface being deleted or a filter detached, and this is what lets a caller
// notice the gap.
//
// A non-nil error joins every failing check, so a caller logging the result
// sees the whole picture rather than the first problem. Every interface is
// checked even after an earlier one failed.
func Health(objs *prog.UsidObjects, ifaces []string) error {
	if objs == nil {
		return errors.New("attach: health: eBPF uSID datapath objects are nil (not loaded)")
	}

	return errors.Join(
		checkProgramReachable(objs.UsidIngress),
		checkMapsReachable(objs),
		checkAttached(ifaces),
	)
}

// checkProgramReachable confirms this process's handle to usid_ingress still
// refers to a live kernel program, through a lightweight info query rather than
// anything touching the packet path.
func checkProgramReachable(program *ebpf.Program) error {
	if program == nil {
		return errors.New("attach: health: usid_ingress program handle is nil")
	}
	if _, err := program.Info(); err != nil {
		return fmt.Errorf("attach: health: usid_ingress program not reachable (unloaded?): %w", err)
	}
	return nil
}

// checkMapsReachable confirms locator_table, function_table, vrf_table, and
// drop_reasons still have live kernel descriptors, through the same lightweight
// query checkProgramReachable uses.
func checkMapsReachable(objs *prog.UsidObjects) error {
	checks := []struct {
		name string
		m    *ebpf.Map
	}{
		{prog.UsidMapVrfTable, objs.VrfTable},
		{prog.UsidMapLocatorTable, objs.LocatorTable},
		{prog.UsidMapFunctionTable, objs.FunctionTable},
		{prog.UsidMapDropReasons, objs.DropReasons},
	}

	var errs []error
	for _, c := range checks {
		if c.m == nil {
			errs = append(errs, fmt.Errorf("attach: health: map %q handle is nil", c.name))
			continue
		}
		if _, err := c.m.Info(); err != nil {
			errs = append(errs, fmt.Errorf("attach: health: map %q not reachable: %w", c.name, err))
		}
	}
	return errors.Join(errs...)
}

// checkAttached confirms this package's TC-BPF ingress filter is present on
// every interface in ifaces. That proves kernel-level attachment, which the
// program and map checks do not: those pass even after the filter itself was
// removed from outside this process.
func checkAttached(ifaces []string) error {
	if len(ifaces) == 0 {
		return errors.New("attach: health: no interfaces resolved to check attachment against")
	}

	var errs []error
	for _, name := range ifaces {
		if err := checkAttachedOne(name); err != nil {
			errs = append(errs, fmt.Errorf("attach: health: interface %q: %w", name, err))
		}
	}
	return errors.Join(errs...)
}

// checkAttachedOne confirms the filter is present among name's ingress filters,
// matched by name rather than by descriptor number, which is process-local and
// not comparable against a netlink query result.
func checkAttachedOne(name string) error {
	iface, err := linkByNameFn(name)
	if err != nil {
		return fmt.Errorf("find link: %w", err)
	}

	filters, err := filterListFn(iface, netlink.HANDLE_MIN_INGRESS)
	if err != nil {
		return fmt.Errorf("list filters: %w", err)
	}
	for _, f := range filters {
		if bpfFilter, ok := f.(*netlink.BpfFilter); ok && bpfFilter.Name == filterName {
			return nil
		}
	}
	return errors.New("galactic uSID ingress filter not attached")
}

// Handle bundles loaded objects with a health check, so a caller can query
// datapath health without depending on the loaded types or on Health directly,
// and without tracking the resolved interface set itself. Objs is exported so a
// caller that also needs the raw maps, such as the metrics collector, can reach
// them without a second load.
type Handle struct {
	Objs *prog.UsidObjects

	// Watcher, when non-nil, is consulted by Healthy alongside Health's own
	// checks:
	//   - A watch loop that is no longer running cannot self-heal drift, and
	//     nothing else restarts it, so an externally cleared filter or a moved
	//     default route would sit unfixed. Healthy reports that as unhealthy
	//     even when Health's own checks pass.
	//   - A failing Health result nudges the watcher to re-evaluate before the
	//     next tick, in case the failure is the kind of drift its reconcile
	//     heals, rather than waiting on an unrelated netlink event.
	Watcher *Watcher
}

// Close releases this process's BPF map and program descriptors. It does not
// detach the filter or unpin the maps; see the package doc comment for why that
// is safe.
func (h *Handle) Close() error {
	return h.Objs.Close()
}

// Healthy re-resolves the current interface set and reports whether the
// datapath is still attached to it with its maps reachable.
//
// Resolving fresh on every call, rather than reusing a set captured at startup,
// makes a probe reflect the datapath's current desired attachment, consistent
// with the watcher's netlink-driven re-evaluation. A transient resolution
// failure, such as a momentarily absent default route, is reported as unhealthy
// too, which is correct if occasionally noisy for a liveness signal.
//
// When a watcher is set, a non-nil Health result nudges it before returning.
// The nudge is asynchronous and debounced, so this call still reports what it
// observed while the next one may find the drift already healed. Separately, a
// watcher that is no longer running is always unhealthy: it can no longer react
// to anything, including that nudge.
func (h *Handle) Healthy() error {
	ifaces, err := ResolveInterfaces()
	if err != nil {
		return fmt.Errorf("attach: health: resolve interfaces: %w", err)
	}

	// Reported, never returned. See reportPreemption.
	reportPreemption(h.Objs)

	healthErr := Health(h.Objs, ifaces)
	if healthErr != nil {
		h.Watcher.Reconcile() // nil-safe no-op if no Watcher is wired up
	}
	if h.Watcher != nil && !h.Watcher.Alive() {
		return errors.Join(healthErr, errors.New("attach: health: netlink watch loop is not running "+
			"(dead watcher can't self-heal drift)"))
	}
	return healthErr
}

// tcxQueryFn is an override point so checkNotPreempted's tests need neither
// root nor a live interface with a foreign program on it.
var tcxQueryFn = func(ifindex int) ([]ebpf.ProgramID, error) {
	res, err := link.QueryPrograms(link.QueryOptions{
		Target: ifindex,
		Attach: ebpf.AttachTCXIngress,
	})
	if err != nil {
		return nil, err
	}
	ids := make([]ebpf.ProgramID, 0, len(res.Programs))
	for _, p := range res.Programs {
		ids = append(ids, p.ID)
	}
	return ids, nil
}

// programNameFn resolves a program id to its kernel program name. Also an
// override point, for the same reason as tcxQueryFn.
var programNameFn = func(id ebpf.ProgramID) (string, error) {
	p, err := ebpf.NewProgramFromID(id)
	if err != nil {
		return "", err
	}
	defer p.Close() //nolint:errcheck // read-only query, nothing to react to
	info, err := p.Info()
	if err != nil {
		return "", err
	}
	return info.Name, nil
}

// ownProgramIDs returns the kernel IDs of this datapath's own programs, so
// checkNotPreempted can recognise itself.
//
// By ID rather than by name, because reading a name means opening the program
// by ID, which wants CAP_SYS_ADMIN or CAP_PERFMON. This container carries
// neither, so that call returns EPERM. An ID needs no such privilege: it comes
// from an info query on a descriptor this process already holds.
//
// Getting this wrong is what made the first version of the check useless. It
// compared names, could not read them, and treated the failure as nothing to
// report, so it sat inert on a node that genuinely was preempted.
func ownProgramIDs(objs *prog.UsidObjects) map[ebpf.ProgramID]struct{} {
	out := make(map[ebpf.ProgramID]struct{}, 2)
	for _, p := range []*ebpf.Program{objs.UsidIngress, objs.UsidEgress} {
		if p == nil {
			continue
		}
		info, err := p.Info()
		if err != nil {
			continue
		}
		if id, ok := info.ID(); ok {
			out[id] = struct{}{}
		}
	}
	return out
}

// reportPreemption logs, and deliberately does not return, whatever
// checkNotPreempted finds.
//
// This must never reach the health service. Both the liveness and readiness
// probes point at that one service, so anything reported through it restarts
// the container, and a restart cannot remove another CNI's program from an
// interface. Wiring preemption into it produces a permanent crashloop, each
// restart changing nothing about the condition that caused it.
//
// Every other check in Health is a condition a restart plausibly fixes, since
// restarting reloads and re-attaches the programs. This one is not, so it
// belongs in the log an operator reads rather than in the signal that decides
// whether this container lives.
func reportPreemption(objs *prog.UsidObjects) {
	if objs == nil {
		return
	}
	if err := checkNotPreempted(ownProgramIDs(objs)); err != nil {
		slog.Warn("attach: health: another tc program runs ahead of this datapath; "+
			"traffic it consumes never reaches this datapath, and restarting will not change that",
			"err", err)
	}
}

// checkNotPreempted confirms nothing runs ahead of this datapath on the
// interfaces it owns exclusively. own is the set of program IDs to recognise as
// this datapath's own.
//
// Being attached is not the same as being reached. This package attaches
// through clsact, and the kernel runs every tcx program on a hook before any
// clsact filter, so another CNI's tcx program decides a packet's fate first. If
// it consumes or drops the packet, usid_egress is never invoked and every
// counter reads a clean zero, because from this side nothing arrived. That is
// worth checking because it is invisible from every other vantage point:
// diagnosing one instance took kernel tracing, then bpftool to see a tcx link
// that tc cannot display, then the other CNI's own drop monitor to name the
// reason.
//
// Scoped to this datapath's per-attachment interfaces, the taps and veths
// carrying usid_egress, and not to the shared uplinks usid_ingress attaches to.
// On an uplink another CNI is expected: the interface is that CNI's too, and
// receive classification here happens on a bond's slaves rather than the master
// a cluster CNI attaches to, so a program there is not in the way. Checking
// uplinks would report every node in a fleet unhealthy over an ordinary
// arrangement.
//
// The interface set is enumerated by filter rather than supplied by the caller:
// an interface carrying this package's usid_egress filter is by definition one
// this datapath owns, so the set cannot drift out of step with what is
// attached.
func checkNotPreempted(own map[ebpf.ProgramID]struct{}) error {
	links, err := linkListFn()
	if err != nil {
		return fmt.Errorf("attach: health: list links to check for preemption: %w", err)
	}

	var errs []error
	for _, l := range links {
		if !hasEgressFilter(l) {
			continue
		}
		if err := checkNotPreemptedOne(l, own); err != nil {
			errs = append(errs, fmt.Errorf("attach: health: interface %q: %w", l.Attrs().Name, err))
		}
	}
	return errors.Join(errs...)
}

// hasEgressFilter reports whether l carries this package's own usid_egress
// filter, which is what marks an interface as one this datapath owns.
func hasEgressFilter(l netlink.Link) bool {
	filters, err := filterListFn(l, netlink.HANDLE_MIN_INGRESS)
	if err != nil {
		return false
	}
	for _, f := range filters {
		if bpfFilter, ok := f.(*netlink.BpfFilter); ok && bpfFilter.Name == egressFilterName {
			return true
		}
	}
	return false
}

// checkNotPreemptedOne reports whether anything precedes this datapath on one
// owned interface. own is the set of program IDs belonging to this datapath.
//
// Findings are reported by program ID, with a name only when one can be read.
// The ID alone is enough to act on, and insisting on the name is what left the
// first version of this check unable to report anything.
//
// A failure to look is logged rather than returned. This is a diagnostic, and
// its own inability to run says nothing about whether the datapath is carrying
// traffic, so failing health on it would report the wrong thing. It is logged
// rather than swallowed, because silence that could mean either "nothing is
// wrong" or "this never ran" is what let an inert check look like a passing
// one.
func checkNotPreemptedOne(l netlink.Link, own map[ebpf.ProgramID]struct{}) error {
	name := l.Attrs().Name

	ids, err := tcxQueryFn(l.Attrs().Index)
	if err != nil {
		if errors.Is(err, ebpf.ErrNotSupported) {
			// A kernel with no tcx cannot have a tcx program to be preempted
			// by, so there is nothing to report or warn about.
			return nil
		}
		slog.Warn("attach: health: could not check whether another tc program precedes this datapath",
			"interface", name, "err", err)
		return nil
	}
	if len(ids) == 0 {
		return nil // nothing in front of clsact
	}

	first := ids[0]
	if _, ours := own[first]; ours {
		return nil
	}

	// Best effort, and expected to fail without CAP_SYS_ADMIN or
	// CAP_PERFMON. The id carries the report either way.
	if progName, nerr := programNameFn(first); nerr == nil {
		return fmt.Errorf("tc program %q (id %d) runs ahead of this datapath "+
			"(tcx precedes clsact), so traffic it consumes never reaches usid_egress",
			progName, first)
	}
	return fmt.Errorf("an unidentified tc program (id %d) runs ahead of this datapath "+
		"(tcx precedes clsact), so traffic it consumes never reaches usid_egress; "+
		"run `bpftool prog show id %d` to name it", first, first)
}
