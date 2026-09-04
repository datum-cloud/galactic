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

// linkByNameFn and filterListFn are package-level override points -- the
// same pattern used throughout this package (interfaces.go's
// routeListFn/linkByIndexFn, watch.go's linkSubscribeFn/routeSubscribeFn) --
// so Health's own tests can simulate an interface losing its attachment
// without needing root or a live network interface.
var (
	linkByNameFn = netlink.LinkByName
	filterListFn = netlink.FilterList
)

// Health reports whether the eBPF uSID datapath is genuinely healthy right
// now: objs is non-nil and its program/maps still have live, reachable
// kernel file descriptors, and the program is still attached to every
// interface in ifaces via this package's own TC-BPF ingress filter
// (filterName). This is deliberately more than "the process is alive"
// (design plan .local/plan-ebpf-xdp-usid-datapath.md §9: "confirms the BPF
// program is actually attached and the maps are reachable -- not just that
// the process is alive"; Milestone 4 of
// .local/implementation-plan-ebpf-xdp-usid-datapath.md) -- a process can be
// running perfectly well while its BPF program has been unloaded out from
// under it (e.g. someone ran `ip link del` on the attached interface, or
// bpftool prog detach), and this function is what a caller (internal/
// installer's gRPC health check) uses to notice that gap.
//
// A non-nil error joins every failing check (errors.Join), so a caller
// logging the result sees the complete picture rather than just the first
// problem encountered; every interface in ifaces is checked even after an
// earlier interface or the program/map checks already failed.
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

// checkProgramReachable confirms this process's own handle to usid_ingress
// still refers to a live kernel program, via a lightweight
// BPF_OBJ_GET_INFO_BY_FD query (program.Info()) rather than anything that
// touches the packet path.
func checkProgramReachable(program *ebpf.Program) error {
	if program == nil {
		return errors.New("attach: health: usid_ingress program handle is nil")
	}
	if _, err := program.Info(); err != nil {
		return fmt.Errorf("attach: health: usid_ingress program not reachable (unloaded?): %w", err)
	}
	return nil
}

// checkMapsReachable confirms every one of the three control-plane maps
// (locator_table, function_table, vrf_table) plus drop_reasons still has a
// live, reachable kernel file descriptor, via the same lightweight Info()
// query checkProgramReachable uses for the program.
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

// checkAttached confirms this package's own TC-BPF ingress filter
// (filterName) is currently present on every interface in ifaces --
// proving actual kernel-level attachment, not merely that this process's
// program/map handles are still open (checkProgramReachable/
// checkMapsReachable can pass even after the filter itself was removed by
// something outside this process, e.g. `tc filter del` or the interface
// being recreated).
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

// checkAttachedOne confirms filterName is present among name's ingress
// filters -- the same identification method detachOne already uses (match
// by filter name, not by comparing file descriptor numbers, which are
// process-local and not meaningfully comparable against a value returned
// from a netlink query).
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

// Handle bundles a loaded *prog.UsidObjects with a Healthy check
// (Milestone 4), so internal/installer's gRPC health-check handler can
// query datapath health without depending on prog.UsidObjects or this
// package's Health function directly -- and without needing to track the
// datapath's resolved interface set itself (Healthy re-resolves it fresh on
// every call, see below). Objs is exported so a caller that also needs the
// raw maps for something else (e.g. internal/plumbing/ebpf/metrics's
// Prometheus collector, also Milestone 4) can reach them without a second
// load.
type Handle struct {
	Objs *prog.UsidObjects

	// Watcher, if non-nil (StartWatching's return value in production),
	// is consulted by Healthy alongside Health's own program/map/filter
	// checks (ecv's review of #283):
	//   - a Watch loop that is no longer running (Watcher.Alive() ==
	//     false) can't self-heal drift on its own -- an externally
	//     cleared tc filter or a moved default route would otherwise sit
	//     unfixed indefinitely, since nothing else in this package
	//     restarts it -- so Healthy reports that as unhealthy even if
	//     Health's own checks currently pass;
	//   - a failing Health result nudges the watcher (Watcher.Reconcile)
	//     to re-evaluate before the next health-check tick, on the chance
	//     the failure is exactly the kind of drift Watch's own reconcile
	//     heals, rather than only ever healing via an unrelated netlink
	//     event or the liveness probe restarting the container.
	Watcher *Watcher
}

// Close releases this process's own BPF map/program file descriptors -- it
// does not detach the filter or unpin the maps (see the package doc
// comment for why that is safe).
func (h *Handle) Close() error {
	return h.Objs.Close()
}

// Healthy re-resolves the current interface set (the same auto-detect/
// override logic ResolveInterfaces always uses) and reports whether the
// datapath is still attached to it and its maps are reachable. Re-resolving
// fresh on every call, rather than reusing a cached set captured at
// startup, means a health probe reflects the datapath's *current* desired
// attachment state, consistent with Watch's own netlink-driven
// re-evaluation (Milestone 3.2) -- a transient ResolveInterfaces failure
// (e.g. no default route momentarily) is reported as unhealthy here too,
// which is the correct, if occasionally noisy, behavior for a liveness/
// readiness signal.
//
// If h.Watcher is set, a non-nil Health result nudges it (Watcher.
// Reconcile) before Healthy returns -- asynchronously and debounced by
// Watch's own debounceInterval, so this call still reports the failure it
// just observed, but the *next* Healthy call (one health-check interval
// later) may find the drift already self-healed instead of needing an
// unrelated netlink event or a full container restart to fix it (ecv's
// review of #283). Separately, and regardless of Health's own result, a
// dead watcher (h.Watcher.Alive() == false) is always reported as
// unhealthy: it can no longer react to anything, including this nudge.
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

// tcxQueryFn is a package-level override point, matching linkByNameFn and
// filterListFn above, so checkNotPreempted's tests need neither root nor a
// live interface with a foreign program on it.
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

// ownProgramIDs returns the kernel ids of this datapath's own programs, for
// checkNotPreempted to recognize itself by.
//
// By id rather than by name, because reading a name means opening the
// program by id, and BPF_PROG_GET_FD_BY_ID wants CAP_SYS_ADMIN or
// CAP_PERFMON. This container carries neither (it drops ALL and adds BPF,
// NET_ADMIN and NET_RAW), so that call returns EPERM here. An id needs no
// such privilege: it comes from BPF_OBJ_GET_INFO_BY_FD on a descriptor
// this process already holds.
//
// Getting this wrong is what made the first version of this check useless.
// It compared names, could not read them, and treated the failure as
// nothing to report -- so it sat inert on a node that genuinely was
// preempted.
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
// This must never reach the health service. Both the liveness and the
// readiness probe point at that one service, so anything reported through
// it restarts this container -- and a restart cannot remove another CNI's
// program from an interface. Wiring preemption into it produced a
// permanent crashloop: measured at six restarts in as many minutes on a
// node with a foreign program deliberately attached, each restart
// changing nothing about the condition that caused it.
//
// Every other check in Health is a condition a restart plausibly fixes,
// since restarting reloads the programs and re-attaches them. This one is
// not, so it belongs in the log next to the other things an operator reads
// rather than in the signal that decides whether this container lives.
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
// interfaces it owns exclusively.
//
// Being attached is not the same as being reached. This package attaches
// via clsact, and the kernel runs every tcx program on a hook before any
// clsact filter on it, so another CNI's tcx program on the same interface
// decides a packet's fate first. If it consumes or drops the packet,
// usid_egress is never invoked and every counter here reads a clean zero,
// because from this side nothing arrived. That is worth a check because it
// is invisible from every vantage point this codebase otherwise has:
// diagnosing one instance took kernel kfree_skb tracing, then bpftool to
// see a tcx link `tc filter show` cannot display, then the other CNI's own
// drop monitor to name the reason.
//
// Scoped to this datapath's own per-attachment interfaces -- the taps and
// veths carrying usid_egress -- and deliberately not to the shared uplinks
// usid_ingress attaches to. On an uplink another CNI is expected: it is
// that CNI's interface too, and this datapath's own receive classification
// happens on a bond's slaves rather than on the master a cluster CNI
// attaches to, so a tcx program there is not in the way of anything.
// Checking uplinks would report every node in a fleet unhealthy over the
// ordinary arrangement.
//
// Enumerating by filter rather than taking a caller-supplied list: an
// interface carrying this package's own usid_egress filter is by definition
// one this datapath owns, so the set defines itself and cannot drift out of
// step with what is actually attached.
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

// checkNotPreemptedOne reports whether anything precedes this datapath on
// one owned interface.
//
// Reported by program id, with a name only when one can be read. The id
// alone is enough to act on (`bpftool prog show id N` names it), and
// insisting on the name is what left the first version of this check
// unable to report anything at all -- see ownProgramIDs.
//
// A failure to look is logged rather than returned. This check is a
// diagnostic, and its own inability to run says nothing about whether the
// datapath is carrying traffic, so failing health on it would report the
// wrong thing. Logged, though, and not swallowed: silence that could mean
// either "nothing is wrong" or "this never ran" is what allowed an inert
// check to look identical to a passing one.
func checkNotPreemptedOne(l netlink.Link, own map[ebpf.ProgramID]struct{}) error {
	name := l.Attrs().Name

	ids, err := tcxQueryFn(l.Attrs().Index)
	if err != nil {
		if errors.Is(err, ebpf.ErrNotSupported) {
			// A kernel with no tcx cannot have a tcx program to be
			// preempted by, so there is nothing to report and nothing
			// to warn about either.
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
