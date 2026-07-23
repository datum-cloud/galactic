// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package attach

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
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
	link, err := linkByNameFn(name)
	if err != nil {
		return fmt.Errorf("find link: %w", err)
	}

	filters, err := filterListFn(link, netlink.HANDLE_MIN_INGRESS)
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
func (h *Handle) Healthy() error {
	ifaces, err := ResolveInterfaces()
	if err != nil {
		return fmt.Errorf("attach: health: resolve interfaces: %w", err)
	}
	return Health(h.Objs, ifaces)
}
