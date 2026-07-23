// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package attach

import (
	"errors"
	"fmt"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"go.datum.net/galactic/internal/plumbing/ebpf/preflight"
	"go.datum.net/galactic/internal/plumbing/ebpf/prog"
)

// PinDir is the default bpffs directory every usid_ingress map is pinned
// under (design plan §4.4/§9: "All maps pinned under /sys/fs/bpf/galactic/
// so a control-daemon restart does not require the datapath to stop
// forwarding").
const PinDir = "/sys/fs/bpf/galactic"

// filterName and filterPriority identify this package's own TC-BPF ingress
// filter on an interface, so re-attachment (across a container restart, or
// Watch's netlink-driven re-attachment, Milestone 3.2) replaces the same
// filter instead of stacking a duplicate.
const (
	filterName     = "galactic_usid_ingress"
	filterPriority = 1
)

// preflightCheckFn is a package-level override point so tests can force the
// preflight failure path without touching the real kernel -- the same
// pattern preflight.CheckWith itself uses for Prober.
var preflightCheckFn = preflight.Check

// Start runs the kernel preflight check (blocking on failure -- design plan
// §6), loads and pins internal/plumbing/ebpf/prog's compiled usid_ingress
// object under pinDir, resolves the interface set per §4.1, and attaches
// the program to each resolved interface's ingress hook. On any failure the
// returned *prog.UsidObjects is nil and any partially-loaded kernel objects
// from this call are cleaned up -- there is no partial/unsafe fallback.
//
// On success, the caller owns the returned objects and the interfaces
// actually attached to; the objects should be kept open for the life of the
// process and Closed on shutdown (see the package doc comment for why that
// is safe).
func Start(pinDir string) (objs *prog.UsidObjects, ifaces []string, err error) {
	objs, err = Load(pinDir)
	if err != nil {
		return nil, nil, err
	}

	ifaces, err = ResolveInterfaces()
	if err != nil {
		_ = objs.Close()
		return nil, nil, fmt.Errorf("attach: resolve interfaces: %w", err)
	}

	if err := Attach(objs.UsidIngress, ifaces); err != nil {
		_ = objs.Close()
		return nil, nil, fmt.Errorf("attach: %w", err)
	}

	return objs, ifaces, nil
}

// Load runs the kernel preflight check (design plan §6, Milestone 2.3) and,
// only if it passes, loads internal/plumbing/ebpf/prog's compiled object
// with every map pinned under pinDir. A map already pinned there from a
// previous process is reused as-is (its contents survive); a map with no
// existing pin is created and pinned fresh. Load does not attach the
// program to any interface -- call Attach (or use Start) for that.
func Load(pinDir string) (objs *prog.UsidObjects, err error) {
	// loadHook observes every return path below (design plan §9's "BPF
	// program load/reload events and failures" metric; Milestone 4) via a
	// single defer over the named return, rather than a call at each
	// return statement -- so a future return path added here can't
	// accidentally forget to report itself.
	defer func() { loadHook(err) }()

	if err = preflightCheckFn(); err != nil {
		err = fmt.Errorf("attach: kernel preflight check failed, refusing to load the eBPF uSID datapath: %w", err)
		return nil, err
	}

	if err = rlimit.RemoveMemlock(); err != nil {
		err = fmt.Errorf("attach: remove memlock rlimit: %w", err)
		return nil, err
	}

	if err = os.MkdirAll(pinDir, 0o755); err != nil {
		err = fmt.Errorf("attach: create bpf map pin directory %q: %w", pinDir, err)
		return nil, err
	}

	spec, specErr := prog.LoadUsid()
	if specErr != nil {
		err = fmt.Errorf("attach: load compiled usid_ingress collection spec: %w", specErr)
		return nil, err
	}

	// Pin every map by name under pinDir (design plan §4.4: "All maps
	// pinned"). usid.c's map definitions don't set a BTF `pinning`
	// attribute themselves, so pinning is configured here at load time
	// instead -- see github.com/cilium/ebpf's Map.newMapWithOptions:
	// PinByName + MapOptions.PinPath together make LoadAndAssign reuse an
	// existing pin if one exists at <pinDir>/<map name>, rather than
	// always creating a fresh map.
	for _, m := range spec.Maps {
		m.Pinning = ebpf.PinByName
	}

	var loaded prog.UsidObjects
	opts := &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: pinDir},
	}
	if loadErr := spec.LoadAndAssign(&loaded, opts); loadErr != nil {
		var ve *ebpf.VerifierError
		if errors.As(loadErr, &ve) {
			detail := fmt.Sprintf("%+v", ve)
			err = fmt.Errorf("attach: verifier rejected usid_ingress program:\n%s: %w", detail, loadErr)
		} else {
			err = fmt.Errorf("attach: load and pin usid_ingress objects: %w", loadErr)
		}
		return nil, err
	}

	return &loaded, nil
}

// Attach attaches program to the ingress hook of each named interface via a
// clsact qdisc + direct-action BPF filter (design plan §4.1: "TC-BPF
// (clsact qdisc, ingress)"), creating the clsact qdisc if it doesn't
// already exist. Re-running Attach against an interface that already has
// this package's filter replaces it (github.com/vishvananda/netlink's
// FilterReplace) instead of stacking a duplicate, so repeated calls -- a
// container restart, or Watch's netlink-driven re-attachment (Milestone
// 3.2) -- are idempotent. Every interface is attempted even if one fails;
// all failures are joined and returned together.
func Attach(program *ebpf.Program, ifaceNames []string) error {
	if program == nil {
		return errors.New("attach: program is nil")
	}
	if len(ifaceNames) == 0 {
		return errors.New("attach: no interfaces to attach to")
	}

	var errs []error
	for _, name := range ifaceNames {
		if err := attachOne(program, name); err != nil {
			errs = append(errs, fmt.Errorf("interface %q: %w", name, err))
		}
	}
	return errors.Join(errs...)
}

// attachOne attaches program to one interface's ingress hook. It is the
// single internal choke point every attach path in this package goes
// through (Attach's loop below, and Watch's netlink-driven reconcile in
// watch.go), so instrumenting it here with attachHook (hooks.go, Milestone
// 4) observes every attach attempt regardless of caller.
func attachOne(program *ebpf.Program, name string) (err error) {
	defer func() { attachHook(name, err) }()

	link, err := netlink.LinkByName(name)
	if err != nil {
		err = fmt.Errorf("find link: %w", err)
		return err
	}

	if err = ensureClsact(link); err != nil {
		err = fmt.Errorf("ensure clsact qdisc: %w", err)
		return err
	}

	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_INGRESS,
			Handle:    netlink.MakeHandle(0, 1),
			Protocol:  unix.ETH_P_ALL,
			Priority:  filterPriority,
		},
		Fd:           program.FD(),
		Name:         filterName,
		DirectAction: true,
	}
	if err = netlink.FilterReplace(filter); err != nil {
		err = fmt.Errorf("attach tc-bpf ingress filter: %w", err)
		return err
	}
	return nil
}

// Detach removes this package's own TC-BPF ingress filter (identified by
// filterName) from each named interface, without touching the interface's
// clsact qdisc itself -- another filter, or a future Attach, may still need
// it. It is not an error for an interface to already lack the filter, or to
// no longer exist on the host at all (netlink.LinkNotFoundError): Watch
// (Milestone 3.2) calls Detach for interfaces that just dropped out of the
// resolved interface set, and by the time that runs the interface may
// already be gone entirely. Every interface is attempted even if one fails;
// all failures are joined and returned together, matching Attach's own
// all-attempted semantics.
func Detach(ifaceNames []string) error {
	var errs []error
	for _, name := range ifaceNames {
		if err := detachOne(name); err != nil {
			errs = append(errs, fmt.Errorf("interface %q: %w", name, err))
		}
	}
	return errors.Join(errs...)
}

// detachOne removes this package's own tc filter from one interface's
// ingress hook, if present. Like attachOne, it is the single internal
// choke point every detach path in this package goes through (Detach's
// loop below, called from Watch's netlink-driven reconcile), so
// instrumenting it here with detachHook (hooks.go, Milestone 4) observes
// every detach attempt regardless of caller.
func detachOne(name string) (err error) {
	defer func() { detachHook(name, err) }()

	link, err := netlink.LinkByName(name)
	if err != nil {
		var notFound netlink.LinkNotFoundError
		if errors.As(err, &notFound) {
			err = nil
			return nil
		}
		err = fmt.Errorf("find link: %w", err)
		return err
	}

	filters, listErr := netlink.FilterList(link, netlink.HANDLE_MIN_INGRESS)
	if listErr != nil {
		err = fmt.Errorf("list filters: %w", listErr)
		return err
	}
	for _, f := range filters {
		bpfFilter, ok := f.(*netlink.BpfFilter)
		if !ok || bpfFilter.Name != filterName {
			continue
		}
		if delErr := netlink.FilterDel(f); delErr != nil {
			err = fmt.Errorf("delete tc-bpf ingress filter: %w", delErr)
			return err
		}
	}
	return nil
}

// ensureClsact adds a clsact qdisc to link if one isn't already present.
func ensureClsact(link netlink.Link) error {
	qdiscs, err := netlink.QdiscList(link)
	if err != nil {
		return fmt.Errorf("list qdiscs: %w", err)
	}
	for _, q := range qdiscs {
		if _, ok := q.(*netlink.Clsact); ok {
			return nil
		}
	}

	qdisc := &netlink.Clsact{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
	}
	if err := netlink.QdiscAdd(qdisc); err != nil {
		return fmt.Errorf("add clsact qdisc: %w", err)
	}
	return nil
}
