// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package attach

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"go.datum.net/galactic/internal/config"
	"go.datum.net/galactic/internal/plumbing/ebpf/mappin"
	"go.datum.net/galactic/internal/plumbing/ebpf/preflight"
	"go.datum.net/galactic/internal/plumbing/ebpf/prog"
)

// PinDir is the default bpffs directory every usid_ingress map is pinned under,
// so a control-daemon restart does not stop the datapath forwarding.
const PinDir = "/sys/fs/bpf/galactic"

// filterName identifies this package's TC-BPF ingress filter on an interface,
// so a re-attach replaces the same filter rather than stacking a duplicate.
const filterName = "galactic_usid_ingress"

// defaultFilterPriority is the tc priority attachOne uses when no override is
// set. Priority 1 is the highest tc allows, and has not been validated against
// another CNI's clsact priority on any particular version. Override it through
// the environment if it collides.
const defaultFilterPriority = 1

// filterPriorityFn resolves the tc priority attachOne attaches at. An override
// point so tests can exercise a non-default priority without setting a real
// environment variable.
var filterPriorityFn = resolveFilterPriority

// resolveFilterPriority returns the configured tc priority when the environment
// sets a valid uint16, and defaultFilterPriority otherwise.
func resolveFilterPriority() uint16 {
	if v := strings.TrimSpace(os.Getenv(config.EnvCNIEBPFFilterPriority)); v != "" {
		if parsed, err := strconv.ParseUint(v, 10, 16); err == nil {
			return uint16(parsed)
		}
		slog.Warn("attach: ignoring invalid filter priority override, using default",
			"env", config.EnvCNIEBPFFilterPriority, "value", v, "default", defaultFilterPriority)
	}
	return defaultFilterPriority
}

// preflightCheckFn is an override point so tests can force the preflight
// failure path without touching the real kernel.
var preflightCheckFn = preflight.Check

// Start runs the kernel preflight check, loads and pins the compiled
// usid_ingress object under pinDir, resolves the interface set, and attaches the
// program to each resolved interface's ingress hook. It returns the loaded
// objects and the interfaces actually attached to.
//
// A preflight failure blocks. On any failure the returned objects are nil and
// partially loaded kernel objects are cleaned up: there is no partial fallback.
//
// On success the caller owns the objects, which should stay open for the life of
// the process and be closed on shutdown.
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

	// Not fatal: an attachment left on the previous usid_egress still forwards,
	// only without what changed since. Failing startup would drop the ingress
	// datapath for the whole node over it.
	replaced, err := ReattachEgress(objs.UsidEgress)
	if err != nil {
		slog.Error("attach: could not move every attachment onto the new usid_egress; "+
			"those keep running the previous program and maps until their next CNI ADD",
			"replaced", replaced, "err", err)
	} else if replaced > 0 {
		slog.Info("attach: moved existing attachments onto the new usid_egress", "replaced", replaced)
	}

	return objs, ifaces, nil
}

// Load runs the kernel preflight check and, only if it passes, loads the
// compiled object with every map pinned under pinDir. A map already pinned there
// by a previous process is reused with its contents intact; one with no pin is
// created and pinned fresh. Load attaches nothing; call Attach or Start for
// that.
func Load(pinDir string) (objs *prog.UsidObjects, err error) {
	// A single defer over the named return observes every path below, so a
	// return added later cannot forget to report itself.
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

	// Pin every map by name under pinDir. The datapath's map definitions set
	// no BTF pinning attribute, so pinning is configured here at load time:
	// pin-by-name plus a pin path together make the load reuse an existing pin
	// when one is present rather than always creating a fresh map.
	for _, m := range spec.Maps {
		m.Pinning = ebpf.PinByName
	}

	var loaded prog.UsidObjects
	opts := &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: pinDir},
	}
	loadErr := spec.LoadAndAssign(&loaded, opts)
	if loadErr != nil && errors.Is(loadErr, ebpf.ErrMapIncompatible) {
		// A pin left by a previous version no longer matches the compiled map
		// spec, after a changed key size, value size or entry count, and
		// cannot be reused. Leaving this fatal would crashloop every node on
		// the first schema change until an operator deleted the pins by hand.
		//
		// Only the maps whose layout changed are recreated. Several maps here,
		// locator_table, function_table, vrf_table, ifindex_vrf_table and
		// ifindex_egress_kind_table among them, are written by CNI ADD alone.
		// Recreating them empties them on a compute node until every workload
		// re-attaches, which blackholes every attachment on the node. An
		// unchanged map keeps its rows.
		unpinned, unpinErr := mappin.UnpinIncompatible(spec, pinDir, nil)
		if unpinErr != nil {
			err = fmt.Errorf("attach: recreate incompatible pinned maps: %w", unpinErr)
			return nil, err
		}
		if len(unpinned) == 0 {
			err = fmt.Errorf("attach: load reported an incompatible map, but every pin under %s matches: %w",
				pinDir, loadErr)
			return nil, err
		}
		slog.Warn("attach: pinned eBPF maps incompatible with the newly compiled map spec, recreating them",
			"pinDir", pinDir, "maps", unpinned, "err", loadErr)
		if loadErr = spec.LoadAndAssign(&loaded, opts); loadErr != nil {
			loadErr = fmt.Errorf("after recreating %v: %w", unpinned, loadErr)
		}
	}
	if loadErr != nil {
		var ve *ebpf.VerifierError
		if errors.As(loadErr, &ve) {
			detail := fmt.Sprintf("%+v", ve)
			err = fmt.Errorf("attach: verifier rejected usid_ingress program:\n%s: %w", detail, loadErr)
		} else {
			err = fmt.Errorf("attach: load and pin usid_ingress objects: %w", loadErr)
		}
		return nil, err
	}

	// Pin usid_egress alongside the maps. usid_ingress is attached once per
	// node by this long-running process to a known interface, while usid_egress
	// attaches per attachment, at CNI ADD time, to an interface that does not
	// exist until that ADD creates it. The short-lived plugin process has no
	// other handle on this collection and loads the program by its pin.
	//
	// A stale pin is removed and replaced unconditionally: a program has no
	// persistent state to preserve, so there is no reuse-or-recreate decision
	// to make as there is for a map.
	egressPinPath := filepath.Join(pinDir, UsidEgressPinName)
	if rmErr := os.Remove(egressPinPath); rmErr != nil && !os.IsNotExist(rmErr) {
		err = fmt.Errorf("attach: remove stale usid_egress pin: %w", rmErr)
		return nil, err
	}
	if pinErr := loaded.UsidEgress.Pin(egressPinPath); pinErr != nil {
		err = fmt.Errorf("attach: pin usid_egress program: %w", pinErr)
		return nil, err
	}

	return &loaded, nil
}

// UsidEgressPinName is the bpffs filename usid_egress is pinned under, distinct
// from every map name in the same directory so the two can never collide.
const UsidEgressPinName = "usid_egress_prog"

// Attach attaches program to the ingress hook of each named interface, through a
// clsact qdisc and a direct-action BPF filter, creating the qdisc if it does not
// exist.
//
// Re-running against an interface that already carries this package's filter
// replaces it rather than stacking a duplicate, so repeated calls are
// idempotent. Every interface is attempted even if one fails, and the failures
// are joined and returned together.
func Attach(program *ebpf.Program, ifaceNames []string) error {
	if program == nil {
		return errors.New("attach: program is nil")
	}
	if len(ifaceNames) == 0 {
		return errors.New("attach: no interfaces to attach to")
	}

	var errs []error
	for _, name := range ifaceNames {
		if err := attachOne(program, name, filterName, netlink.HANDLE_MIN_INGRESS); err != nil {
			errs = append(errs, fmt.Errorf("interface %q: %w", name, err))
		}
	}
	return errors.Join(errs...)
}

// egressFilterName identifies usid_egress's TC-BPF ingress filter, so a
// re-attach replaces the same filter rather than stacking a duplicate. Its own
// constant even though the two programs never target the same interface:
// usid_ingress takes the shared uplink, usid_egress each tenant's host-side veth
// or tap.
const egressFilterName = "galactic_usid_egress"

// AttachEgress attaches program, usid_egress loaded from its pin, to ifaceName's
// ingress hook. That interface is the tenant's own host-side veth or tap, not
// the shared uplink usid_ingress uses, because that is where the tenant's egress
// traffic arrives.
//
// A thin wrapper around the same idempotency Attach provides, for one interface
// at a time, since each CNI ADD attaches only its own attachment's interface.
func AttachEgress(program *ebpf.Program, ifaceName string) error {
	if program == nil {
		return errors.New("attach: program is nil")
	}
	return attachOne(program, ifaceName, egressFilterName, netlink.HANDLE_MIN_INGRESS)
}

// attachOne attaches program to one interface's TC hook, named by
// tcFilterName and rooted at parent, either the ingress or egress handle. It is
// the choke point every attach path in this package goes through, so
// instrumenting it here observes every attempt whatever the caller.
func attachOne(program *ebpf.Program, name, tcFilterName string, parent uint32) (err error) {
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
			Parent:    parent,
			Handle:    netlink.MakeHandle(0, 1),
			Protocol:  unix.ETH_P_ALL,
			Priority:  filterPriorityFn(),
		},
		Fd:           program.FD(),
		Name:         tcFilterName,
		DirectAction: true,
	}
	if err = netlink.FilterReplace(filter); err != nil {
		err = fmt.Errorf("attach tc-bpf filter: %w", err)
		return err
	}
	return nil
}

// Detach removes this package's ingress filter from each named interface,
// leaving the clsact qdisc in place since another filter or a future attach may
// still need it.
//
// An interface that already lacks the filter, or no longer exists at all, is not
// an error: the watch loop detaches interfaces that just left the resolved set,
// by which time one may already be gone. Every interface is attempted even if
// one fails, and the failures are joined and returned together.
func Detach(ifaceNames []string) error {
	var errs []error
	for _, name := range ifaceNames {
		if err := detachOne(name, filterName, netlink.HANDLE_MIN_INGRESS); err != nil {
			errs = append(errs, fmt.Errorf("interface %q: %w", name, err))
		}
	}
	return errors.Join(errs...)
}

// detachOne removes the filter named tcFilterName from one interface's TC hook
// at parent, if present. Like attachOne it is the choke point every detach path
// goes through, so instrumenting it here observes every attempt whatever the
// caller. An interface that already lacks the filter, or no longer exists, is
// not an error.
func detachOne(name, tcFilterName string, parent uint32) (err error) {
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

	filters, listErr := netlink.FilterList(link, parent)
	if listErr != nil {
		err = fmt.Errorf("list filters: %w", listErr)
		return err
	}
	for _, f := range filters {
		bpfFilter, ok := f.(*netlink.BpfFilter)
		if !ok || bpfFilter.Name != tcFilterName {
			continue
		}
		if delErr := netlink.FilterDel(f); delErr != nil {
			err = fmt.Errorf("delete tc-bpf filter: %w", delErr)
			return err
		}
	}
	return nil
}

// qdiscListFn and qdiscAddFn are override points so ensureClsact's tests can
// simulate the concurrent-EEXIST race below without a live netlink socket or
// root.
var (
	qdiscListFn = netlink.QdiscList
	qdiscAddFn  = netlink.QdiscAdd
)

// ensureClsact adds a clsact qdisc to link if one is not already present.
//
// Listing then conditionally adding is inherently racy against any other agent
// doing the same to the same device, notably a cluster CNI ensuring its own
// clsact qdisc. If something else wins that race, the add returns EEXIST, which
// is the outcome this function wanted, so it is treated as success.
func ensureClsact(link netlink.Link) error {
	qdiscs, err := qdiscListFn(link)
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
	if err := qdiscAddFn(qdisc); err != nil && !errors.Is(err, unix.EEXIST) {
		return fmt.Errorf("add clsact qdisc: %w", err)
	}
	return nil
}
