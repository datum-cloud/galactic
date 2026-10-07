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
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"go.datum.net/galactic/internal/config"
	"go.datum.net/galactic/internal/plumbing/ebpf/attachmentidentity"
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

var (
	filterReplaceFn       = netlink.FilterReplace
	filterDeleteFn        = netlink.FilterDel
	programFromIDFn       = ebpf.NewProgramFromID
	snapshotEgressChainFn = snapshotEgressChain
	restoreEgressChainFn  = func(snapshot *egressChainSnapshot, ifaceName string) error {
		return snapshot.restore(ifaceName)
	}
	attachOneAtPriorityFn = func(program *ebpf.Program, name, ifaceName string, parent uint32,
		priority uint16, handle uint32) error {
		return attachOneAtPriority(program, ifaceName, name, parent, priority, handle)
	}
	withInterfaceLockFn         = withInterfaceLock
	withIdentityLockFn          = withIdentityLock
	validateEgressTargetSlotsFn = validateEgressTargetSlots
)

var localEgressAttachMu sync.Mutex

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
	// Close the service-policy gate before rotating any attachment identity.
	// The controller reopens it only after its cache-synchronized rebuild and
	// sweep. Doing this here, rather than waiting for that controller runnable,
	// prevents unchanged interfaces from continuing against the previous
	// generation while startup reattach rotates their peers one by one.
	if err := objs.ServicePolicyStateTable.Put(uint32(0), prog.UsidServicePolicyStateValue{}); err != nil {
		_ = objs.Close()
		return nil, nil, fmt.Errorf("attach: disable service policy before startup reattach: %w", err)
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

	// Reattach is readiness-fatal. After an incompatible policy-map rollout an
	// old classifier may reference the deliberately drained, unpinned map set;
	// reporting ready before every owned interface moves to this collection
	// would leave private services unavailable indefinitely.
	replaced, err := ReattachEgress(objs.UsidServiceEgress, objs.UsidEgress, objs.AttachmentIdentityTable)
	if err != nil {
		_ = objs.Close()
		return nil, nil, fmt.Errorf("attach: reattach service egress chain (replaced %d): %w", replaced, err)
	} else if replaced > 0 {
		slog.Info("attach: moved existing attachments onto the new service egress chain", "replaced", replaced)
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
		// An already-attached old classifier keeps map FDs after their pins
		// are removed. Revoke its service authorization before replacing any
		// incompatible pin so it cannot keep forwarding against an orphaned
		// policy generation if the subsequent reattach fails.
		if drainErr := drainLegacyServiceAuthorization(pinDir); drainErr != nil {
			err = fmt.Errorf("attach: revoke legacy service authorization before map replacement: %w", drainErr)
			return nil, err
		}
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
	serviceEgressPinPath := filepath.Join(pinDir, UsidServiceEgressPinName)
	if rmErr := os.Remove(serviceEgressPinPath); rmErr != nil && !os.IsNotExist(rmErr) {
		err = fmt.Errorf("attach: remove stale usid_service_egress pin: %w", rmErr)
		return nil, err
	}
	if pinErr := loaded.UsidServiceEgress.Pin(serviceEgressPinPath); pinErr != nil {
		err = fmt.Errorf("attach: pin usid_service_egress program: %w", pinErr)
		return nil, err
	}

	return &loaded, nil
}

// UsidEgressPinName is the bpffs filename usid_egress is pinned under, distinct
// from every map name in the same directory so the two can never collide.
const UsidEgressPinName = "usid_egress_prog"

// UsidServiceEgressPinName is the bpffs filename for the private-service
// classifier that runs immediately before usid_egress in the TC chain.
const UsidServiceEgressPinName = "usid_service_egress_prog"

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

const serviceEgressFilterName = "galactic_usid_service_egress"

// AttachEgress attaches program, usid_egress loaded from its pin, to ifaceName's
// ingress hook. That interface is the tenant's own host-side veth or tap, not
// the shared uplink usid_ingress uses, because that is where the tenant's egress
// traffic arrives.
//
// A thin wrapper around the same idempotency Attach provides, for one interface
// at a time, since each CNI ADD attaches only its own attachment's interface.
func AttachEgress(serviceProgram, legacyProgram *ebpf.Program, ifaceName string) error {
	localEgressAttachMu.Lock()
	defer localEgressAttachMu.Unlock()
	return attachEgressLocked(serviceProgram, legacyProgram, ifaceName)
}

// AttachEgressWithIdentity performs CNI ADD's identity decision and TC update
// under one cross-process interface lock. A genuinely idempotent ADD keeps its
// token only when the exact current two-program chain is already present;
// every new/reused interface incarnation rotates before a classifier can run.
func AttachEgressWithIdentity(serviceProgram, legacyProgram *ebpf.Program, identityMap *ebpf.Map,
	ifindex uint32, ifaceName string,
) error {
	return withIdentityLockFn(func() error {
		return withInterfaceLockFn(ifaceName, func() error {
			current, err := exactEgressChainCurrent(ifaceName, serviceProgram, legacyProgram)
			if err != nil {
				return err
			}
			var token uint64
			if err := identityMap.Lookup(ifindex, &token); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
				return fmt.Errorf("lookup attachment identity: %w", err)
			}
			if !current || token == 0 {
				if _, err := attachmentidentity.RotateMap(identityMap, ifindex); err != nil {
					return err
				}
			}
			return attachEgressLocked(serviceProgram, legacyProgram, ifaceName)
		})
	})
}

func withIdentityLock(fn func() error) error {
	return withInterfaceLock("attachment-identity-global", fn)
}

func exactEgressChainCurrent(ifaceName string, serviceProgram, legacyProgram *ebpf.Program) (bool, error) {
	serviceID, err := egressProgramID(serviceProgram, "usid_service_egress")
	if err != nil {
		return false, err
	}
	legacyID, err := egressProgramID(legacyProgram, "usid_egress")
	if err != nil {
		return false, err
	}
	link, err := linkByNameFn(ifaceName)
	if err != nil {
		return false, err
	}
	filters, err := filterListFn(link, netlink.HANDLE_MIN_INGRESS)
	if err != nil {
		return false, err
	}
	priority := filterPriorityFn()
	serviceMatches, legacyMatches, managed := 0, 0, 0
	for _, filter := range filters {
		bpfFilter, ok := filter.(*netlink.BpfFilter)
		if !ok || !isManagedEgressFilter(bpfFilter.Name) {
			continue
		}
		managed++
		if bpfFilter.Name == serviceEgressFilterName && uint32(bpfFilter.Id) == serviceID &&
			bpfFilter.Priority == priority && bpfFilter.Handle == netlink.MakeHandle(0, 1) {
			serviceMatches++
		}
		if bpfFilter.Name == egressFilterName && uint32(bpfFilter.Id) == legacyID &&
			bpfFilter.Priority == priority+1 && bpfFilter.Handle == netlink.MakeHandle(0, 2) {
			legacyMatches++
		}
	}
	return managed == 2 && serviceMatches == 1 && legacyMatches == 1, nil
}

func attachEgressLocked(serviceProgram, legacyProgram *ebpf.Program, ifaceName string) error {
	if serviceProgram == nil || legacyProgram == nil {
		return errors.New("attach: egress program is nil")
	}
	priority := filterPriorityFn()
	if priority == ^uint16(0) {
		return errors.New("attach: egress filter priority leaves no room for legacy continuation")
	}
	snapshot, err := snapshotEgressChainFn(ifaceName, priority)
	if err != nil {
		return fmt.Errorf("snapshot existing egress chain: %w", err)
	}
	defer snapshot.close()

	// Install the continuation first. During a legacy-only migration the old
	// priority slot remains the active program until the final replace, so a
	// failure here cannot interrupt forwarding.
	if err := validateEgressTargetSlotsFn(ifaceName, priority); err != nil {
		return err
	}
	if err := attachOneAtPriorityFn(legacyProgram, egressFilterName, ifaceName,
		netlink.HANDLE_MIN_INGRESS, priority+1, netlink.MakeHandle(0, 2)); err != nil {
		// A netlink error does not prove the kernel rejected the mutation (for
		// example, the request may have committed before an acknowledgement was
		// lost). Restore even this make-before-break step so every failure path
		// converges on the exact snapshot.
		restoreErr := restoreEgressChainFn(snapshot, ifaceName)
		return errors.Join(fmt.Errorf("legacy continuation: %w", err), restoreErr)
	}
	if err := validateEgressTargetSlotsFn(ifaceName, priority); err != nil {
		restoreErr := restoreEgressChainFn(snapshot, ifaceName)
		return errors.Join(err, restoreErr)
	}
	if err := attachOneAtPriorityFn(serviceProgram, serviceEgressFilterName, ifaceName,
		netlink.HANDLE_MIN_INGRESS, priority, netlink.MakeHandle(0, 1)); err != nil {
		restoreErr := restoreEgressChainFn(snapshot, ifaceName)
		return errors.Join(fmt.Errorf("service classifier: %w", err), restoreErr)
	}
	if err := removeDuplicateManagedEgressFilters(ifaceName, priority); err != nil {
		return fmt.Errorf("remove duplicate egress filters: %w", err)
	}
	return nil
}

func withInterfaceLock(ifaceName string, fn func() error) error {
	const lockDir = "/run/galactic"
	if err := os.MkdirAll(lockDir, 0o755); err != nil {
		return fmt.Errorf("attach: create interface lock directory: %w", err)
	}
	lockPath := filepath.Join(lockDir, "tc-"+filepath.Base(ifaceName)+".lock")
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("attach: open interface lock: %w", err)
	}
	defer func() { _ = f.Close() }()
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX); err != nil {
		return fmt.Errorf("attach: lock interface: %w", err)
	}
	defer func() { _ = unix.Flock(int(f.Fd()), unix.LOCK_UN) }()
	return fn()
}

func validateEgressTargetSlots(ifaceName string, priority uint16) error {
	link, err := linkByNameFn(ifaceName)
	if err != nil {
		return fmt.Errorf("revalidate target slots: find link: %w", err)
	}
	filters, err := filterListFn(link, netlink.HANDLE_MIN_INGRESS)
	if err != nil {
		return fmt.Errorf("revalidate target slots: list filters: %w", err)
	}
	for _, filter := range filters {
		if !isEgressTargetSlot(filter.Attrs(), priority) {
			continue
		}
		bpfFilter, ok := filter.(*netlink.BpfFilter)
		if !ok || !allowedEgressSlotOwner(bpfFilter, priority) {
			return fmt.Errorf("target priority=%d handle=%#x became occupied by a foreign tc filter",
				filter.Attrs().Priority, filter.Attrs().Handle)
		}
	}
	return nil
}

func removeDuplicateManagedEgressFilters(ifaceName string, priority uint16) error {
	link, err := linkByNameFn(ifaceName)
	if err != nil {
		return err
	}
	filters, err := filterListFn(link, netlink.HANDLE_MIN_INGRESS)
	if err != nil {
		return err
	}
	var errs []error
	for _, filter := range filters {
		bpfFilter, ok := filter.(*netlink.BpfFilter)
		if !ok || !isManagedEgressFilter(bpfFilter.Name) {
			continue
		}
		wanted := bpfFilter.Name == serviceEgressFilterName && bpfFilter.Priority == priority &&
			bpfFilter.Handle == netlink.MakeHandle(0, 1) ||
			bpfFilter.Name == egressFilterName && bpfFilter.Priority == priority+1 &&
				bpfFilter.Handle == netlink.MakeHandle(0, 2)
		if !wanted {
			errs = append(errs, filterDeleteFn(filter))
		}
	}
	return errors.Join(errs...)
}

type egressFilterSnapshot struct {
	program  *ebpf.Program
	name     string
	priority uint16
	handle   uint32
}

type egressChainSnapshot struct {
	filters []egressFilterSnapshot
}

func snapshotEgressChain(ifaceName string, priority uint16) (*egressChainSnapshot, error) {
	link, err := linkByNameFn(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("find link: %w", err)
	}
	filters, err := filterListFn(link, netlink.HANDLE_MIN_INGRESS)
	if err != nil {
		return nil, fmt.Errorf("list filters: %w", err)
	}
	snapshot := &egressChainSnapshot{}
	for _, filter := range filters {
		attrs := filter.Attrs()
		bpfFilter, ok := filter.(*netlink.BpfFilter)
		if isEgressTargetSlot(attrs, priority) && (!ok || !allowedEgressSlotOwner(bpfFilter, priority)) {
			snapshot.close()
			return nil, fmt.Errorf("target priority=%d handle=%#x is occupied by a foreign tc filter",
				attrs.Priority, attrs.Handle)
		}
		if !ok || (bpfFilter.Name != egressFilterName && bpfFilter.Name != serviceEgressFilterName) {
			continue
		}
		program, err := programFromIDFn(ebpf.ProgramID(bpfFilter.Id))
		if err != nil {
			snapshot.close()
			return nil, fmt.Errorf("open prior program %d for %s: %w", bpfFilter.Id, bpfFilter.Name, err)
		}
		snapshot.filters = append(snapshot.filters, egressFilterSnapshot{
			program: program, name: bpfFilter.Name, priority: bpfFilter.Priority, handle: bpfFilter.Handle,
		})
	}
	return snapshot, nil
}

func isEgressTargetSlot(attrs *netlink.FilterAttrs, priority uint16) bool {
	return (attrs.Priority == priority && attrs.Handle == netlink.MakeHandle(0, 1)) ||
		(attrs.Priority == priority+1 && attrs.Handle == netlink.MakeHandle(0, 2))
}

func allowedEgressSlotOwner(filter *netlink.BpfFilter, priority uint16) bool {
	if filter.Priority == priority && filter.Handle == netlink.MakeHandle(0, 1) {
		return filter.Name == serviceEgressFilterName || filter.Name == egressFilterName
	}
	return filter.Priority == priority+1 && filter.Handle == netlink.MakeHandle(0, 2) &&
		filter.Name == egressFilterName
}

func (s *egressChainSnapshot) close() {
	for _, filter := range s.filters {
		_ = filter.program.Close()
	}
}

func (s *egressChainSnapshot) restore(ifaceName string) error {
	var errs []error
	// Put the old filters back before removing anything. In the legacy-only
	// migration this restores the old first-stage filter while the newly added
	// continuation still exists, so rollback never deliberately creates an
	// interval with no working egress program.
	for _, filter := range s.filters {
		if err := attachOneAtPriorityFn(filter.program, filter.name, ifaceName, netlink.HANDLE_MIN_INGRESS,
			filter.priority, filter.handle); err != nil {
			errs = append(errs, fmt.Errorf("restore %s: %w", filter.name, err))
		}
	}

	link, err := linkByNameFn(ifaceName)
	if err != nil {
		errs = append(errs, fmt.Errorf("find link while removing new filters: %w", err))
	} else {
		filters, listErr := filterListFn(link, netlink.HANDLE_MIN_INGRESS)
		if listErr != nil {
			errs = append(errs, fmt.Errorf("list filters while removing new filters: %w", listErr))
		} else {
			for _, current := range filters {
				bpfFilter, ok := current.(*netlink.BpfFilter)
				if !ok || !isManagedEgressFilter(bpfFilter.Name) || s.contains(bpfFilter) {
					continue
				}
				if err := filterDeleteFn(current); err != nil {
					errs = append(errs, fmt.Errorf("remove newly installed %s: %w", bpfFilter.Name, err))
				}
			}
		}
	}
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("restore prior egress chain: %w", err)
	}
	return nil
}

func (s *egressChainSnapshot) contains(filter *netlink.BpfFilter) bool {
	for _, saved := range s.filters {
		if saved.name == filter.Name && saved.priority == filter.Priority && saved.handle == filter.Handle {
			return true
		}
	}
	return false
}

func isManagedEgressFilter(name string) bool {
	return name == egressFilterName || name == serviceEgressFilterName
}

// attachOne attaches program to one interface's TC hook, named by
// tcFilterName and rooted at parent, either the ingress or egress handle. It is
// the choke point every attach path in this package goes through, so
// instrumenting it here observes every attempt whatever the caller.
func attachOne(program *ebpf.Program, name, tcFilterName string, parent uint32) (err error) {
	return attachOneAtPriority(program, name, tcFilterName, parent, filterPriorityFn(), netlink.MakeHandle(0, 1))
}

func attachOneAtPriority(program *ebpf.Program, name, tcFilterName string, parent uint32,
	priority uint16, handle uint32) (err error) {
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
			Handle:    handle,
			Protocol:  unix.ETH_P_ALL,
			Priority:  priority,
		},
		Fd:           program.FD(),
		Name:         tcFilterName,
		DirectAction: true,
	}
	if err = filterReplaceFn(filter); err != nil {
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
		if delErr := filterDeleteFn(f); delErr != nil {
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
