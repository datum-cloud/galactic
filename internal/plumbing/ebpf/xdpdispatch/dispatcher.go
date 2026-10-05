// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package xdpdispatch

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// PinDir is the bpffs directory every datapath sharing the XDP hook pins its
// dispatch state under. It belongs to neither datapath.
const PinDir = "/sys/fs/bpf/galactic-xdp"

// ABIVersion names the map layout dispatch.h defines. It is also the name of
// the directory those maps are pinned in, so a new layout never shares a pin
// with an old one.
const ABIVersion = 1

// RootRevision is this build's revision of xdp_dispatch. Raise it whenever
// dispatch.c or dispatch_from changes without a new ABIVersion. A process
// carrying a higher revision than the pinned root replaces the root on every
// link.
const RootRevision = 1

// Lease timing. The TTL is long enough to cover a restart that pulls a new
// image, and short enough that a removed datapath stops claiming packets
// within minutes.
const (
	LeaseTTL     = 120 * time.Second
	LeaseRenewal = 10 * time.Second
)

// Slot is a position in dispatch_progs. Slots run in index order.
type Slot uint32

// The slots, mirroring XDPD_SLOT_* in dispatch.h. Numbering is ABI: a slot is
// appended, never renumbered.
const (
	SlotGatewayLB     Slot = 0
	SlotGatewayReturn Slot = 1
	SlotNAT           Slot = 2

	// NumSlots is dispatch_progs' size, XDPD_MAX_SLOTS.
	NumSlots = 8
)

// Role is a set of role bits for one interface. Bit N lets slot N run there.
type Role uint32

// The roles, mirroring XDPD_ROLE_* in dispatch.h.
const (
	RolePublicLB       Role = 1 << SlotGatewayLB
	RoleInternalReturn Role = 1 << SlotGatewayReturn
	RoleEgress         Role = 1 << SlotNAT
)

// Errors a caller can tell apart.
var (
	// ErrForeignProgram means another XDP program, not this node's root,
	// holds the interface. It is never replaced.
	ErrForeignProgram = errors.New("xdpdispatch: interface is held by an XDP program that is not the dispatcher")
	// ErrRoleConflict means a role would let the return program run on a
	// public interface.
	ErrRoleConflict = errors.New("xdpdispatch: the internal return role cannot share an interface with the public role")
	// ErrIncompatibleLayout means the pinned maps do not match this build's
	// layout for the same ABIVersion. Recreating them would empty every
	// datapath's slot, so this is fatal.
	ErrIncompatibleLayout = errors.New("xdpdispatch: pinned dispatch maps do not match this build's layout")
)

// Reasons Coverage reports an interface as uncovered.
var (
	ErrNoLink       = errors.New("no dispatcher link is pinned for the interface")
	ErrLinkDefunct  = errors.New("the dispatcher link's interface is gone")
	ErrNotRoot      = errors.New("the pinned link runs a program other than the pinned root")
	ErrRoleMissing  = errors.New("the interface does not carry the slot's role")
	ErrSlotNotHeld  = errors.New("the slot does not hold this program")
	ErrLeaseExpired = errors.New("the slot's lease has expired")
)

var (
	errInvalidSlot = errors.New("xdpdispatch: slot out of range")
	errNilProgram  = errors.New("xdpdispatch: program is nil")
)

// dispatch_meta keys.
const (
	metaKeyABI      = uint32(0)
	metaKeyRevision = uint32(1)
)

// Pin layout under the dispatch directory.
var (
	abiDirName        = "v" + strconv.Itoa(ABIVersion)
	linksDirName      = "links"
	rootPinName       = "root"
	rootStagedPinName = "root_next" // bpffs reserves names containing a dot
)

// Override points for tests.
var (
	linkByIndexFn  = netlink.LinkByIndex
	attachXDPFn    = link.AttachXDP
	monotonicNowFn = monotonicNow
)

// Dispatcher is an open handle on a node's pinned dispatch state. Closing it
// closes this process's descriptors only; everything pinned stays.
//
// A Dispatcher holds no root program of its own. Every call that needs the
// root reads it from its pin, so a process started before a newer root was
// pinned follows that root instead of moving links back to the one it loaded.
type Dispatcher struct {
	dir  string
	maps DispatchMaps
}

// Open loads the dispatch state pinned under dir, creating it on first use,
// and makes sure the pinned root is at least this build's revision. When this
// build's root is newer, Open pins it and moves every pinned link to it with a
// link update. Only Open replaces the pinned root.
//
// Open takes the dispatch lock itself, waiting until ctx is done, so the
// caller must not hold it.
func Open(ctx context.Context, dir string) (*Dispatcher, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("xdpdispatch: remove memlock rlimit: %w", err)
	}
	for _, sub := range []string{abiDirName, linksDirName} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o755); err != nil {
			return nil, fmt.Errorf("xdpdispatch: create pin directory: %w", err)
		}
	}

	unlock, err := lockDir(ctx, dir)
	if err != nil {
		return nil, err
	}
	defer unlock()

	spec, err := LoadDispatch()
	if err != nil {
		return nil, fmt.Errorf("xdpdispatch: load compiled dispatch spec: %w", err)
	}
	for _, m := range spec.Maps {
		m.Pinning = ebpf.PinByName
	}

	var objs DispatchObjects
	opts := &ebpf.CollectionOptions{Maps: ebpf.MapOptions{PinPath: filepath.Join(dir, abiDirName)}}
	if err := spec.LoadAndAssign(&objs, opts); err != nil {
		if errors.Is(err, ebpf.ErrMapIncompatible) {
			return nil, fmt.Errorf("%w: %w", ErrIncompatibleLayout, err)
		}
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			return nil, fmt.Errorf("xdpdispatch: verifier rejected xdp_dispatch:\n%w", ve)
		}
		return nil, fmt.Errorf("xdpdispatch: load and pin dispatch objects: %w", err)
	}
	// The pin, when adoptRoot makes one, keeps the program alive.
	defer objs.XdpDispatch.Close() //nolint:errcheck // our own descriptor

	d := &Dispatcher{dir: dir, maps: objs.DispatchMaps}
	if err := d.adoptRoot(objs.XdpDispatch); err != nil {
		_ = d.maps.Close()
		return nil, err
	}
	return d, nil
}

// adoptRoot pins ours as the node's root when the pinned root is older or
// missing, and moves every link to it. It records the ABI on first use and
// refuses a mismatch. The revision is recorded only once every link has moved,
// so a failed move is retried by the next Open.
func (d *Dispatcher) adoptRoot(ours *ebpf.Program) error {
	var abi uint64
	if err := d.maps.DispatchMeta.Lookup(metaKeyABI, &abi); err != nil {
		return fmt.Errorf("xdpdispatch: read dispatch ABI: %w", err)
	}
	switch abi {
	case 0:
		if err := d.maps.DispatchMeta.Put(metaKeyABI, uint64(ABIVersion)); err != nil {
			return fmt.Errorf("xdpdispatch: record dispatch ABI: %w", err)
		}
	case ABIVersion:
	default:
		return fmt.Errorf("%w: pinned ABI %d, this build %d", ErrIncompatibleLayout, abi, ABIVersion)
	}

	var pinnedRev uint64
	if err := d.maps.DispatchMeta.Lookup(metaKeyRevision, &pinnedRev); err != nil {
		return fmt.Errorf("xdpdispatch: read root revision: %w", err)
	}
	if pinnedRev >= RootRevision {
		if _, err := os.Stat(d.rootPath()); err == nil {
			return nil
		}
	}

	// Pin under a staging name and rename over the old pin, so the root path
	// always names a program.
	staged := filepath.Join(d.dir, abiDirName, rootStagedPinName)
	_ = os.Remove(staged)
	if err := ours.Pin(staged); err != nil {
		return fmt.Errorf("xdpdispatch: pin root: %w", err)
	}
	if err := os.Rename(staged, d.rootPath()); err != nil {
		_ = ours.Unpin()
		return fmt.Errorf("xdpdispatch: install pinned root: %w", err)
	}
	if err := d.updateLinks(ours); err != nil {
		return err
	}
	if err := d.maps.DispatchMeta.Put(metaKeyRevision, uint64(RootRevision)); err != nil {
		return fmt.Errorf("xdpdispatch: record root revision: %w", err)
	}
	return nil
}

// updateLinks moves every live pinned link to root.
func (d *Dispatcher) updateLinks(root *ebpf.Program) error {
	entries, err := os.ReadDir(filepath.Join(d.dir, linksDirName))
	if err != nil {
		return fmt.Errorf("xdpdispatch: list pinned links: %w", err)
	}
	var errs []error
	for _, e := range entries {
		l, err := link.LoadPinnedLink(filepath.Join(d.dir, linksDirName, e.Name()), nil)
		if err != nil {
			errs = append(errs, fmt.Errorf("load pinned link %q: %w", e.Name(), err))
			continue
		}
		if err := l.Update(root); err != nil {
			errs = append(errs, fmt.Errorf("move link %q to the new root: %w", e.Name(), err))
		}
		_ = l.Close()
	}
	if len(errs) > 0 {
		return fmt.Errorf("xdpdispatch: update pinned links: %w", errors.Join(errs...))
	}
	return nil
}

// Close closes this process's descriptors. Pinned state is untouched.
func (d *Dispatcher) Close() error {
	return d.maps.Close()
}

// Maps returns the pinned dispatch maps, for a datapath whose own programs
// include dispatch.h and must be loaded against them
// (CollectionOptions.MapReplacements).
func (d *Dispatcher) Maps() map[string]*ebpf.Map {
	return map[string]*ebpf.Map{
		"dispatch_progs": d.maps.DispatchProgs,
		"iface_roles":    d.maps.IfaceRoles,
		"slot_lease":     d.maps.SlotLease,
	}
}

func (d *Dispatcher) rootPath() string {
	return filepath.Join(d.dir, abiDirName, rootPinName)
}

// loadRoot opens the pinned root. The caller closes it.
func (d *Dispatcher) loadRoot() (*ebpf.Program, error) {
	root, err := ebpf.LoadPinnedProgram(d.rootPath(), nil)
	if err != nil {
		return nil, fmt.Errorf("xdpdispatch: load pinned root: %w", err)
	}
	return root, nil
}

// RootID returns the ID of the root program currently pinned.
func (d *Dispatcher) RootID() (ebpf.ProgramID, error) {
	root, err := d.loadRoot()
	if err != nil {
		return 0, err
	}
	defer root.Close() //nolint:errcheck // our own descriptor
	return programID(root)
}

func (d *Dispatcher) linkPath(ifindex int) string {
	return filepath.Join(d.dir, linksDirName, strconv.Itoa(ifindex))
}

// Locked is the dispatch lock, held. Every call that changes shared state
// other than a datapath's own slot program or lease is a method here, so it
// cannot run without the lock. Release it with Unlock.
type Locked struct {
	d      *Dispatcher
	unlock func()
}

// Lock takes the node-wide dispatch lock, an flock on the pin directory,
// waiting while another holder has it, until ctx is done. Each call opens its
// own descriptor, so it also excludes other goroutines of this process: a
// goroutine that calls Lock again before Unlock blocks on itself.
//
// Hold it across EnsureLink and, when EnsureLink bounced the interface, the
// wait for a bond member to rejoin, so two processes never bounce two members
// of one bond at once.
func (d *Dispatcher) Lock(ctx context.Context) (*Locked, error) {
	unlock, err := lockDir(ctx, d.dir)
	if err != nil {
		return nil, err
	}
	return &Locked{d: d, unlock: unlock}, nil
}

// Unlock releases the lock. Calling it again does nothing.
func (l *Locked) Unlock() {
	if l.unlock != nil {
		l.unlock()
		l.unlock = nil
	}
}

// EnsureLink makes sure the pinned root is attached to ifindex through a
// pinned link. bounced reports whether this call attached it, which on most
// drivers resets the interface; the caller then waits for a bond member to
// rejoin. A link running an older root is moved to the pinned one. A pinned
// link whose interface is gone is released and replaced. An interface held by
// any other XDP program returns ErrForeignProgram and is left alone.
//
// A link is defunct when the kernel reports its interface index as 0, which it
// does once the interface is unregistered. Interface indexes are not reused
// until the counter wraps, so a pin named for one interface never matches a
// different one.
func (l *Locked) EnsureLink(ifindex int) (bounced bool, err error) {
	d := l.d
	root, err := d.loadRoot()
	if err != nil {
		return false, err
	}
	defer root.Close() //nolint:errcheck // our own descriptor
	rootID, err := programID(root)
	if err != nil {
		return false, err
	}

	path := d.linkPath(ifindex)
	if pinned, err := link.LoadPinnedLink(path, nil); err == nil {
		defer pinned.Close() //nolint:errcheck // our own descriptor; the pin keeps the link
		info, err := pinned.Info()
		if err != nil {
			return false, fmt.Errorf("xdpdispatch: read link info for ifindex %d: %w", ifindex, err)
		}
		if xdp := info.XDP(); xdp != nil && int(xdp.Ifindex) == ifindex {
			if info.Program != rootID {
				if err := pinned.Update(root); err != nil {
					return false, fmt.Errorf("xdpdispatch: move ifindex %d to the pinned root: %w", ifindex, err)
				}
			}
			return false, nil
		}
		if err := pinned.Unpin(); err != nil {
			return false, fmt.Errorf("xdpdispatch: unpin defunct link for ifindex %d: %w", ifindex, err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, fmt.Errorf("xdpdispatch: load pinned link for ifindex %d: %w", ifindex, err)
	}

	nl, err := linkByIndexFn(ifindex)
	if err != nil {
		return false, fmt.Errorf("xdpdispatch: find interface %d: %w", ifindex, err)
	}
	if xdp := nl.Attrs().Xdp; xdp != nil && xdp.Attached {
		return false, fmt.Errorf("%w: %s (ifindex %d) runs XDP program %d",
			ErrForeignProgram, nl.Attrs().Name, ifindex, xdp.ProgId)
	}

	attached, err := attachXDPFn(link.XDPOptions{Program: root, Interface: ifindex, Flags: link.XDPDriverMode})
	if err != nil {
		return false, fmt.Errorf("xdpdispatch: attach dispatcher to %s in native/driver mode: %w",
			nl.Attrs().Name, err)
	}
	defer attached.Close() //nolint:errcheck // our own descriptor; the pin keeps the link
	if err := attached.Pin(path); err != nil {
		return true, fmt.Errorf("xdpdispatch: pin link for %s: %w", nl.Attrs().Name, err)
	}
	return true, nil
}

// Release detaches the root from ifindex and removes its pin and role row.
// Every datapath on the interface stops seeing its traffic at once, so this is
// for an interface no datapath uses any more, or for an operator returning the
// hook to a non-dispatching program. It is a no-op when nothing is pinned.
func (l *Locked) Release(ifindex int) error {
	pinned, err := link.LoadPinnedLink(l.d.linkPath(ifindex), nil)
	if errors.Is(err, os.ErrNotExist) {
		return l.ClearRoles(ifindex)
	}
	if err != nil {
		return fmt.Errorf("xdpdispatch: load pinned link for ifindex %d: %w", ifindex, err)
	}
	defer pinned.Close() //nolint:errcheck // our own descriptor
	var errs []error
	if err := pinned.Detach(); err != nil && !errors.Is(err, unix.ENOLINK) {
		errs = append(errs, fmt.Errorf("detach: %w", err))
	}
	if err := pinned.Unpin(); err != nil {
		errs = append(errs, fmt.Errorf("unpin: %w", err))
	}
	if err := l.ClearRoles(ifindex); err != nil {
		errs = append(errs, err)
	}
	if len(errs) > 0 {
		return fmt.Errorf("xdpdispatch: release ifindex %d: %w", ifindex, errors.Join(errs...))
	}
	return nil
}

// PruneDefunct releases every pinned link whose interface is gone and drops
// its role row. It returns the ifindexes it pruned.
func (l *Locked) PruneDefunct() ([]int, error) {
	d := l.d
	entries, err := os.ReadDir(filepath.Join(d.dir, linksDirName))
	if err != nil {
		return nil, fmt.Errorf("xdpdispatch: list pinned links: %w", err)
	}
	var (
		pruned []int
		errs   []error
	)
	for _, e := range entries {
		ifindex, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		pinned, err := link.LoadPinnedLink(filepath.Join(d.dir, linksDirName, e.Name()), nil)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		info, err := pinned.Info()
		if err == nil {
			if xdp := info.XDP(); xdp == nil || int(xdp.Ifindex) != ifindex {
				err = errors.Join(pinned.Unpin(), l.ClearRoles(ifindex))
				if err == nil {
					pruned = append(pruned, ifindex)
				}
			}
		}
		if err != nil {
			errs = append(errs, err)
		}
		_ = pinned.Close()
	}
	if len(errs) > 0 {
		return pruned, fmt.Errorf("xdpdispatch: prune defunct links: %w", errors.Join(errs...))
	}
	return pruned, nil
}

// SetRole adds role to ifindex's role bits. A role that would put the return
// program on a public interface returns ErrRoleConflict. The read and write
// are one step under the lock, so two datapaths adding their bits to one
// interface never lose either.
func (l *Locked) SetRole(ifindex int, role Role) error {
	cur, err := l.d.Roles(ifindex)
	if err != nil {
		return err
	}
	next := cur | role
	if next&RolePublicLB != 0 && next&RoleInternalReturn != 0 {
		return fmt.Errorf("%w (ifindex %d)", ErrRoleConflict, ifindex)
	}
	if next == cur {
		return nil
	}
	return l.d.writeRoles(ifindex, next)
}

// RemoveRole drops role from ifindex's role bits and keeps the rest, so a
// datapath can give up an interface without touching the other's bits. The
// row goes when no bit is left.
func (l *Locked) RemoveRole(ifindex int, role Role) error {
	cur, err := l.d.Roles(ifindex)
	if err != nil {
		return err
	}
	next := cur &^ role
	switch next {
	case cur:
		return nil
	case 0:
		return l.ClearRoles(ifindex)
	default:
		return l.d.writeRoles(ifindex, next)
	}
}

// ClearRoles drops ifindex's whole role row, every datapath's bits. It is for
// an interface that is gone.
func (l *Locked) ClearRoles(ifindex int) error {
	err := l.d.maps.IfaceRoles.Delete(uint32(ifindex))
	if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("xdpdispatch: clear roles for ifindex %d: %w", ifindex, err)
	}
	return nil
}

func (d *Dispatcher) writeRoles(ifindex int, roles Role) error {
	if err := d.maps.IfaceRoles.Put(uint32(ifindex), uint32(roles)); err != nil {
		return fmt.Errorf("xdpdispatch: write roles for ifindex %d: %w", ifindex, err)
	}
	return nil
}

// Roles returns ifindex's role bits, zero when it has none.
func (d *Dispatcher) Roles(ifindex int) (Role, error) {
	var cur uint32
	err := d.maps.IfaceRoles.Lookup(uint32(ifindex), &cur)
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("xdpdispatch: read roles for ifindex %d: %w", ifindex, err)
	}
	return Role(cur), nil
}

// Fill puts program in slot, replacing whatever the slot held, and renews the
// slot's lease, so the slot runs from the moment it is filled. The kernel swaps
// the program atomically, so a restarted datapath takes over its slot with no
// packet missing it. The program must be an XDP program with the default
// attach type and no frags support, like the root.
func (d *Dispatcher) Fill(slot Slot, program *ebpf.Program) error {
	if slot >= NumSlots {
		return errInvalidSlot
	}
	if program == nil {
		return errNilProgram
	}
	if err := d.maps.DispatchProgs.Put(uint32(slot), program); err != nil {
		return fmt.Errorf("xdpdispatch: fill slot %d "+
			"(EINVAL here means the program is incompatible with the root): %w", slot, err)
	}
	return d.Renew(slot)
}

// Clear empties slot whatever it holds and expires its lease, so its traffic
// passes straight to the later slots. It is for turning a datapath off. A
// process shutting down uses ClearIfHeld instead, so it never empties a slot
// its replacement has already filled.
func (l *Locked) Clear(slot Slot) error {
	if slot >= NumSlots {
		return errInvalidSlot
	}
	err := l.d.maps.DispatchProgs.Delete(uint32(slot))
	if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("xdpdispatch: clear slot %d: %w", slot, err)
	}
	return l.d.setLease(slot, 0)
}

// ClearIfHeld clears slot only while it holds program. It reports whether it
// cleared it.
func (l *Locked) ClearIfHeld(slot Slot, program *ebpf.Program) (bool, error) {
	if slot >= NumSlots {
		return false, errInvalidSlot
	}
	held, err := l.d.holds(slot, program)
	if err != nil || !held {
		return false, err
	}
	return true, l.Clear(slot)
}

// holds reports whether slot holds program.
func (d *Dispatcher) holds(slot Slot, program *ebpf.Program) (bool, error) {
	want, err := programID(program)
	if err != nil {
		return false, err
	}
	var got uint32
	if err := d.maps.DispatchProgs.Lookup(uint32(slot), &got); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("xdpdispatch: read slot %d: %w", slot, err)
	}
	return ebpf.ProgramID(got) == want, nil
}

// Renew extends slot's lease to LeaseTTL from now. A slot's owner calls it
// without the lock: the lease is the owner's alone, written in one update.
func (d *Dispatcher) Renew(slot Slot) error {
	return d.setLease(slot, monotonicNowFn()+uint64(LeaseTTL))
}

func (d *Dispatcher) setLease(slot Slot, expiry uint64) error {
	if slot >= NumSlots {
		return errInvalidSlot
	}
	if err := d.maps.SlotLease.Put(uint32(slot), expiry); err != nil {
		return fmt.Errorf("xdpdispatch: write lease for slot %d: %w", slot, err)
	}
	return nil
}

// LiveSlots returns every slot holding a program whose lease is live.
func (d *Dispatcher) LiveSlots() ([]Slot, error) {
	now := monotonicNowFn()
	var live []Slot
	for s := range Slot(NumSlots) {
		var id uint32
		err := d.maps.DispatchProgs.Lookup(uint32(s), &id)
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("xdpdispatch: read slot %d: %w", s, err)
		}
		var expiry uint64
		if err := d.maps.SlotLease.Lookup(uint32(s), &expiry); err != nil {
			return nil, fmt.Errorf("xdpdispatch: read lease for slot %d: %w", s, err)
		}
		if expiry > now {
			live = append(live, s)
		}
	}
	return live, nil
}

// Coverage reports whether program actually sees ifindex's traffic through
// slot. It returns nil when it does, and otherwise one of the Err* reasons
// above, wrapped. Only the pinned root on a pinned, live link counts: an
// interface held by any other XDP program is never covered.
func (d *Dispatcher) Coverage(ifindex int, slot Slot, program *ebpf.Program) error {
	if slot >= NumSlots {
		return errInvalidSlot
	}
	pinned, err := link.LoadPinnedLink(d.linkPath(ifindex), nil)
	if errors.Is(err, os.ErrNotExist) {
		return ErrNoLink
	}
	if err != nil {
		return fmt.Errorf("xdpdispatch: load pinned link for ifindex %d: %w", ifindex, err)
	}
	defer pinned.Close() //nolint:errcheck // our own descriptor
	info, err := pinned.Info()
	if err != nil {
		return fmt.Errorf("xdpdispatch: read link info for ifindex %d: %w", ifindex, err)
	}
	if xdp := info.XDP(); xdp == nil || int(xdp.Ifindex) != ifindex {
		return ErrLinkDefunct
	}
	rootID, err := d.RootID()
	if err != nil {
		return err
	}
	if info.Program != rootID {
		return ErrNotRoot
	}

	roles, err := d.Roles(ifindex)
	if err != nil {
		return err
	}
	if roles&(1<<slot) == 0 || (slot == SlotGatewayReturn && roles&RolePublicLB != 0) {
		return ErrRoleMissing
	}

	held, err := d.holds(slot, program)
	if err != nil {
		return err
	}
	if !held {
		return ErrSlotNotHeld
	}

	var expiry uint64
	if err := d.maps.SlotLease.Lookup(uint32(slot), &expiry); err != nil {
		return fmt.Errorf("xdpdispatch: read lease for slot %d: %w", slot, err)
	}
	if expiry <= monotonicNowFn() {
		return ErrLeaseExpired
	}
	return nil
}

func programID(p *ebpf.Program) (ebpf.ProgramID, error) {
	if p == nil {
		return 0, errNilProgram
	}
	info, err := p.Info()
	if err != nil {
		return 0, fmt.Errorf("xdpdispatch: read program info: %w", err)
	}
	id, ok := info.ID()
	if !ok {
		return 0, errors.New("xdpdispatch: kernel reports no program ID")
	}
	return id, nil
}

// monotonicNow reads CLOCK_MONOTONIC in nanoseconds, the clock
// bpf_ktime_get_ns reads, so a lease written here compares correctly in the
// root. A pod in its own time namespace would read an offset clock; Kubernetes
// does not create one.
//
// A small duplicate of the uSID map layer's function of the same name, which
// is unexported there.
func monotonicNow() uint64 {
	var ts unix.Timespec
	// A rejected call leaves ts zero, so every lease written then has already
	// expired: the slot fails open to the later slots rather than claiming
	// packets forever.
	_ = unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	return uint64(ts.Sec)*1e9 + uint64(ts.Nsec)
}
