// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package xdpdispatch

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"go.datum.net/galactic/internal/plumbing/ebpf/xdpmode"
)

// ErrNoDispatcher means the host has no dispatch state: no datapath sharing
// the XDP hook has opened a dispatcher on it.
var ErrNoDispatcher = errors.New("xdpdispatch: no dispatcher on this host")

// ErrSlotEmpty means a slot holds no program.
var ErrSlotEmpty = errors.New("xdpdispatch: slot holds no program")

// Inspector reads a host's dispatch state without changing it. Unlike Open
// and OpenForSlots it loads no program, pins nothing and takes no lock, so a
// process that only checks whether another datapath's slot covers an
// interface, such as Worker's Local module, never creates dispatch state on a
// host that has none.
type Inspector struct {
	dir      string
	progs    *ebpf.Map
	leases   *ebpf.Map
	roles    *ebpf.Map
	hostMode *ebpf.Map
}

// Inspect opens dir's pinned dispatch state read-only. It returns
// ErrNoDispatcher when dir holds no root.
func Inspect(dir string) (*Inspector, error) {
	abi := filepath.Join(dir, abiDirName)
	if _, err := os.Stat(filepath.Join(abi, rootPinName)); errors.Is(err, os.ErrNotExist) {
		return nil, ErrNoDispatcher
	}
	ro := &ebpf.LoadPinOptions{ReadOnly: true}
	in := &Inspector{dir: dir}
	for _, m := range []struct {
		dst  **ebpf.Map
		path string
	}{
		{&in.progs, filepath.Join(abi, "dispatch_progs")},
		{&in.leases, filepath.Join(abi, "slot_lease")},
		{&in.roles, filepath.Join(abi, "iface_roles")},
		{&in.hostMode, filepath.Join(dir, hostModePinName)},
	} {
		mp, err := ebpf.LoadPinnedMap(m.path, ro)
		if err != nil {
			_ = in.Close()
			if errors.Is(err, os.ErrNotExist) {
				return nil, ErrNoDispatcher
			}
			return nil, fmt.Errorf("xdpdispatch: open %s: %w", m.path, err)
		}
		*m.dst = mp
	}
	return in, nil
}

// Close releases the inspector's descriptors.
func (in *Inspector) Close() error {
	var errs []error
	for _, m := range []*ebpf.Map{in.progs, in.leases, in.roles, in.hostMode} {
		if m != nil {
			errs = append(errs, m.Close())
		}
	}
	return errors.Join(errs...)
}

// Interfaces returns every ifindex whose roles include role.
func (in *Inspector) Interfaces(role Role) ([]int, error) {
	var (
		out   []int
		key   uint32
		roles uint32
	)
	it := in.roles.Iterate()
	for it.Next(&key, &roles) {
		if Role(roles)&role != 0 {
			out = append(out, int(key))
		}
	}
	if err := it.Err(); err != nil {
		return nil, fmt.Errorf("xdpdispatch: read interface roles: %w", err)
	}
	return out, nil
}

// HostMode returns the XDP mode the attaching datapaths on the host
// recorded, and false when none has.
func (in *Inspector) HostMode() (xdpmode.Mode, bool, error) {
	var v uint32
	if err := in.hostMode.Lookup(uint32(0), &v); err != nil {
		return 0, false, fmt.Errorf("xdpdispatch: read host mode record: %w", err)
	}
	if v == 0 {
		return 0, false, nil
	}
	return xdpmode.Mode(v - 1), true, nil
}

// Claimed reports whether some program sees ifindex's traffic through slot,
// whichever program it is. It returns nil when it does, and otherwise
// ErrNoLink, ErrLinkDefunct, ErrNotRoot, ErrModeMismatch, ErrRoleMissing,
// ErrSlotEmpty or ErrLeaseExpired, wrapped. It is Coverage for a reader that
// does not hold the slot's program.
func (in *Inspector) Claimed(ifindex int, slot Slot) error {
	if slot >= NumSlots {
		return errInvalidSlot
	}
	// A pinned link takes no read-only open; the inspector only reads it.
	pinned, err := link.LoadPinnedLink(filepath.Join(in.dir, linksDirName, strconv.Itoa(ifindex)), nil)
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
	root, err := ebpf.LoadPinnedProgram(filepath.Join(in.dir, abiDirName, rootPinName), nil)
	if err != nil {
		return fmt.Errorf("xdpdispatch: load pinned root: %w", err)
	}
	rootID, err := programID(root)
	_ = root.Close()
	if err != nil {
		return err
	}
	if info.Program != rootID {
		return ErrNotRoot
	}
	want, recorded, err := in.HostMode()
	if err != nil {
		return err
	}
	mode, ok, err := attachedMode(ifindex)
	if err != nil {
		return err
	}
	if !ok || (recorded && mode != want) {
		return ErrModeMismatch
	}
	var roles uint32
	if err := in.roles.Lookup(uint32(ifindex), &roles); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("xdpdispatch: read roles for ifindex %d: %w", ifindex, err)
	}
	if Role(roles)&(1<<slot) == 0 || (slot == SlotGatewayReturn && Role(roles)&RolePublicLB != 0) {
		return ErrRoleMissing
	}
	var id uint32
	if err := in.progs.Lookup(uint32(slot), &id); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return ErrSlotEmpty
		}
		return fmt.Errorf("xdpdispatch: read slot %d: %w", slot, err)
	}
	var expiry uint64
	if err := in.leases.Lookup(uint32(slot), &expiry); err != nil {
		return fmt.Errorf("xdpdispatch: read lease for slot %d: %w", slot, err)
	}
	if expiry <= monotonicNowFn() {
		return ErrLeaseExpired
	}
	return nil
}
