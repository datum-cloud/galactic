// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package attachreg

import (
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"

	"go.datum.net/galactic/internal/plumbing/ebpf/attach"
	"go.datum.net/galactic/internal/plumbing/ebpf/ifindexvrfmap"
	"go.datum.net/galactic/internal/plumbing/ebpf/tpmap"
	"go.datum.net/galactic/internal/plumbing/ebpf/usidmap"
)

// ErrVRFNotRegistered is returned by RegisterHostLink when the VRF has no
// uSID entry on this node: no workload of its VPC has registered it.
var ErrVRFNotRegistered = errors.New("eBPF registration: VRF has no uSID entry on this node")

// RegisterHostLink registers a host link that is enslaved to an existing
// canonical VRF, such as a Galactic Edge attachment's, with the uSID
// datapath under that VRF's own uSID entry: it allocates no Argument. It
// writes the link's ifindex_vrf_table and ifindex_egress_kind_table rows and
// attaches usid_egress to its tc ingress and tp_deliver to its tc egress.
// Where the VRF has more than one entry, the lowest Argument is used, so
// every call picks the same one.
func RegisterHostLink(pinDir string, vrfTableID uint32, ifindex uint32, ifname string) error {
	registry, closer, err := usidmap.OpenPinnedRegistry(pinDir)
	if err != nil {
		return fmt.Errorf("open pinned eBPF uSID maps: %w", err)
	}
	defer func() { _ = closer.Close() }()
	entries, err := registry.VRF.List()
	if err != nil {
		return fmt.Errorf("list eBPF vrf_table: %w", err)
	}
	var found bool
	var key usidmap.VRFKey
	argument := uint16(math.MaxUint16)
	for _, e := range entries {
		if e.VRFTableID == vrfTableID && e.Argument < argument {
			key, argument, found = e.VRFKey, e.Argument, true
		}
	}
	if !found {
		return fmt.Errorf("%w: table %d", ErrVRFNotRegistered, vrfTableID)
	}

	table, tableCloser, err := ifindexvrfmap.OpenPinned(pinDir)
	if err != nil {
		return fmt.Errorf("open pinned eBPF ifindex_vrf_table: %w", err)
	}
	defer func() { _ = tableCloser.Close() }()
	if err := table.Register(ifindex, key.Block, key.Argument); err != nil {
		return fmt.Errorf("register eBPF ifindex_vrf_table entry: %w", err)
	}
	if err := registerEgressKind(pinDir, ifindex, usidmap.EgressKindVeth); err != nil {
		return err
	}
	if err := attachUsidEgress(pinDir, ifname); err != nil {
		return fmt.Errorf("attach eBPF usid_egress to host interface %q: %w", ifname, err)
	}
	// tp_deliver checks what the kernel itself transmits to the link: the
	// traffic policy, and an edge link's forwarding gate.
	program, err := ebpf.LoadPinnedProgram(filepath.Join(pinDir, attach.TpDeliverPinName), nil)
	if err != nil {
		return fmt.Errorf("load pinned tp_deliver: %w", err)
	}
	defer func() { _ = program.Close() }()
	if err := attach.AttachDeliver(program, ifname); err != nil {
		return fmt.Errorf("attach eBPF tp_deliver to host interface %q: %w", ifname, err)
	}
	return nil
}

// UnregisterHostLink removes every per-ifindex row RegisterHostLink wrote for
// ifindex, and the link's traffic policy rows. Call it before deleting the
// link, while the caller can still prove the ifindex is its own: a later link
// may reuse the number. Absent maps and rows are not errors.
func UnregisterHostLink(pinDir string, ifindex uint32) error {
	var errs []error
	// A map that is not pinned holds no row; any other failure to open one
	// may leave a row behind, so it is reported.
	opened := func(err error) bool {
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, err)
		}
		return err == nil
	}
	if table, closer, err := ifindexvrfmap.OpenPinned(pinDir); opened(err) {
		errs = append(errs, table.Unregister(ifindex))
		_ = closer.Close()
	}
	if kinds, closer, err := ifindexvrfmap.OpenPinnedEgressKind(pinDir); opened(err) {
		errs = append(errs, kinds.Unregister(ifindex))
		_ = closer.Close()
	}
	errs = append(errs, tpmap.RemovePinnedInterface(pinDir, ifindex))
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("unregister eBPF rows of ifindex %d: %w", ifindex, err)
	}
	return nil
}
