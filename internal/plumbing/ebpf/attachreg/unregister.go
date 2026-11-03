// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package attachreg

import (
	"errors"
	"fmt"
	"os"

	"github.com/cilium/ebpf"

	"go.datum.net/galactic/internal/plumbing/ebpf/ifindexvrfmap"
	"go.datum.net/galactic/internal/plumbing/ebpf/tpmap"
)

// UnregisterInterface removes every row the uSID datapath's pinned maps under
// pinDir key on one attachment's host ifindex: its ifindex_vrf_table,
// ifindex_egress_kind_table, tenant_gw_table and host_only_port_table entries
// and its traffic policy state (bindings, policy token, addresses and fallback
// counter rows). These rows belong to the interface's lifetime alone, so
// every caller that ends that lifetime removes them through here: CNI DEL, and
// the galactic-cni daemon's reclaim of a tap no DEL removed.
//
// Left behind, each row applies to whatever attachment next reuses the
// ifindex until that attachment's own ADD overwrites it.
//
// It removes them before the interface goes, since nothing resolves the
// ifindex afterward. A map that is not pinned, because the datapath is not
// enabled or not loaded yet, has nothing to remove. Every other failure is
// returned, joined, after the remaining maps have been tried.
func UnregisterInterface(pinDir string, ifindex uint32) error {
	var errs []error
	unregister := func(name string, open func(string) (func(uint32) error, *ebpf.Map, error)) {
		del, m, err := open(pinDir)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				errs = append(errs, fmt.Errorf("open %s: %w", name, err))
			}
			return
		}
		defer func() { _ = m.Close() }()
		if err := del(ifindex); err != nil {
			errs = append(errs, err)
		}
	}
	unregister("ifindex_vrf_table", func(dir string) (func(uint32) error, *ebpf.Map, error) {
		t, m, err := ifindexvrfmap.OpenPinned(dir)
		if err != nil {
			return nil, nil, err
		}
		return t.Unregister, m, nil
	})
	unregister("ifindex_egress_kind_table", func(dir string) (func(uint32) error, *ebpf.Map, error) {
		t, m, err := ifindexvrfmap.OpenPinnedEgressKind(dir)
		if err != nil {
			return nil, nil, err
		}
		return t.Unregister, m, nil
	})
	unregister("tenant_gw_table", func(dir string) (func(uint32) error, *ebpf.Map, error) {
		t, m, err := ifindexvrfmap.OpenPinnedGateway(dir)
		if err != nil {
			return nil, nil, err
		}
		return t.Unregister, m, nil
	})
	unregister("host_only_port_table", func(dir string) (func(uint32) error, *ebpf.Map, error) {
		t, m, err := ifindexvrfmap.OpenPinnedHostOnlyPorts(dir)
		if err != nil {
			return nil, nil, err
		}
		return t.Unregister, m, nil
	})
	if err := tpmap.RemovePinnedInterface(pinDir, ifindex); err != nil {
		errs = append(errs, fmt.Errorf("remove traffic policy state: %w", err))
	}
	return errors.Join(errs...)
}
