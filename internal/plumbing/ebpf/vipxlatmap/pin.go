// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package vipxlatmap

import (
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"sync"

	"github.com/cilium/ebpf"

	"go.datum.net/galactic/internal/plumbing/ebpf/prog"
	"go.datum.net/galactic/internal/plumbing/ebpf/usidmap"
)

// OpenPinnedVipXlatTable opens vip_xlat_table from its pinned path under pinDir
// and returns a table wrapping it. The datapath's maps are each pinned at
// <pinDir>/<map name>, the same convention the uSID registry relies on.
//
// The router loads and attaches no eBPF program of its own, that happening once
// elsewhere on the CNI side, so this function's only job is to open a second
// handle onto a map another running process on this node pinned.
//
// Unlike the short-lived plugin binary the uSID registry serves, the router is a
// long-lived daemon: the returned closer should be closed once at process
// shutdown rather than immediately after use. Either way it does not affect the
// map's pinned lifetime, closing only this process's own descriptor.
func OpenPinnedVipXlatTable(pinDir string) (*VipXlatTable, io.Closer, error) {
	m, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, prog.UsidMapVipXlatTable), nil)
	if err != nil {
		return nil, nil, fmt.Errorf("vipxlatmap: open pinned map %q under %q: %w", prog.UsidMapVipXlatTable, pinDir, err)
	}
	table, closer := newPinnedTable(usidmap.KernelTable{Map: m}, m, func() (usidmap.Table, io.Closer, error) {
		ranges, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, prog.UsidMapVipXlatRangeTable), nil)
		if err != nil {
			return nil, nil, fmt.Errorf("open range translation map: %w", err)
		}
		return usidmap.KernelTable{Map: ranges}, ranges, nil
	})
	return table, closer, nil
}

// newPinnedTable keeps the exact handle and its registration ledger stable when
// a newer CNI creates the range map after the router has already started.
func newPinnedTable(exact usidmap.Table, exactCloser io.Closer,
	openRanges func() (usidmap.Table, io.Closer, error),
) (*VipXlatTable, io.Closer) {
	closer := &rangeMapCloser{exact: exactCloser}
	table := NewVipXlatTable(exact)
	table.openRanges = func() (usidmap.Table, error) {
		closer.mu.Lock()
		defer closer.mu.Unlock()
		if closer.closed {
			return nil, errors.New("translation map handles are closed")
		}
		ranges, handle, err := openRanges()
		if err != nil {
			return nil, err
		}
		closer.ranges = handle
		return ranges, nil
	}
	return table, closer
}

type rangeMapCloser struct {
	mu            sync.Mutex
	exact, ranges io.Closer
	closed        bool
}

func (c *rangeMapCloser) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	err := c.exact.Close()
	if c.ranges != nil {
		err = errors.Join(err, c.ranges.Close())
	}
	return err
}
