// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package srcfiltermap

import (
	"errors"
	"fmt"
	"io"
	"path/filepath"

	"github.com/cilium/ebpf"

	"go.datum.net/galactic/internal/plumbing/ebpf/prog"
	"go.datum.net/galactic/internal/plumbing/ebpf/usidmap"
)

// OpenPinned opens every source filter map from its pin under pinDir, where
// each is pinned at <pinDir>/<map name>, and returns a Filter over them.
//
// The returned closer releases only this process's descriptors, never the
// maps' pinned lifetime. On error nothing is left open.
func OpenPinned(pinDir string) (*Filter, io.Closer, error) {
	var opened closers
	load := func(name string) usidmap.Table {
		m, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, name), nil)
		if err != nil {
			opened.errs = append(opened.errs, fmt.Errorf("open pinned map %q under %q: %w", name, pinDir, err))
			return nil
		}
		opened.maps = append(opened.maps, m)
		return usidmap.KernelTable{Map: m}
	}

	tables := Tables{
		Allow:       load(prog.UsidMapSrcAllowTable),
		UplinkSlots: load(prog.UsidMapUplinkSlotTable),
		Config:      load(prog.UsidMapSrcFilterConfigTable),
		Stats:       load(prog.UsidMapSrcFilterStats),
		Denied:      load(prog.UsidMapSrcFilterDenied),
	}
	if len(opened.errs) > 0 {
		err := errors.Join(opened.errs...)
		_ = opened.Close()
		return nil, nil, fmt.Errorf("srcfiltermap: %w", err)
	}
	return New(tables), &opened, nil
}

// NewFromObjects returns a Filter over the source filter maps of an already
// loaded datapath collection. The caller keeps ownership of objs.
func NewFromObjects(objs *prog.UsidObjects) *Filter {
	return New(Tables{
		Allow:       usidmap.KernelTable{Map: objs.SrcAllowTable},
		UplinkSlots: usidmap.KernelTable{Map: objs.UplinkSlotTable},
		Config:      usidmap.KernelTable{Map: objs.SrcFilterConfigTable},
		Stats:       usidmap.KernelTable{Map: objs.SrcFilterStats},
		Denied:      usidmap.KernelTable{Map: objs.SrcFilterDenied},
	})
}

type closers struct {
	maps []*ebpf.Map
	errs []error
}

func (c *closers) Close() error {
	var errs []error
	for _, m := range c.maps {
		if err := m.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
