// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package mappin recovers a pinned eBPF collection whose map layout changed
// between versions.
//
// Loading a collection with pin-by-name reuses each existing pin, and fails
// with ebpf.ErrMapIncompatible when any one pin no longer matches the compiled
// spec. The recovery is to remove that pin so the retry creates the map fresh.
// Removing only the pins that no longer match matters: every map holds state
// some writer put there, and a map whose layout did not change has no reason to
// lose it. Some of that state, such as the uSID datapath's per-attachment rows,
// is written once at CNI ADD and never again, so recreating a map that did not
// need it blackholes traffic until every workload on the node re-attaches.
package mappin

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/cilium/ebpf"
)

// UnpinIncompatible removes the pin under pinDir of every map in spec whose
// pinned copy no longer matches spec, and returns their names, sorted. A map
// with no pin, or whose pin still matches, is left alone. skip, when non-nil,
// excludes maps the caller does not own.
func UnpinIncompatible(spec *ebpf.CollectionSpec, pinDir string, skip func(name string) bool) ([]string, error) {
	names := make([]string, 0, len(spec.Maps))
	for name := range spec.Maps {
		if skip == nil || !skip(name) {
			names = append(names, name)
		}
	}
	sort.Strings(names)

	var unpinned []string
	var errs []error
	for _, name := range names {
		m, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, name), nil)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			errs = append(errs, fmt.Errorf("load pinned map %q: %w", name, err))
			continue
		}
		compatErr := spec.Maps[name].Compatible(m)
		if compatErr == nil {
			_ = m.Close()
			continue
		}
		if !errors.Is(compatErr, ebpf.ErrMapIncompatible) {
			errs = append(errs, fmt.Errorf("check pinned map %q: %w", name, compatErr))
			_ = m.Close()
			continue
		}
		if err := m.Unpin(); err != nil {
			errs = append(errs, fmt.Errorf("unpin incompatible map %q: %w", name, err))
		} else {
			unpinned = append(unpinned, name)
		}
		_ = m.Close()
	}
	return unpinned, errors.Join(errs...)
}
