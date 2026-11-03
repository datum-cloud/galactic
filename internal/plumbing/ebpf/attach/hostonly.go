// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package attach

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/cilium/ebpf"
)

// DeliverReadsHostOnlyPorts reports whether the tp_deliver program pinned in
// pinDir reads table, the host_only_port_table pinned beside it. A node rolled
// back to a datapath without the check keeps the newer pinned table, so the
// table existing proves nothing; only the program's own map references do.
// A missing tp_deliver pin reads nothing.
func DeliverReadsHostOnlyPorts(pinDir string, table *ebpf.Map) (bool, error) {
	deliver, err := ebpf.LoadPinnedProgram(filepath.Join(pinDir, TpDeliverPinName), nil)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("attach: open pinned tp_deliver: %w", err)
	}
	defer func() { _ = deliver.Close() }()
	return programReadsMap(deliver, table)
}

func programReadsMap(program *ebpf.Program, m *ebpf.Map) (bool, error) {
	progInfo, err := program.Info()
	if err != nil {
		return false, fmt.Errorf("attach: read program info: %w", err)
	}
	mapIDs, ok := progInfo.MapIDs()
	if !ok {
		return false, errors.New("attach: kernel does not report a program's maps")
	}
	mapInfo, err := m.Info()
	if err != nil {
		return false, fmt.Errorf("attach: read map info: %w", err)
	}
	id, ok := mapInfo.ID()
	if !ok {
		return false, errors.New("attach: kernel does not report a map's ID")
	}
	return slices.Contains(mapIDs, id), nil
}
