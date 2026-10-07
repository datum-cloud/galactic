// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package attach

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
)

// drainLegacyServiceAuthorization revokes the authorization held by a
// classifier that may continue running briefly while an incompatible map set
// is replaced. Protocol-zero access markers are deliberately retained: they
// make fragmented traffic to known service addresses fail closed in the old
// classifier. Real access rows, reverse state, and remote grants are removed.
func drainLegacyServiceAuthorization(pinDir string) error {
	if err := disablePinnedServicePolicy(pinDir); err != nil {
		return err
	}
	if err := deletePinnedMapEntries(filepath.Join(pinDir, "service_access_table"), func(key []byte) bool {
		// service_access_key has a stable prefix: ifindex(4), family(1),
		// protocol(1), port(2). Keep only the address marker tuple.
		return len(key) >= 8 && key[5] == 0 && key[6] == 0 && key[7] == 0
	}); err != nil {
		return fmt.Errorf("drain service access: %w", err)
	}
	for _, name := range []string{"service_reverse_table", "service_remote_grant_table"} {
		if err := deletePinnedMapEntries(filepath.Join(pinDir, name), nil); err != nil {
			return fmt.Errorf("drain %s: %w", name, err)
		}
	}
	return nil
}

func disablePinnedServicePolicy(pinDir string) error {
	path := filepath.Join(pinDir, "service_policy_state_table")
	m, err := ebpf.LoadPinnedMap(path, nil)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("open service policy state: %w", err)
	}
	defer func() { _ = m.Close() }()
	info, err := m.Info()
	if err != nil {
		return fmt.Errorf("inspect service policy state: %w", err)
	}
	value := make([]byte, info.ValueSize)
	if err := m.Put(uint32(0), value); err != nil {
		return fmt.Errorf("disable service policy: %w", err)
	}
	return nil
}

// deletePinnedMapEntries deletes every entry for which keep returns false.
// Missing maps are valid when upgrading a version that predates service
// routing entirely.
func deletePinnedMapEntries(path string, keep func([]byte) bool) error {
	m, err := ebpf.LoadPinnedMap(path, nil)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	defer func() { _ = m.Close() }()
	info, err := m.Info()
	if err != nil {
		return err
	}
	key := make([]byte, info.KeySize)
	value := make([]byte, info.ValueSize)
	keys := make([][]byte, 0)
	iterator := m.Iterate()
	for iterator.Next(&key, &value) {
		if keep != nil && keep(key) {
			continue
		}
		keys = append(keys, append([]byte(nil), key...))
	}
	if err := iterator.Err(); err != nil {
		return err
	}
	for _, doomed := range keys {
		if err := m.Delete(doomed); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return err
		}
	}
	return nil
}
