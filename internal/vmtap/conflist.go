// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package vmtap

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// PluginType is the "type" field vmtap-cni registers under in a conflist's
// "plugins" array, and the value PatchConflistDir looks for to decide
// whether a conflist has already been patched.
const PluginType = "vmtap-cni"

// conflistEnvelope is the standard CNI conflist JSON structure. Plugins is
// kept as raw JSON so patching only ever appends a new element — existing
// plugin entries (Cilium's own, and any others already chained) are never
// re-marshaled and so cannot be reformatted or reordered by a patch.
type conflistEnvelope struct {
	CNIVersion string            `json:"cniVersion"`
	Name       string            `json:"name"`
	Plugins    []json.RawMessage `json:"plugins"`
}

// PatchConflistDir scans dir (non-recursively) for conflist files matching
// glob and appends a {"type": vmtap.PluginType} entry to each one's
// "plugins" array, unless already present. Returns the paths that were
// newly patched this call.
//
// This is a best-effort installer step, not a verified solution to the
// conflist-chaining problem flagged in
// .local/kraftlet-cilium-tap-plan.md section 7: it assumes Cilium's
// conflist already exists under dir by the time this runs (there is no
// cross-DaemonSet ordering guarantee for that — see RunPatchLoop, which
// polls specifically to tolerate arriving late) and it does not undo the
// patch on uninstall, so removing vmtap-cni from a cluster currently
// requires manually editing Cilium's conflist back out. Both are open
// items, not solved problems.
func PatchConflistDir(dir, glob string) ([]string, error) {
	matches, err := filepath.Glob(filepath.Join(dir, glob))
	if err != nil {
		return nil, fmt.Errorf("glob %q in %q: %w", glob, dir, err)
	}

	var patched []string
	for _, path := range matches {
		changed, err := patchConflistFile(path)
		if err != nil {
			return patched, fmt.Errorf("patch %q: %w", path, err)
		}
		if changed {
			patched = append(patched, path)
		}
	}
	return patched, nil
}

// patchConflistFile appends vmtap-cni's plugin entry to path's "plugins"
// array if not already present. Returns true if the file was modified.
func patchConflistFile(path string) (bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return false, fmt.Errorf("read: %w", err)
	}

	var env conflistEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		return false, fmt.Errorf("parse conflist: %w", err)
	}

	for _, raw := range env.Plugins {
		var meta struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(raw, &meta); err != nil {
			continue
		}
		if meta.Type == PluginType {
			return false, nil // already patched
		}
	}

	entry, err := json.Marshal(map[string]string{"type": PluginType})
	if err != nil {
		return false, fmt.Errorf("marshal plugin entry: %w", err)
	}
	env.Plugins = append(env.Plugins, entry)

	out, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return false, fmt.Errorf("marshal patched conflist: %w", err)
	}

	return true, writeFileAtomic(path, out)
}

// writeFileAtomic writes data to path via a temp-file-plus-rename, so a
// CNI runtime reading the conflist concurrently never observes a partially
// written file — conflists are read on every pod ADD, including
// potentially while this patch is in flight.
func writeFileAtomic(path string, data []byte) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat: %w", err)
	}

	tmp := path + ".vmtap-cni.tmp"
	if err := os.WriteFile(tmp, data, info.Mode()); err != nil {
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename temp file into place: %w", err)
	}
	return nil
}
