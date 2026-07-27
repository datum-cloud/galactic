// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package vmtap

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

const ciliumConflist = `{
	"cniVersion": "1.0.0",
	"name": "cilium",
	"plugins": [
		{"type": "cilium-cni"}
	]
}`

func TestPatchConflistDirAppendsEntry(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "05-cilium.conflist")
	if err := os.WriteFile(path, []byte(ciliumConflist), 0644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	patched, err := PatchConflistDir(dir, "*cilium*.conflist")
	if err != nil {
		t.Fatalf("PatchConflistDir() = %v, want nil", err)
	}
	if len(patched) != 1 || patched[0] != path {
		t.Fatalf("patched = %v, want [%s]", patched, path)
	}

	var env conflistEnvelope
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read patched file: %v", err)
	}
	if err := json.Unmarshal(data, &env); err != nil {
		t.Fatalf("unmarshal patched file: %v", err)
	}
	if len(env.Plugins) != 2 {
		t.Fatalf("plugins count = %d, want 2", len(env.Plugins))
	}
	var last struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(env.Plugins[1], &last); err != nil {
		t.Fatalf("unmarshal last plugin entry: %v", err)
	}
	if last.Type != PluginType {
		t.Errorf("last plugin type = %q, want %q", last.Type, PluginType)
	}
}

func TestPatchConflistDirIdempotent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "05-cilium.conflist")
	if err := os.WriteFile(path, []byte(ciliumConflist), 0644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	if _, err := PatchConflistDir(dir, "*cilium*.conflist"); err != nil {
		t.Fatalf("first PatchConflistDir() = %v, want nil", err)
	}
	patched, err := PatchConflistDir(dir, "*cilium*.conflist")
	if err != nil {
		t.Fatalf("second PatchConflistDir() = %v, want nil", err)
	}
	if len(patched) != 0 {
		t.Errorf("second call patched = %v, want empty (already patched)", patched)
	}
}

func TestPatchConflistDirNoMatch(t *testing.T) {
	dir := t.TempDir()

	patched, err := PatchConflistDir(dir, "*cilium*.conflist")
	if err != nil {
		t.Fatalf("PatchConflistDir() = %v, want nil", err)
	}
	if len(patched) != 0 {
		t.Errorf("patched = %v, want empty (no matching files)", patched)
	}
}
