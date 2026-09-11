// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package dan

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// testSandboxID stands in for the runtime's container ID.
const testSandboxID = "sandbox-1"

// sampleDocument mirrors the document a tap attachment produces, so the shape
// assertions below read against something realistic.
func sampleDocument() *Document {
	return &Document{
		Devices: []Device{{
			Name:     "eth0",
			GuestMAC: "02:00:0f:00:04:00",
			Device:   DeviceSpec{Type: DeviceTypeHostTap, TapName: "G00000000bayhH"},
			NetworkInfo: NetworkInfo{
				Interface: Interface{
					IPAddresses: []string{"fd20:0:f::4:0:0/96"},
					MTU:         1460,
					Ntype:       InterfaceTypeTap,
				},
				Routes:    []Route{{Gateway: "fd20:0:f::1"}},
				Neighbors: []any{},
			},
		}},
	}
}

// TestWriteMatchesDocumentedShape pins the on-disk JSON against the shape a
// runtime-rs shim was observed to accept. Key names and nesting are the
// contract with a component outside this repository.
func TestWriteMatchesDocumentedShape(t *testing.T) {
	dir := t.TempDir()
	if err := Write(dir, testSandboxID, sampleDocument()); err != nil {
		t.Fatalf("Write: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, testSandboxID+".json"))
	if err != nil {
		t.Fatalf("read DAN file: %v", err)
	}

	var got map[string]any
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("parse DAN file: %v", err)
	}

	want := map[string]any{
		"devices": []any{map[string]any{
			"name":      "eth0",
			"guest_mac": "02:00:0f:00:04:00",
			"device": map[string]any{
				"type":     "host-tap",
				"tap_name": "G00000000bayhH",
			},
			"network_info": map[string]any{
				"interface": map[string]any{
					"ip_addresses": []any{"fd20:0:f::4:0:0/96"},
					"mtu":          float64(1460),
					"ntype":        "tuntap",
					"flags":        float64(0),
				},
				"routes": []any{map[string]any{
					"dest":    "",
					"gateway": "fd20:0:f::1",
					"source":  "",
					"scope":   float64(0),
					"flags":   float64(0),
					"mtu":     float64(0),
				}},
				"neighbors": []any{},
			},
		}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("DAN JSON = %#v, want %#v", got, want)
	}
}

// TestWriteOmitsNetns guards the field whose presence sends the shim back to
// scanning the sandbox namespace.
func TestWriteOmitsNetns(t *testing.T) {
	dir := t.TempDir()
	if err := Write(dir, testSandboxID, sampleDocument()); err != nil {
		t.Fatalf("Write: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, testSandboxID+".json"))
	if err != nil {
		t.Fatalf("read DAN file: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("parse DAN file: %v", err)
	}
	if _, present := got["netns"]; present {
		t.Errorf("DAN JSON carries a netns field: %s", data)
	}
}

// TestWriteRoundTrips checks that the document survives the file, so a reader
// of this package's own types sees what was written.
func TestWriteRoundTrips(t *testing.T) {
	dir := t.TempDir()
	want := sampleDocument()
	if err := Write(dir, testSandboxID, want); err != nil {
		t.Fatalf("Write: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, testSandboxID+".json"))
	if err != nil {
		t.Fatalf("read DAN file: %v", err)
	}
	var got Document
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("parse DAN file: %v", err)
	}
	if !reflect.DeepEqual(&got, want) {
		t.Errorf("round-tripped document = %#v, want %#v", &got, want)
	}
}

// TestWriteRefusesGoShimDir covers the guardrail against the directory whose
// shim hard-errors on a host tap.
func TestWriteRefusesGoShimDir(t *testing.T) {
	for _, dir := range []string{GoShimDir, GoShimDir + "/", GoShimDir + "/../dans"} {
		err := Write(dir, testSandboxID, sampleDocument())
		if err == nil {
			t.Fatalf("Write(%q) succeeded, want refusal", dir)
		}
		if !strings.Contains(err.Error(), "refusing") {
			t.Errorf("Write(%q) error = %v, want a refusal", dir, err)
		}
		if _, statErr := os.Stat(filepath.Join(GoShimDir, testSandboxID+".json")); statErr == nil {
			t.Fatalf("Write(%q) created a file in the Go shim's directory", dir)
		}
	}
}

// TestRemoveRefusesGoShimDir keeps the guardrail symmetric, so no path in this
// package can be aimed at the Go shim's directory.
func TestRemoveRefusesGoShimDir(t *testing.T) {
	if err := Remove(GoShimDir, testSandboxID); err == nil {
		t.Error("Remove succeeded on the Go shim's directory, want refusal")
	}
}

// TestRemoveIsIdempotent covers DEL being called twice, and being called when
// ADD never wrote a file.
func TestRemoveIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	if err := Remove(dir, "never-written"); err != nil {
		t.Errorf("Remove of a missing file: %v", err)
	}
	if err := Write(dir, testSandboxID, sampleDocument()); err != nil {
		t.Fatalf("Write: %v", err)
	}
	for attempt := range 2 {
		if err := Remove(dir, testSandboxID); err != nil {
			t.Errorf("Remove attempt %d: %v", attempt+1, err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, testSandboxID+".json")); !os.IsNotExist(err) {
		t.Errorf("DAN file still present after Remove: %v", err)
	}
}

// TestRemoveIdempotentOnMissingDirectory covers a DEL on a node where emission
// was never enabled, so the directory itself does not exist.
func TestRemoveIdempotentOnMissingDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "never-created")
	if err := Remove(dir, testSandboxID); err != nil {
		t.Errorf("Remove under a missing directory: %v", err)
	}
}

// TestWriteReplacesExistingFile covers an ADD retried after a partial failure,
// which must leave the current document rather than the stale one.
func TestWriteReplacesExistingFile(t *testing.T) {
	dir := t.TempDir()
	if err := Write(dir, testSandboxID, sampleDocument()); err != nil {
		t.Fatalf("first Write: %v", err)
	}
	replacement := sampleDocument()
	replacement.Devices[0].Device.TapName = "G00000000otherH"
	if err := Write(dir, testSandboxID, replacement); err != nil {
		t.Fatalf("second Write: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, testSandboxID+".json"))
	if err != nil {
		t.Fatalf("read DAN file: %v", err)
	}
	var got Document
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("parse DAN file: %v", err)
	}
	if got.Devices[0].Device.TapName != "G00000000otherH" {
		t.Errorf("tap name = %q, want the replacement's", got.Devices[0].Device.TapName)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read directory: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("directory holds %d entries, want only the DAN file", len(entries))
	}
}

// TestWriteRejectsUnusableInput covers the inputs that would put a file
// somewhere other than one sandbox's own, or write one no shim can use.
func TestWriteRejectsUnusableInput(t *testing.T) {
	dir := t.TempDir()
	cases := map[string]struct {
		dir       string
		sandboxID string
		doc       *Document
	}{
		"empty directory":          {"", testSandboxID, sampleDocument()},
		"empty sandbox ID":         {dir, "", sampleDocument()},
		"path in ID":               {dir, "../escape", sampleDocument()},
		"nil document":             {dir, testSandboxID, nil},
		"document with no devices": {dir, testSandboxID, &Document{}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if err := Write(tc.dir, tc.sandboxID, tc.doc); err == nil {
				t.Error("Write succeeded, want an error")
			}
		})
	}
}

// TestWriteFailsWhenDirectoryCannotBeCreated checks that a write failure
// surfaces to the caller. A swallowed failure leaves the shim falling back to
// namespace scanning.
func TestWriteFailsWhenDirectoryCannotBeCreated(t *testing.T) {
	blocked := filepath.Join(t.TempDir(), "blocked")
	if err := os.WriteFile(blocked, []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("create blocking file: %v", err)
	}
	if err := Write(blocked, testSandboxID, sampleDocument()); err == nil {
		t.Error("Write succeeded where the directory cannot exist, want an error")
	}
}

// TestDefaultDirIsNotTheGoShimDir pins the two directories apart.
func TestDefaultDirIsNotTheGoShimDir(t *testing.T) {
	if DefaultDir == GoShimDir {
		t.Fatalf("DefaultDir is the Go shim's directory %q", GoShimDir)
	}
}
