// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package radv

import (
	"path/filepath"
	"testing"
)

func TestRecordAttachmentThenListAttachments(t *testing.T) {
	stateDir := t.TempDir()

	if err := RecordAttachment(stateDir, "tap-abc123H", 1500); err != nil {
		t.Fatalf("RecordAttachment() error = %v", err)
	}
	if err := RecordAttachment(stateDir, "tap-def456H", 9000); err != nil {
		t.Fatalf("RecordAttachment() error = %v", err)
	}

	records, err := ListAttachments(stateDir)
	if err != nil {
		t.Fatalf("ListAttachments() error = %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("ListAttachments() returned %d records, want 2", len(records))
	}

	byIface := make(map[string]Record, len(records))
	for _, r := range records {
		byIface[r.HostInterface] = r
	}
	if got, want := byIface["tap-abc123H"].MTU, 1500; got != want {
		t.Errorf("tap-abc123H MTU = %d, want %d", got, want)
	}
	if got, want := byIface["tap-def456H"].MTU, 9000; got != want {
		t.Errorf("tap-def456H MTU = %d, want %d", got, want)
	}
}

func TestRecordAttachmentOverwritesExisting(t *testing.T) {
	stateDir := t.TempDir()

	if err := RecordAttachment(stateDir, "tap-abc123H", 1500); err != nil {
		t.Fatalf("RecordAttachment() error = %v", err)
	}
	if err := RecordAttachment(stateDir, "tap-abc123H", 1400); err != nil {
		t.Fatalf("RecordAttachment() error = %v", err)
	}

	records, err := ListAttachments(stateDir)
	if err != nil {
		t.Fatalf("ListAttachments() error = %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("ListAttachments() returned %d records, want 1", len(records))
	}
	if got, want := records[0].MTU, 1400; got != want {
		t.Errorf("MTU = %d, want %d", got, want)
	}
}

func TestRemoveAttachment(t *testing.T) {
	stateDir := t.TempDir()

	if err := RecordAttachment(stateDir, "tap-abc123H", 1500); err != nil {
		t.Fatalf("RecordAttachment() error = %v", err)
	}
	if err := RemoveAttachment(stateDir, "tap-abc123H"); err != nil {
		t.Fatalf("RemoveAttachment() error = %v", err)
	}

	records, err := ListAttachments(stateDir)
	if err != nil {
		t.Fatalf("ListAttachments() error = %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("ListAttachments() returned %d records, want 0", len(records))
	}
}

func TestRemoveAttachmentMissingIsNotError(t *testing.T) {
	stateDir := t.TempDir()

	if err := RemoveAttachment(stateDir, "tap-never-existed-H"); err != nil {
		t.Errorf("RemoveAttachment() on a never-recorded interface error = %v, want nil", err)
	}
}

func TestListAttachmentsMissingStateDirIsNotError(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "does-not-exist")

	records, err := ListAttachments(stateDir)
	if err != nil {
		t.Fatalf("ListAttachments() error = %v, want nil", err)
	}
	if len(records) != 0 {
		t.Errorf("ListAttachments() returned %d records, want 0", len(records))
	}
}
