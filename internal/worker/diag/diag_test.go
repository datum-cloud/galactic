// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package diag

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.datum.net/galactic/internal/ownership"
)

// TestInspectAfterHandback checks that inspect reports a handed-back scope
// from the live fence once Worker and its snapshot are gone.
func TestInspectAfterHandback(t *testing.T) {
	fence, err := ownership.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	worker := ownership.WorkerOwnerPrefix + "node-a:1"
	tk, err := fence.Claim(ownership.VPCScope("10"), worker)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fence.CommitSnapshot(tk, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := fence.Relinquish(ownership.VPCScope("10"), func(r ownership.Record) bool {
		return ownership.WorkerOwned(r.Owner)
	}, ownership.HandbackOwnerPrefix+"x"); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(filepath.Join(t.TempDir(), "status.json")); err == nil {
		t.Fatal("reading a missing snapshot succeeded")
	}
	s, err := Join(Snapshot{}, fence)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Scopes) != 1 || s.Scopes[0].VPC != "10" || !s.Scopes[0].Fence.Pending {
		t.Fatalf("scopes %+v", s.Scopes)
	}
	var out bytes.Buffer
	if err := Print(&out, s, time.Now()); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"No Worker status snapshot", ownership.HandbackOwnerPrefix + "x",
		"handed back; the next writer takes it"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("output lacks %q:\n%s", want, out.String())
		}
	}
}

// TestWriteRead round-trips a snapshot through a root-only file.
func TestWriteRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "status.json")
	in := Snapshot{Time: time.Unix(1, 0).UTC(), Node: "n", Owner: "o",
		Scopes: []Scope{{VPC: "10", Claims: []Claim{{Key: "n/10/a", Destinations: []Destination{{ID: "d",
			Reason: "HandoffHookMissing"}}}}}}}
	if err := Write(path, in); err != nil {
		t.Fatal(err)
	}
	got, err := Read(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Scopes[0].Claims[0].Destinations[0].Reason != "HandoffHookMissing" || !got.Time.Equal(in.Time) {
		t.Fatalf("round trip = %+v", got)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v, want 0600", st.Mode().Perm())
	}
}
