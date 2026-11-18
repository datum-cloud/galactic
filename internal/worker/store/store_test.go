// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"encoding/json"
	"os"
	"testing"
)

func TestDirRoundTrip(t *testing.T) {
	dir := t.TempDir()
	d, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	a := Record{Node: "n", VPC: "v1", AttachmentUID: "a", Owner: "ns/sa", Generation: 3, SpecHash: "h",
		Spec: json.RawMessage(`{"handoff":"HANDOFF_TAP"}`)}
	b := a
	b.AttachmentUID, b.Releasing, b.Withdrawal = "b", true, WithdrawCaller
	for _, r := range []Record{a, b} {
		if err := d.Put(r); err != nil {
			t.Fatal(err)
		}
	}
	a.Generation = 4
	if err := d.Put(a); err != nil {
		t.Fatal(err)
	}
	// A fresh handle reads what the first wrote.
	d2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	recs, err := d2.List()
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Record{}
	for _, r := range recs {
		got[r.AttachmentUID] = r
	}
	if len(got) != 2 || got["a"].Generation != 4 || !got["b"].Releasing || got["b"].Withdrawal != WithdrawCaller {
		t.Fatalf("records = %+v", recs)
	}
	if err := d2.Delete("n", "v1", "a"); err != nil {
		t.Fatal(err)
	}
	if err := d2.Delete("n", "v1", "a"); err != nil {
		t.Fatalf("deleting a missing record: %v", err)
	}
	if recs, _ := d2.List(); len(recs) != 1 {
		t.Fatalf("records after delete = %+v", recs)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("directory holds %d entries, want 1 and no temporary files", len(entries))
	}
}
