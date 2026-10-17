// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package activation

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func appendAll(t *testing.T, j *Journal, recs ...Record) {
	t.Helper()
	for _, rec := range recs {
		if _, err := j.Append(rec); err != nil {
			t.Fatal(err)
		}
	}
}

func TestJournalReopens(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "journal.log")
	j, err := OpenJournal(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	act := Activation{DeploymentUID: "d", Epoch: 1, Revision: testRev1}
	appendAll(t, j,
		Record{Type: RecordAccepted, Activation: act, Recovery: &Recovery{TargetRevision: "r-0"}},
		Record{Type: RecordApplied, Activation: act},
	)
	again, err := OpenJournal(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := recordTypes(again); !slices.Equal(got, []RecordType{RecordAccepted, RecordApplied}) {
		t.Fatalf("reopened records = %v", got)
	}
	if last, _ := again.Last(); last.Seq != 2 {
		t.Errorf("last sequence = %d, want 2", last.Seq)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("journal mode %v, want 0600", info.Mode().Perm())
	}
}

// TestJournalTornTail: a crash mid-append leaves a partial last line, which
// is dropped; damage anywhere earlier is corruption.
func TestJournalTornTail(t *testing.T) {
	for _, tc := range []struct {
		name    string
		damage  func(lines []string) string
		want    int
		corrupt bool
	}{
		{"partial last line", func(l []string) string {
			return l[0] + "\n" + l[1] + "\n" + l[2][:len(l[2])/2]
		}, 2, false},
		{"last line with a bad checksum", func(l []string) string {
			return l[0] + "\n" + l[1] + "\n" + "00000000" + l[2][8:] + "\n"
		}, 2, false},
		{"last line without its newline", func(l []string) string {
			return l[0] + "\n" + l[1] + "\n" + l[2]
		}, 3, false},
		{"damaged middle line", func(l []string) string {
			return l[0] + "\n" + l[1][:10] + "\n" + l[2] + "\n"
		}, 0, true},
		{"edited middle line", func(l []string) string {
			return l[0] + "\n" + strings.Replace(l[1], `"epoch":2`, `"epoch":9`, 1) + "\n" + l[2] + "\n"
		}, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "journal.log")
			j, err := OpenJournal(path, nil)
			if err != nil {
				t.Fatal(err)
			}
			for epoch := int64(1); epoch <= 3; epoch++ {
				appendAll(t, j, Record{Type: RecordAccepted, Activation: Activation{DeploymentUID: "d", Epoch: epoch}})
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
			if err := os.WriteFile(path, []byte(tc.damage(lines)), 0o600); err != nil {
				t.Fatal(err)
			}
			j, err = OpenJournal(path, nil)
			if tc.corrupt {
				if !errors.Is(err, ErrCorrupt) {
					t.Fatalf("open = %v, want ErrCorrupt", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(j.Records()) != tc.want {
				t.Fatalf("kept %d records, want %d", len(j.Records()), tc.want)
			}
			// The torn line is gone from disk, so the next append follows
			// the last good record.
			appendAll(t, j, Record{Type: RecordAccepted, Activation: Activation{DeploymentUID: "d", Epoch: 4}})
			j, err = OpenJournal(path, nil)
			if err != nil {
				t.Fatalf("reopen after repair: %v", err)
			}
			if len(j.Records()) != tc.want+1 {
				t.Errorf("after repair and append: %d records, want %d", len(j.Records()), tc.want+1)
			}
		})
	}
}

func TestJournalQueries(t *testing.T) {
	j, err := OpenJournal(filepath.Join(t.TempDir(), "journal.log"), nil)
	if err != nil {
		t.Fatal(err)
	}
	a1 := Activation{DeploymentUID: "d", Epoch: 1, Revision: testRev1}
	a2 := Activation{DeploymentUID: "d", Epoch: 2, Revision: "r-2"}
	appendAll(t, j,
		Record{Type: RecordAccepted, Activation: a1, Recovery: &Recovery{TargetRevision: "r-0"}},
		Record{Type: RecordCommitted, Activation: a1},
		Record{Type: RecordAccepted, Activation: a2, Recovery: &Recovery{TargetRevision: testRev1,
			RevokedPrefixes: []string{testPrefix}}},
		Record{Type: RecordApplyFailed, Activation: a2, Detail: "timeout"},
		Record{Type: RecordRecovered, Activation: a2},
	)
	if high, ok := j.HighWater("d"); !ok || high != 2 {
		t.Errorf("HighWater = %d, %v", high, ok)
	}
	if _, ok := j.HighWater(otherID); ok {
		t.Error("another deployment has a high water mark")
	}
	if !j.Failed("d", 2) || j.Failed("d", 1) {
		t.Error("Failed misreports epochs")
	}
	if rec, _ := j.LatestRecovery(); rec.TargetRevision != testRev1 || len(rec.RevokedPrefixes) != 1 {
		t.Errorf("LatestRecovery = %+v", rec)
	}
	got := j.Epochs("d", 16)
	if len(got) != 2 || got[0].Epoch != 2 || got[0].Stage != RecordRecovered || got[1].Stage != RecordCommitted {
		t.Fatalf("Epochs = %+v", got)
	}
	if got[0].Recovery == nil || got[0].Recovery.TargetRevision != testRev1 {
		t.Errorf("epoch 2 lost its journaled recovery: %+v", got[0])
	}
	if got := j.Epochs("d", 1); len(got) != 1 || got[0].Epoch != 2 {
		t.Errorf("Epochs limited to one = %+v", got)
	}
	if err := j.SetSource("CRD"); err != nil {
		t.Fatal(err)
	}
	if err := j.SetSource("CRD"); err != nil {
		t.Fatal(err)
	}
	if j.Source() != "CRD" || len(j.Records()) != 6 {
		t.Errorf("SetSource journaled %d records, source %q", len(j.Records()), j.Source())
	}
}

func TestJournalRebind(t *testing.T) {
	j, err := OpenJournal(filepath.Join(t.TempDir(), "journal.log"), nil)
	if err != nil {
		t.Fatal(err)
	}
	appendAll(t, j, Record{Type: RecordAccepted, Activation: Activation{DeploymentUID: "old", Epoch: 4}})
	if err := j.Rebind("someone-else", "new"); !errors.Is(err, ErrRecoveryConflict) {
		t.Fatalf("rebind from the wrong UID = %v", err)
	}
	if err := j.Rebind("old", "new"); err != nil {
		t.Fatal(err)
	}
	if j.BoundDeployment() != "new" {
		t.Errorf("bound to %q after rebind", j.BoundDeployment())
	}
}

func TestJournalLatestTime(t *testing.T) {
	c := &clock{t: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)}
	j, err := OpenJournal(filepath.Join(t.TempDir(), "journal.log"), c.Now)
	if err != nil {
		t.Fatal(err)
	}
	appendAll(t, j, Record{Type: RecordSource, Source: "CRD"})
	c.set(c.Now().Add(-time.Hour))
	appendAll(t, j, Record{Type: RecordSource, Source: "ConfigMap"})
	if got := j.LatestTime(); !got.Equal(time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)) {
		t.Errorf("LatestTime = %v", got)
	}
}
