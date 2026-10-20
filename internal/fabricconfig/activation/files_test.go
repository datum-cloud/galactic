// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package activation

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestBindIdentity(t *testing.T) {
	dir := t.TempDir()
	want := Identity{NodeUID: testNode, MachineID: testMachine, ClusterID: testCluster}
	if _, err := BindIdentity(dir, Identity{MachineID: testMachine}); !errors.Is(err, ErrIdentityMismatch) {
		t.Fatalf("first bind without a node or cluster = %v", err)
	}
	got, err := BindIdentity(dir, want)
	if err != nil {
		t.Fatal(err)
	}
	if got.Nonce == "" {
		t.Error("no nonce recorded")
	}
	for _, tc := range []struct {
		name string
		id   Identity
		ok   bool
	}{
		{"same identity", want, true},
		{"API unreachable", Identity{MachineID: testMachine}, true},
		{"copied to another machine", Identity{NodeUID: testNode, MachineID: otherID, ClusterID: testCluster}, false},
		{"replacement Node", Identity{NodeUID: otherID, MachineID: testMachine, ClusterID: testCluster}, false},
		{"another cluster", Identity{NodeUID: testNode, MachineID: testMachine, ClusterID: otherID}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			again, err := BindIdentity(dir, tc.id)
			if tc.ok {
				if err != nil {
					t.Fatal(err)
				}
				if again.Nonce != got.Nonce {
					t.Error("the nonce changed")
				}
				return
			}
			if !errors.Is(err, ErrIdentityMismatch) {
				t.Fatalf("bind = %v, want ErrIdentityMismatch", err)
			}
		})
	}
}

func TestReadMachineID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "machine-id")
	if err := os.WriteFile(path, []byte("  \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadMachineID(path); err == nil {
		t.Error("an empty machine ID was accepted")
	}
	if err := os.WriteFile(path, []byte("abc123\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if id, err := ReadMachineID(path); err != nil || id != "abc123" {
		t.Errorf("ReadMachineID = %q, %v", id, err)
	}
}

func testCheckpoint() Checkpoint {
	cfg := "router bgp 64500\n"
	sum := sha256.Sum256([]byte(cfg))
	return Checkpoint{
		Activation: Activation{DeploymentUID: testDeployment, Epoch: 1, Revision: testRev1},
		Config:     cfg, ConfigDigest: hex.EncodeToString(sum[:]),
		SemanticsVersion: "1", FRRVersion: "10.7.1",
		BootAuthorizedUntil: time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC),
	}
}

func TestCheckpoint(t *testing.T) {
	dir := t.TempDir()
	if _, err := ReadCheckpoint(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing checkpoint = %v", err)
	}
	if err := WriteCheckpoint(dir, testCheckpoint()); err != nil {
		t.Fatal(err)
	}
	got, err := ReadCheckpoint(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got.Config != testCheckpoint().Config || got.Activation != testCheckpoint().Activation {
		t.Errorf("round trip = %+v", got)
	}

	for _, tc := range []struct {
		name   string
		tamper func(map[string]any)
	}{
		{"edited configuration", func(m map[string]any) { m["config"] = "router bgp 64501\n" }},
		{"extended boot authorization", func(m map[string]any) { m["bootAuthorizedUntil"] = "2099-01-01T00:00:00Z" }},
		{"configuration that does not match its digest", func(m map[string]any) {
			m["config"] = "router bgp 64501\n"
			delete(m, "sum")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := WriteCheckpoint(dir, testCheckpoint()); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "checkpoint.json")
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var m map[string]any
			if err := json.Unmarshal(data, &m); err != nil {
				t.Fatal(err)
			}
			tc.tamper(m)
			if _, ok := m["sum"]; !ok {
				// Recompute the sum so only the configuration digest is wrong.
				var c Checkpoint
				raw, _ := json.Marshal(m)
				if err := json.Unmarshal(raw, &c); err != nil {
					t.Fatal(err)
				}
				s, err := c.sum()
				if err != nil {
					t.Fatal(err)
				}
				m["sum"] = s
			}
			data, err = json.Marshal(m)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := ReadCheckpoint(dir); !errors.Is(err, ErrCheckpointInvalid) {
				t.Fatalf("read = %v, want ErrCheckpointInvalid", err)
			}
		})
	}
}
