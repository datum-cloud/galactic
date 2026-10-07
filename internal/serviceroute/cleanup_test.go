//go:build linux

// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package serviceroute

import (
	"errors"
	"fmt"
	"testing"

	"github.com/cilium/ebpf"
)

func TestCleanupDrainsFailedApplyRollbackBeforeFinalize(t *testing.T) {
	applyFailure := errors.New("route write failed")
	rollbackFailure := errors.New("access rollback failed")
	routes := &recordingTable{putErr: applyFailure}
	access := &recordingTable{deleteErr: rollbackFailure}
	programmer := testRouteProgrammer(routes, access, &recordingTable{})
	programmer.mapIDs = [7]ebpf.MapID{1, 2, 3, 4, 5, 6, 7}
	programmer.mapIDsValid = true
	programmer.readMapIDsFn = func(string) ([7]ebpf.MapID, error) { return programmer.mapIDs, nil }
	programmer.targetIndexFn = func(name string) (uint32, error) {
		switch name {
		case "consumer0":
			return 10, nil
		case "producer0":
			return 20, nil
		default:
			return 0, fmt.Errorf("unknown interface %q", name)
		}
	}
	intent := localTestIntent()

	err := programmer.Apply(intent)
	if !errors.Is(err, applyFailure) || !errors.Is(err, rollbackFailure) {
		t.Fatalf("Apply error = %v, want joined apply and rollback failures", err)
	}
	if len(programmer.pendingRollbacks[intentKey(intent)]) == 0 || programmer.syncFailures != 1 {
		t.Fatalf("pending rollback/failure count = %d/%d, want nonzero/1",
			len(programmer.pendingRollbacks[intentKey(intent)]), programmer.syncFailures)
	}
	if err := programmer.Finalize(); err == nil {
		t.Fatal("Finalize enabled policy with an unresolved Apply rollback")
	}

	if err := programmer.Cleanup(intent); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	if len(programmer.pendingRollbacks) != 0 || programmer.syncFailures != 0 {
		t.Fatalf("pending rollbacks/failure count after Cleanup = %d/%d, want 0/0",
			len(programmer.pendingRollbacks), programmer.syncFailures)
	}
	if err := programmer.Finalize(); err != nil {
		t.Fatalf("Finalize after successful Cleanup: %v", err)
	}
}
