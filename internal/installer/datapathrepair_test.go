// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package installer

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"go.datum.net/galactic/internal/gc"
	"go.datum.net/galactic/internal/plumbing/ebpf/attachreg"
	"go.datum.net/galactic/internal/plumbing/ebpf/prog"
)

// withRepairFn replaces repairDatapathFn for one test with fn and shrinks the
// retry intervals so a retrying test finishes quickly.
func withRepairFn(
	t *testing.T, fn func(context.Context, client.Client, gc.DatapathRepairConfig) (gc.DatapathRepairResult, error),
) {
	t.Helper()
	origFn, origRetry, origMax := repairDatapathFn, datapathRepairRetryInterval, datapathRepairMaxRetryInterval
	t.Cleanup(func() {
		repairDatapathFn, datapathRepairRetryInterval, datapathRepairMaxRetryInterval = origFn, origRetry, origMax
	})
	repairDatapathFn = fn
	datapathRepairRetryInterval = time.Millisecond
	datapathRepairMaxRetryInterval = 4 * time.Millisecond
}

// repairState is an ebpfDatapathState with a loaded datapath and a client.
func repairState() ebpfDatapathState {
	return ebpfDatapathState{
		objs:      &prog.UsidObjects{},
		k8sClient: fake.NewClientBuilder().Build(),
		namespace: testNamespace,
		nodeName:  "worker-a",
		egress:    attachreg.EgressConfig{ShardSIDs: "2001:db8:ff01:9:e001::"},
	}
}

func TestStartDatapathRepair_RetriesUntilAPassSucceeds(t *testing.T) {
	var calls atomic.Int32
	var gotCfg atomic.Value
	done := make(chan struct{})
	withRepairFn(t, func(
		_ context.Context, _ client.Client, cfg gc.DatapathRepairConfig,
	) (gc.DatapathRepairResult, error) {
		gotCfg.Store(cfg)
		if calls.Add(1) < 3 {
			return gc.DatapathRepairResult{}, errors.New("transient")
		}
		close(done)
		return gc.DatapathRepairResult{}, nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sem := make(chan struct{}, 1)
	startDatapathRepair(ctx, sem, repairState())

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("repair made %d passes, want it to retry until the third succeeds", calls.Load())
	}
	time.Sleep(20 * time.Millisecond)
	if n := calls.Load(); n != 3 {
		t.Errorf("repair made %d passes, want exactly 3 (no pass after the first success)", n)
	}

	cfg := gotCfg.Load().(gc.DatapathRepairConfig)
	if cfg.NodeName != "worker-a" || cfg.Namespace != testNamespace || cfg.Egress.ShardSIDs == "" {
		t.Errorf("repair config = %+v, want the state's node, namespace and egress config", cfg)
	}
	if cfg.ForeignTableID == nil || !cfg.ForeignTableID(sidecarReturnTableBase+1) {
		t.Error("repair config does not treat the sidecar return tables as foreign")
	}
	select {
	case sem <- struct{}{}:
	default:
		t.Error("semaphore still held after the startup repair finished")
	}
}

func TestStartDatapathRepair_DisabledWithoutDatapathOrClient(t *testing.T) {
	var calls atomic.Int32
	withRepairFn(t, func(context.Context, client.Client, gc.DatapathRepairConfig) (gc.DatapathRepairResult, error) {
		calls.Add(1)
		return gc.DatapathRepairResult{}, nil
	})

	noDatapath := repairState()
	noDatapath.objs = nil
	noClient := repairState()
	noClient.k8sClient = nil

	sem := make(chan struct{}, 1)
	for _, st := range []ebpfDatapathState{noDatapath, noClient} {
		startDatapathRepair(context.Background(), sem, st)
		repairDatapathOnTick(context.Background(), sem, st)
	}
	time.Sleep(20 * time.Millisecond)
	if n := calls.Load(); n != 0 {
		t.Errorf("repair made %d passes, want none without a datapath and a client", n)
	}
}

// TestRepairDatapathOnTick_RunsOffTheCallersGoroutine covers a pass that
// blocks, as one waiting on unresolvable shards does: the tick must return at
// once, hold the semaphore for the pass, and skip while it is held.
func TestRepairDatapathOnTick_RunsOffTheCallersGoroutine(t *testing.T) {
	var calls atomic.Int32
	release := make(chan struct{})
	withRepairFn(t, func(context.Context, client.Client, gc.DatapathRepairConfig) (gc.DatapathRepairResult, error) {
		calls.Add(1)
		<-release
		return gc.DatapathRepairResult{}, nil
	})

	sem := make(chan struct{}, 1)
	returned := make(chan struct{})
	go func() {
		repairDatapathOnTick(context.Background(), sem, repairState())
		close(returned)
	}()
	select {
	case <-returned:
	case <-time.After(time.Second):
		t.Fatal("tick blocked on a pass that has not finished")
	}

	repairDatapathOnTick(context.Background(), sem, repairState())
	close(release)
	waitFor(t, func() bool { return len(sem) == 0 })
	if n := calls.Load(); n != 1 {
		t.Errorf("ticks ran %d passes, want 1: the second tick must skip while the first holds the semaphore", n)
	}
}

// TestStartDatapathRepair_RetriesWhileAttachmentsArePending covers attachments
// whose BGPRouter or BGPVRFInstance appears only after startup: the startup
// passes keep going until a pass finds nothing pending.
func TestStartDatapathRepair_RetriesWhileAttachmentsArePending(t *testing.T) {
	var calls atomic.Int32
	withRepairFn(t, func(context.Context, client.Client, gc.DatapathRepairConfig) (gc.DatapathRepairResult, error) {
		if calls.Add(1) < 4 {
			return gc.DatapathRepairResult{Pending: 2}, nil
		}
		return gc.DatapathRepairResult{Attachments: 2}, nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	startDatapathRepair(ctx, make(chan struct{}, 1), repairState())

	waitFor(t, func() bool { return calls.Load() >= 4 })
	time.Sleep(20 * time.Millisecond)
	if n := calls.Load(); n != 4 {
		t.Errorf("repair made %d passes, want 4: retried while pending, then stopped", n)
	}
}

// TestStartDatapathRepair_StopsRetryingPendingAfterTheLimit covers
// attachments that stay pending: the startup passes give up after
// datapathRepairPendingLimit and leave them to the GC tick.
func TestStartDatapathRepair_StopsRetryingPendingAfterTheLimit(t *testing.T) {
	var calls atomic.Int32
	withRepairFn(t, func(context.Context, client.Client, gc.DatapathRepairConfig) (gc.DatapathRepairResult, error) {
		calls.Add(1)
		return gc.DatapathRepairResult{Pending: 1}, nil
	})
	origLimit := datapathRepairPendingLimit
	t.Cleanup(func() { datapathRepairPendingLimit = origLimit })
	datapathRepairPendingLimit = 30 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	startDatapathRepair(ctx, make(chan struct{}, 1), repairState())

	waitFor(t, func() bool { return calls.Load() >= 2 })
	time.Sleep(100 * time.Millisecond)
	settled := calls.Load()
	time.Sleep(100 * time.Millisecond)
	if n := calls.Load(); n != settled {
		t.Errorf("repair still retrying (%d then %d passes) after the pending limit", settled, n)
	}
}

// waitFor polls cond until it holds or a second passes.
func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met within a second")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestIsSidecarReturnTable(t *testing.T) {
	tests := []struct {
		name    string
		tableID uint32
		want    bool
	}{
		{name: "BelowRange", tableID: sidecarReturnTableBase - 1, want: false},
		{name: "Base", tableID: sidecarReturnTableBase, want: true},
		{name: "Max", tableID: sidecarReturnTableMax, want: true},
		{name: "AboveRange", tableID: sidecarReturnTableMax + 1, want: false},
		{name: "TenantTable", tableID: 7, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isSidecarReturnTable(tt.tableID); got != tt.want {
				t.Errorf("isSidecarReturnTable(%#x) = %v, want %v", tt.tableID, got, tt.want)
			}
		})
	}
}
