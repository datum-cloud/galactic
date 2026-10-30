// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package installer

import (
	"errors"
	"os"
	"testing"

	"go.datum.net/galactic/internal/hostgw"
	"go.datum.net/galactic/internal/plumbing/ebpf/metrics"
)

// TestMain keeps Run's host link repair, which every test calling Run
// starts, off the test host's real links and VRF lock.
func TestMain(m *testing.M) {
	reenslaveHostLinksFn = func() (hostgw.MasterlessResult, error) { return hostgw.MasterlessResult{}, nil }
	os.Exit(m.Run())
}

// hostLinkMetric returns the value of the unlabeled host link series name.
func hostLinkMetric(t *testing.T, name string) float64 {
	t.Helper()
	for _, f := range gatherPrefixed(t, name) {
		if f.GetName() != name || len(f.GetMetric()) != 1 {
			continue
		}
		m := f.GetMetric()[0]
		if m.GetGauge() != nil {
			return m.GetGauge().GetValue()
		}
		return m.GetCounter().GetValue()
	}
	t.Fatalf("series %s not found", name)
	return 0
}

// TestRunHostLinkRepairRecordsPass records a pass that re-enslaved two links
// and left one masterless, then one that fixed the last: the counter adds
// up and the gauge follows the latest pass.
func TestRunHostLinkRepairRecordsPass(t *testing.T) {
	orig := reenslaveHostLinksFn
	t.Cleanup(func() { reenslaveHostLinksFn = orig })
	m := metrics.NewHostLinks()
	reenslaved0 := hostLinkMetric(t, "galactic_cni_host_link_reenslaved_total")

	reenslaveHostLinksFn = func() (hostgw.MasterlessResult, error) {
		return hostgw.MasterlessResult{Reenslaved: 2, Masterless: 1}, errors.New("one link failed")
	}
	runHostLinkRepair(m)
	if got := hostLinkMetric(t, "galactic_cni_host_links_masterless"); got != 1 {
		t.Errorf("masterless gauge = %v, want 1", got)
	}

	reenslaveHostLinksFn = func() (hostgw.MasterlessResult, error) {
		return hostgw.MasterlessResult{Reenslaved: 1}, nil
	}
	runHostLinkRepair(m)
	if got := hostLinkMetric(t, "galactic_cni_host_links_masterless"); got != 0 {
		t.Errorf("masterless gauge = %v, want 0", got)
	}
	if got := hostLinkMetric(t, "galactic_cni_host_link_reenslaved_total") - reenslaved0; got != 3 {
		t.Errorf("re-enslaved counter rose by %v, want 3", got)
	}
}

// TestStartHostLinkRepairDropsOverlappingTick starts a pass while another
// holds the semaphore: the tick is dropped.
func TestStartHostLinkRepairDropsOverlappingTick(t *testing.T) {
	orig := reenslaveHostLinksFn
	t.Cleanup(func() { reenslaveHostLinksFn = orig })
	ran := make(chan struct{}, 1)
	reenslaveHostLinksFn = func() (hostgw.MasterlessResult, error) {
		ran <- struct{}{}
		return hostgw.MasterlessResult{}, nil
	}
	sem := make(chan struct{}, 1)
	sem <- struct{}{}
	startHostLinkRepair(sem, nil)
	select {
	case <-ran:
		t.Fatal("a pass ran while another held the semaphore")
	default:
	}
	<-sem
	startHostLinkRepair(sem, nil)
	<-ran
}
