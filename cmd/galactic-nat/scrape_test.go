// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"sync"
	"testing"

	"go.miloapis.com/instrumentation/instrumenttest"
	"go.miloapis.com/instrumentation/metrics"

	"go.datum.net/galactic/internal/config"
	"go.datum.net/galactic/internal/plumbing/ebpf/natattach"
	"go.datum.net/galactic/internal/plumbing/ebpf/xdpdispatch"
)

// startup registers the series once per test process, as run does once per
// process, so repeated runs of TestMetricsScrape share them.
var startup sync.Once

// TestMetricsScrape scrapes what the manager serves at /metrics, the
// instrumentation library's registry, once it holds the series run creates
// at startup that need no kernel: the shard state collector of a disabled
// datapath, and the lease and uplink metrics setupNatDatapath creates. It
// lints them too. The map and NIC queue collectors read a loaded datapath, so
// they are left out.
func TestMetricsScrape(t *testing.T) {
	startup.Do(func() {
		metrics.MustRegister(newShardStateCollector(disabledDatapath{}, false, config.NATXDPAttachDispatch))
		xdpdispatch.NewLeaseMetrics(metricsNamespace)
		natattach.NewUplinkResolveErrors(metricsNamespace)
	})
	instrumenttest.AssertScrapes(t, metrics.Handler())
	instrumenttest.Lint(t)
}
