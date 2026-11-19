// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"testing"

	"go.miloapis.com/instrumentation/instrumenttest"
	"go.miloapis.com/instrumentation/metrics"

	"go.datum.net/galactic/internal/worker"
)

// TestMetricsScrape scrapes what the manager serves at /metrics once run has
// created every series, and lints them.
func TestMetricsScrape(t *testing.T) {
	worker.InitMetrics()
	instrumenttest.AssertScrapes(t, metrics.Handler())
	instrumenttest.Lint(t)
}

func TestOptionsValidate(t *testing.T) {
	o := &options{nodeName: "node-a", allowlist: "a.yaml", claimLimit: 1,
		lease: worker.DefaultLease, renewInterval: worker.DefaultRenewInterval, hostGrace: worker.DefaultHostGrace}
	if err := o.validate(); err != nil {
		t.Fatalf("validate() = %v", err)
	}
	for name, mutate := range map[string]func(*options){
		"no node":         func(o *options) { o.nodeName = "" },
		"no allowlist":    func(o *options) { o.allowlist = "" },
		"no claims":       func(o *options) { o.claimLimit = 0 },
		"lease too short": func(o *options) { o.lease = o.renewInterval },
		"no host grace":   func(o *options) { o.hostGrace = 0 },
	} {
		bad := *o
		mutate(&bad)
		if bad.validate() == nil {
			t.Errorf("%s: validate() = nil, want an error", name)
		}
	}
}
