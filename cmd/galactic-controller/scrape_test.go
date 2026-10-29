// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"sync"
	"testing"

	"go.miloapis.com/instrumentation/instrumenttest"
	"go.miloapis.com/instrumentation/metrics"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
	edgediag "go.datum.net/galactic/internal/edge/diag"
)

// startup registers the series once per test process, as run does once per
// process, so repeated runs of TestMetricsScrape share them.
var startup sync.Once

// TestMetricsScrape scrapes what the manager serves at /metrics, the
// instrumentation library's registry, once it holds what run adds with
// --edge: the failure counters and the state collector, here reading an
// empty cluster. It lints them too.
func TestMetricsScrape(t *testing.T) {
	startup.Do(func() {
		scheme := runtime.NewScheme()
		utilruntime.Must(galacticv1alpha1.AddToScheme(scheme))
		edgediag.NewMetrics(edgediag.RoleCore)
		metrics.MustRegister(&edgediag.StateCollector{Reader: fake.NewClientBuilder().WithScheme(scheme).Build()})
	})
	instrumenttest.AssertScrapes(t, metrics.Handler())
	instrumenttest.Lint(t)
}
