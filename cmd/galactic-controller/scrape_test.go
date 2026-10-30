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
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	computev1alpha "go.datum.net/compute/api/v1alpha"
	cloudv1alpha1 "go.datum.net/galactic/api/cloud/v1alpha1"
	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
	cloudcontroller "go.datum.net/galactic/internal/cloud/controller"
	edgediag "go.datum.net/galactic/internal/edge/diag"
	networkingv1alpha "go.datum.net/network-services-operator/api/v1alpha"
)

// startup registers the series once per test process, as run does once per
// process, so repeated runs of TestMetricsScrape share them.
var startup sync.Once

// TestMetricsScrape scrapes what the manager serves at /metrics, the
// instrumentation library's registry, once it holds what run adds: the
// instance attachment collector and, with --edge, the failure counters and
// the state collector, here reading an empty cluster. It lints them too.
func TestMetricsScrape(t *testing.T) {
	startup.Do(func() {
		scheme := runtime.NewScheme()
		utilruntime.Must(clientgoscheme.AddToScheme(scheme))
		utilruntime.Must(galacticv1alpha1.AddToScheme(scheme))
		utilruntime.Must(cloudv1alpha1.AddToScheme(scheme))
		utilruntime.Must(networkingv1alpha.AddToScheme(scheme))
		utilruntime.Must(computev1alpha.AddToScheme(scheme))
		reader := fake.NewClientBuilder().WithScheme(scheme).Build()
		metrics.MustRegister(&cloudcontroller.InstanceAttachmentCollector{Reader: reader})
		edgediag.NewMetrics(edgediag.RoleCore)
		metrics.MustRegister(&edgediag.StateCollector{Reader: reader})
	})
	instrumenttest.AssertScrapes(t, metrics.Handler())
	instrumenttest.Lint(t)
}
