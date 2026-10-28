// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package installer

import (
	"errors"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
)

// gatherPrefixed returns the families on the instrumentation library's
// registry whose names start with prefix. The registry is shared by the whole
// test process, and a test that ran Run against a real datapath leaves map
// collectors behind whose maps are closed, so collection errors from other
// families are ignored. An error from a family under prefix fails the test.
func gatherPrefixed(t *testing.T, prefix string) []*dto.MetricFamily {
	t.Helper()
	families, err := ctrlmetrics.Registry.Gather()
	var errs prometheus.MultiError
	if !errors.As(err, &errs) && err != nil {
		errs = prometheus.MultiError{err}
	}
	for _, e := range errs {
		if strings.Contains(e.Error(), `fqName: "`+prefix) {
			t.Fatal(e)
		}
	}
	var out []*dto.MetricFamily
	for _, f := range families {
		if strings.HasPrefix(f.GetName(), prefix) {
			out = append(out, f)
		}
	}
	return out
}
