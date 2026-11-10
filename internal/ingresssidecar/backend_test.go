// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package ingresssidecar

import (
	"testing"

	"go.datum.net/galactic/internal/plumbing/ebpf/egressroutemap"
)

func TestNewKernelBackend_AcceptsADefaultRouteToBackendSIDs(t *testing.T) {
	NewKernelBackend()

	if !egressroutemap.DefaultRouteAccepted() {
		t.Error("the kernel backend left default routes rejected, so every backend SID resolved from " +
			"Envoy's pod namespace, whose only route is the default, would be refused")
	}
}
