// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

// TestSetupGatewayDatapath_InvalidAddressIsError covers the address-parse
// failure path, which runs before any kernel/eBPF interaction -- no root
// needed. Unlike cmd/galactic-router's removed identically-named test
// file, there is no "empty interface is a no-op" case to cover here: this
// binary's config.GatewayConfig.Validate rejects an empty
// PublicInterface/SRv6Address before setupGatewayDatapath is ever called.
func TestSetupGatewayDatapath_InvalidAddressIsError(t *testing.T) {
	_, err := setupGatewayDatapath("eth0", "not-an-ip-address", prometheus.NewRegistry())
	if err == nil {
		t.Error("setupGatewayDatapath with an invalid SRv6 address: want an error, got nil")
	}
}
