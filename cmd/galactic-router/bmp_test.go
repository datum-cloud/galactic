// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"testing"
	"time"

	api "github.com/osrg/gobgp/v4/api"

	"go.datum.net/galactic/internal/config"
	"go.datum.net/galactic/internal/runtime/gobgp"
)

func TestBMPConfigFromRouter(t *testing.T) {
	t.Run("no stations disables BMP", func(t *testing.T) {
		got, err := bmpConfigFromRouter(config.NewRouterConfig(), "node-a")
		if err != nil {
			t.Fatalf("err = %v", err)
		}
		if len(got.Stations) != 0 || got.Observer != nil {
			t.Errorf("got %+v, want the zero BMPConfig", got)
		}
	})

	t.Run("stations", func(t *testing.T) {
		t.Setenv(config.EnvRouterBMPStations, "gobmp:5000,[fc00:0:7::1]:5001")
		t.Setenv(config.EnvRouterBMPPolicy, "all")
		t.Setenv(config.EnvRouterBMPStatisticsInterval, "30s")
		got, err := bmpConfigFromRouter(config.NewRouterConfig(), "node-a")
		if err != nil {
			t.Fatalf("err = %v", err)
		}
		want := []gobgp.BMPStation{{Host: "gobmp", Port: 5000}, {Host: "fc00:0:7::1", Port: 5001}}
		if len(got.Stations) != len(want) || got.Stations[0] != want[0] || got.Stations[1] != want[1] {
			t.Errorf("Stations = %v, want %v", got.Stations, want)
		}
		if got.Policy != api.AddBmpRequest_MONITORING_POLICY_ALL {
			t.Errorf("Policy = %v, want ALL", got.Policy)
		}
		if got.StatisticsInterval != 30*time.Second {
			t.Errorf("StatisticsInterval = %v, want 30s", got.StatisticsInterval)
		}
		if got.SysName != "node-a" {
			t.Errorf("SysName = %q, want node-a", got.SysName)
		}
		if got.Observer == nil {
			t.Error("Observer = nil, want the gauge observer")
		}
	})

	t.Run("bad policy", func(t *testing.T) {
		t.Setenv(config.EnvRouterBMPStations, "gobmp:5000")
		t.Setenv(config.EnvRouterBMPPolicy, "both")
		if _, err := bmpConfigFromRouter(config.NewRouterConfig(), "node-a"); err == nil {
			t.Error("err = nil, want an error for an unknown policy")
		}
	})
}
