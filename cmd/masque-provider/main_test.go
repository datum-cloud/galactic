// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package main

import (
	"strings"
	"testing"

	"go.miloapis.com/instrumentation/instrumenttest"
	"go.miloapis.com/instrumentation/metrics"

	"go.datum.net/galactic/internal/edge/masque/service"
)

// TestMetricsScrape scrapes what --health-listen serves at /metrics, the
// instrumentation library's registry, and lints it.
func TestMetricsScrape(t *testing.T) {
	_ = service.HealthHandler(func() bool { return true })
	instrumenttest.AssertScrapes(t, metrics.Handler())
	instrumenttest.Lint(t)
}

func TestFlagsRequireGrantAuthority(t *testing.T) {
	base := make([]string, 0, 6)
	base = append(base, "--provider", "masque", "--authority", "masque.example.test")
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"NoAuthorityURL", base, "--grant-authority-url"},
		{"PlainHTTP", append(base, "--grant-authority-url", "http://authority.example.test"), "https://"},
		{"NoProvider", []string{"--authority", "masque.example.test"}, "--provider"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := newRootCommand()
			cmd.SetArgs(tt.args)
			cmd.SetOut(&strings.Builder{})
			cmd.SetErr(&strings.Builder{})
			err := cmd.Execute()
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Execute = %v, want an error naming %s", err, tt.want)
			}
		})
	}
}
