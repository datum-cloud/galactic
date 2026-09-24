// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"errors"
	"fmt"
	"reflect"
	"testing"

	"go.datum.net/galactic/internal/config"
	"go.datum.net/galactic/internal/plumbing/ebpf/natsrcfiltermap"
)

const (
	testUplinkA = "eth1"
	testUplinkB = "eth0"
)

func fakeIfindex(indexes map[string]int) func(string) (int, error) {
	return func(name string) (int, error) {
		if i, ok := indexes[name]; ok {
			return i, nil
		}
		return 0, errors.New("link not found")
	}
}

func TestUplinkSlots(t *testing.T) {
	many := make([]string, 33)
	for i := range many {
		many[i] = fmt.Sprintf("eth%d", i)
	}
	tests := []struct {
		name      string
		ifaces    []string
		want      map[uint32]uint8
		wantError bool
	}{
		{"ConfigurationOrder", []string{testUplinkA, testUplinkB}, map[uint32]uint8{3: 0, 2: 1}, false},
		{"Unresolvable", []string{testUplinkA, "missing"}, nil, true},
		{"TooMany", many, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := uplinkSlots(tt.ifaces, fakeIfindex(map[string]int{testUplinkB: 2, testUplinkA: 3}))
			if (err != nil) != tt.wantError {
				t.Fatalf("uplinkSlots error = %v, wantError = %v", err, tt.wantError)
			}
			if !tt.wantError && !reflect.DeepEqual(got, tt.want) {
				t.Errorf("uplinkSlots = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSetupSourceFilterRejectsUnknownMode(t *testing.T) {
	filter, fakes := natsrcfiltermap.NewFakeFilter()
	cfg := &config.NATConfig{SRv6SourceFilter: "strict"}
	if err := setupSourceFilter(cfg, filter); err == nil {
		t.Fatal("setupSourceFilter succeeded with an unknown mode, want error")
	}
	if fakes.Config.Len() != 0 || fakes.UplinkSlots.Len() != 0 {
		t.Error("setupSourceFilter wrote state before rejecting its mode")
	}
}
