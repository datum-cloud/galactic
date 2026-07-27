// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package vmtap

import (
	"strings"
	"testing"
)

const validStdin = `{
	"cniVersion": "1.0.0",
	"name": "cilium",
	"type": "vmtap-cni",
	"prevResult": {
		"cniVersion": "1.0.0",
		"interfaces": [{"name": "eth0", "mac": "aa:bb:cc:dd:ee:ff", "mtu": 1500}],
		"ips": [{"address": "10.0.0.5/24", "gateway": "10.0.0.1", "interface": 0}]
	}
}`

func TestParseConfMissingPrevResult(t *testing.T) {
	_, err := parseConf([]byte(`{"cniVersion": "1.0.0", "name": "cilium", "type": "vmtap-cni"}`))
	if err == nil {
		t.Fatal("expected error for missing prevResult, got nil")
	}
	if !strings.Contains(err.Error(), "chained") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestParseConfInvalidJSON(t *testing.T) {
	_, err := parseConf([]byte(`not json`))
	if err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
}

func TestParseConfDefaults(t *testing.T) {
	conf, err := parseConf([]byte(validStdin))
	if err != nil {
		t.Fatalf("parseConf() = %v, want nil", err)
	}
	if conf.TapName != defaultTapName {
		t.Errorf("TapName = %q, want %q", conf.TapName, defaultTapName)
	}
	if conf.FilterPriority != defaultFilterPriority {
		t.Errorf("FilterPriority = %d, want %d", conf.FilterPriority, defaultFilterPriority)
	}
	if !conf.enabled() {
		t.Error("enabled() = false, want true (default)")
	}
	if conf.PrevResult == nil {
		t.Fatal("PrevResult = nil, want parsed result")
	}
}

func TestParseConfExplicitFields(t *testing.T) {
	stdin := `{
		"cniVersion": "1.0.0",
		"name": "cilium",
		"type": "vmtap-cni",
		"enabled": false,
		"tap_name": "vmtap1",
		"filter_priority": 42,
		"prevResult": {
			"cniVersion": "1.0.0",
			"interfaces": [{"name": "eth0", "mac": "aa:bb:cc:dd:ee:ff", "mtu": 1500}]
		}
	}`

	conf, err := parseConf([]byte(stdin))
	if err != nil {
		t.Fatalf("parseConf() = %v, want nil", err)
	}
	if conf.TapName != "vmtap1" {
		t.Errorf("TapName = %q, want %q", conf.TapName, "vmtap1")
	}
	if conf.FilterPriority != 42 {
		t.Errorf("FilterPriority = %d, want %d", conf.FilterPriority, 42)
	}
	if conf.enabled() {
		t.Error("enabled() = true, want false (explicitly disabled)")
	}
}
