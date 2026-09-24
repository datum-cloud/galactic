// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import "testing"

func TestNATConfigSRv6SourceFilter(t *testing.T) {
	tests := []struct {
		name      string
		value     string
		set       bool
		want      string
		wantError bool
	}{
		{"DefaultOff", "", false, NATSRv6SourceFilterOff, false},
		{"Audit", "audit", true, NATSRv6SourceFilterAudit, false},
		{"EnforceNormalised", " Enforce ", true, NATSRv6SourceFilterEnforce, false},
		{"Unknown", "strict", true, "strict", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(EnvNATNodeName, testNATNodeName)
			t.Setenv(EnvNATUplinkInterfaces, testNATIface)
			t.Setenv(EnvNATShardSID, testNATShardSID)
			t.Setenv(EnvNATShardPubAddr6, testNATShardPub)
			if tt.set {
				t.Setenv(EnvNATSRv6SourceFilter, tt.value)
			}

			cfg := NewNATConfig()
			if cfg.SRv6SourceFilter != tt.want {
				t.Errorf("SRv6SourceFilter = %q, want %q", cfg.SRv6SourceFilter, tt.want)
			}
			if err := cfg.Validate(); (err != nil) != tt.wantError {
				t.Errorf("Validate() error = %v, wantError = %v", err, tt.wantError)
			}
		})
	}
}
