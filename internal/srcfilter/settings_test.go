// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package srcfilter

import (
	"net/netip"
	"slices"
	"testing"

	"go.datum.net/galactic/internal/config"
)

const testDomain = "2001:db8::/32"

func TestLoadSettings(t *testing.T) {
	tests := []struct {
		name      string
		env       map[string]string
		want      Settings
		wantError bool
	}{
		{"Unset", nil, Settings{Mode: ModeOff}, false},
		{"OffIgnoresRest", map[string]string{
			config.EnvCNISRv6SourceFilter:   modeNameOff,
			config.EnvCNISRv6SourceBinding:  "bogus",
			config.EnvCNISRv6DomainPrefixes: "nope",
		}, Settings{Mode: ModeOff}, false},
		{"AUDIT", map[string]string{
			config.EnvCNISRv6SourceFilter:     "AUDIT",
			config.EnvCNISRv6DomainPrefixes:   " 2001:db8::/32, ,fd00::1/48",
			config.EnvCNISRv6SourceAllowExtra: "2001:db8:ffff::/48",
		}, Settings{
			Mode:           ModeAudit,
			DomainPrefixes: []netip.Prefix{netip.MustParsePrefix(testDomain), netip.MustParsePrefix("fd00::/48")},
			ExtraSources:   []netip.Prefix{netip.MustParsePrefix("2001:db8:ffff::/48")},
		}, false},
		{"EnforceLoose", map[string]string{
			config.EnvCNISRv6SourceFilter:   modeNameEnforce,
			config.EnvCNISRv6DomainPrefixes: testDomain,
			config.EnvCNISRv6SourceBinding:  bindingNameLoose,
		}, Settings{
			Mode:           ModeEnforce,
			DomainPrefixes: []netip.Prefix{netip.MustParsePrefix(testDomain)},
			Binding:        BindingLoose,
		}, false},
		{"EnforceWithoutDomain", map[string]string{config.EnvCNISRv6SourceFilter: modeNameEnforce}, Settings{}, true},
		{"AuditWithoutDomain", map[string]string{config.EnvCNISRv6SourceFilter: modeNameAudit}, Settings{}, true},
		{"UnknownMode", map[string]string{config.EnvCNISRv6SourceFilter: "drop"}, Settings{}, true},
		{"UnknownBinding", map[string]string{
			config.EnvCNISRv6SourceFilter:   modeNameAudit,
			config.EnvCNISRv6DomainPrefixes: testDomain,
			config.EnvCNISRv6SourceBinding:  "tight",
		}, Settings{}, true},
		{"IPv4Domain", map[string]string{
			config.EnvCNISRv6SourceFilter:   modeNameAudit,
			config.EnvCNISRv6DomainPrefixes: "10.0.0.0/8",
		}, Settings{}, true},
		{"FabricNextHops", map[string]string{
			config.EnvCNISRv6SourceFilter:   modeNameAudit,
			config.EnvCNISRv6DomainPrefixes: testDomain,
			config.EnvCNISRv6FabricNextHops: "fe80::/10,fd00:f::/64",
		}, Settings{
			Mode:           ModeAudit,
			DomainPrefixes: []netip.Prefix{netip.MustParsePrefix(testDomain)},
			FabricNextHops: []netip.Prefix{netip.MustParsePrefix("fe80::/10"), netip.MustParsePrefix("fd00:f::/64")},
		}, false},
		{"BadFabricNextHops", map[string]string{
			config.EnvCNISRv6SourceFilter:   modeNameAudit,
			config.EnvCNISRv6DomainPrefixes: testDomain,
			config.EnvCNISRv6FabricNextHops: "10.0.0.0/8",
		}, Settings{}, true},
		{"BadExtra", map[string]string{
			config.EnvCNISRv6SourceFilter:     modeNameAudit,
			config.EnvCNISRv6DomainPrefixes:   testDomain,
			config.EnvCNISRv6SourceAllowExtra: "2001:db8::1",
		}, Settings{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := LoadSettings(func(k string) string { return tt.env[k] })
			if (err != nil) != tt.wantError {
				t.Fatalf("LoadSettings() error = %v, wantError %v", err, tt.wantError)
			}
			if tt.wantError {
				return
			}
			if got.Mode != tt.want.Mode || got.Binding != tt.want.Binding ||
				!slices.Equal(got.DomainPrefixes, tt.want.DomainPrefixes) ||
				!slices.Equal(got.ExtraSources, tt.want.ExtraSources) ||
				!slices.Equal(got.FabricNextHops, tt.want.FabricNextHops) {
				t.Errorf("LoadSettings() = %+v, want %+v", got, tt.want)
			}
		})
	}
}
