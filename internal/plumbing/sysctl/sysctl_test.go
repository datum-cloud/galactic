// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package sysctl

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func TestConfigureInterfaceSysctls_nonexistentInterface(t *testing.T) {
	// Use a name guaranteed to not exist on any real system.
	// gosysctl.Set will fail for every sysctl, but the function
	// must still return nil (gracefully skipping missing entries).
	const fakeIf = "this_interface_does_not_exist_xk9z2m"

	var buf bytes.Buffer
	origLogger := logger
	logger = slog.New(slog.NewTextHandler(&buf, nil))
	defer func() { logger = origLogger }()

	if err := ConfigureInterfaceSysctls(fakeIf); err != nil {
		t.Fatalf("expected nil error for nonexistent interface, got: %v", err)
	}

	logs := buf.String()
	// Verify that a WARN was logged for each failed sysctl
	if !strings.Contains(logs, "failed to set sysctl") {
		t.Errorf("expected WARN log for failed sysctl, got: %q", logs)
	}
}

func TestConfigureInterfaceSysctls_returnsNil(t *testing.T) {
	// Even when some sysctls fail to set, the function must return nil.
	const fakeIf = "nonexistent_iface_abc123"

	if err := ConfigureInterfaceSysctls(fakeIf); err != nil {
		t.Fatalf("ConfigureInterfaceSysctls must always return nil, got error: %v", err)
	}
}

func TestConfigureTapSysctls_returnsNil(t *testing.T) {
	// Same guarantee: ConfigureTapSysctls must always return nil.
	const fakeIf = "nonexistent_tap_xyz789"

	if err := ConfigureTapSysctls(fakeIf); err != nil {
		t.Fatalf("ConfigureTapSysctls must always return nil, got error: %v", err)
	}
}

func TestInterfaceSettings_hasAllEntries(t *testing.T) {
	// Verify that interfaceSettings contains all expected sysctl types.
	expected := map[string]bool{
		"rp_filter":  false,
		"forwarding": false,
		"proxy_arp":  false,
		"proxy_ndp":  false,
	}
	for _, entry := range interfaceSettings {
		for name := range expected {
			if strings.Contains(entry.format, name) {
				expected[name] = true
			}
		}
	}
	for name, found := range expected {
		if !found {
			t.Errorf("interfaceSettings missing expected sysctl: %s", name)
		}
	}
}
