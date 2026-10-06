// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package sysctl

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
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

// fakeProcSys builds a procfs sysctl root under a temporary directory holding
// the IPv6 forwarding sysctls for iface and all, each set to value, and points
// the FIB-lookup helpers at it for the rest of the test.
func fakeProcSys(t *testing.T, iface, value string, mode os.FileMode) {
	t.Helper()
	root := t.TempDir()
	for _, dev := range []string{iface, "all"} {
		dir := filepath.Join(root, "net", "ipv6", "conf", dev)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, "forwarding")
		if err := os.WriteFile(path, []byte(value+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
	}
	orig := procSysPath
	if err := SetProcSysPath(root); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { procSysPath = orig })
}

func TestConfigureFIBLookupUplinkSysctls(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores the read-only file modes these cases depend on")
	}
	const iface = "uplink0"
	tests := []struct {
		name    string
		value   string
		mode    os.FileMode
		iface   string
		wantErr bool
	}{
		{name: "writable, off", value: "0", mode: 0o644, iface: iface},
		{name: "read-only, already on", value: "1", mode: 0o444, iface: iface},
		// The defect in #586: the write fails, forwarding stays off, and the
		// helper used to report success anyway.
		{name: "read-only, off", value: "0", mode: 0o444, iface: iface, wantErr: true},
		{name: "interface missing", value: "1", mode: 0o644, iface: "missing0", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeProcSys(t, iface, tt.value, tt.mode)
			err := ConfigureFIBLookupUplinkSysctls(tt.iface)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ConfigureFIBLookupUplinkSysctls(%q) error = %v, wantErr %v", tt.iface, err, tt.wantErr)
			}
			if err != nil {
				return
			}
			for _, dev := range []string{tt.iface, "all"} {
				got, readErr := os.ReadFile(filepath.Join(procSysPath, "net", "ipv6", "conf", dev, "forwarding"))
				if readErr != nil {
					t.Fatal(readErr)
				}
				if strings.TrimSpace(string(got)) != "1" {
					t.Errorf("net.ipv6.conf.%s.forwarding = %q, want 1", dev, got)
				}
			}
		})
	}
}

func TestSetProcSysPath_missingDirectory(t *testing.T) {
	orig := procSysPath
	t.Cleanup(func() { procSysPath = orig })
	if err := SetProcSysPath(filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Fatal("SetProcSysPath accepted a directory that does not exist")
	}
	if procSysPath != orig {
		t.Errorf("procSysPath changed to %q after a rejected path", procSysPath)
	}
}
