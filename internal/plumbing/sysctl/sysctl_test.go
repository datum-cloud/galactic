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
// each of the given sysctls, by path segment, set to value with file mode
// mode, and points the FIB-lookup helpers at it for the rest of the test.
func fakeProcSys(t *testing.T, sysctls [][]string, value string, mode os.FileMode) string {
	t.Helper()
	root := t.TempDir()
	for _, segments := range sysctls {
		path := filepath.Join(append([]string{root}, segments...)...)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
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
	return root
}

const (
	testUplink = "uplink0"
	// testVLAN is a VLAN's name, whose dot a dotted sysctl key would read as a
	// separator.
	testVLAN = "bond0.100"
)

func TestConfigureFIBLookupUplinkSysctls(t *testing.T) {
	helpers := []struct {
		name    string
		fn      func(string) error
		sysctls func(string) [][]string
	}{
		{"IPv6", ConfigureFIBLookupUplinkSysctls, ipv6ForwardingSysctls},
		{"IPv4", ConfigureFIBLookupUplinkSysctlsIPv4, ipv4ForwardingSysctls},
	}
	tests := []struct {
		name     string
		present  string // interface the fake root holds sysctls for
		iface    string // interface the helper is asked to configure
		value    string
		readOnly bool
		wantErr  bool
	}{
		{name: "writable, off", present: testUplink, iface: testUplink, value: "0"},
		{name: "dotted interface name", present: testVLAN, iface: testVLAN, value: "0"},
		{name: "read-only, already on", present: testUplink, iface: testUplink, value: "1", readOnly: true},
		// The defect in #586: the write fails, forwarding stays off, and the
		// helper used to report success anyway.
		{name: "read-only, off", present: testUplink, iface: testUplink, value: "0", readOnly: true, wantErr: true},
		{name: "interface missing", present: testUplink, iface: "missing0", value: "1", wantErr: true},
	}
	for _, h := range helpers {
		for _, tt := range tests {
			t.Run(h.name+"/"+tt.name, func(t *testing.T) {
				mode := os.FileMode(0o644)
				if tt.readOnly {
					if os.Geteuid() == 0 {
						t.Skip("root ignores the read-only file mode this case depends on")
					}
					mode = 0o444
				}
				root := fakeProcSys(t, h.sysctls(tt.present), tt.value, mode)
				err := h.fn(tt.iface)
				if (err != nil) != tt.wantErr {
					t.Fatalf("configure %q: error = %v, wantErr %v", tt.iface, err, tt.wantErr)
				}
				if err != nil {
					return
				}
				for _, segments := range h.sysctls(tt.iface) {
					got, readErr := os.ReadFile(filepath.Join(append([]string{root}, segments...)...))
					if readErr != nil {
						t.Fatal(readErr)
					}
					if strings.TrimSpace(string(got)) != "1" {
						t.Errorf("%s = %q, want 1", sysctlName(segments), got)
					}
				}
			})
		}
	}
}

func TestSysctlName(t *testing.T) {
	got := sysctlName(forwardingSysctl("ipv6", testVLAN))
	if want := "net.ipv6.conf.bond0/100.forwarding"; got != want {
		t.Errorf("sysctlName = %q, want %q", got, want)
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
