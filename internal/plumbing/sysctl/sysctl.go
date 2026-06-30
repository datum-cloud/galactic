// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package sysctl applies kernel sysctl settings required for VRF-based
// container networking. Requires CAP_NET_ADMIN.
package sysctl

import (
	"fmt"
	"log/slog"

	gosysctl "github.com/lorenzosaino/go-sysctl"
)

// logger is the package-level logger. Defaults to slog.Default().
// Override for testing.
var logger *slog.Logger = slog.Default()

var interfaceSettings = []struct {
	format string
	value  string
}{
	{"net.ipv4.conf.%s.rp_filter", "0"},
	{"net.ipv4.conf.%s.forwarding", "1"},
	{"net.ipv6.conf.%s.forwarding", "1"},
	{"net.ipv4.conf.%s.proxy_arp", "1"},
	{"net.ipv6.conf.%s.proxy_ndp", "1"},
}

// ConfigureInterfaceSysctls applies forwarding, rp_filter, and proxy ARP/NDP
// sysctl settings to iface, which are required for correct VRF packet handling.
// Silently skips sysctls that don't exist (e.g., in container environments
// where dynamically created interfaces may not have all sysctl entries).
func ConfigureInterfaceSysctls(iface string) error {
	for _, entry := range interfaceSettings {
		key := fmt.Sprintf(entry.format, iface)
		if err := gosysctl.Set(key, entry.value); err != nil {
			logger.Warn("failed to set sysctl (non-fatal)", "sysctl", key, "err", err)
		}
	}
	return nil
}

// ConfigureTapSysctls applies sysctls appropriate for a tap interface
// connected to a VM. Unlike ConfigureInterfaceSysctls, it skips
// proxy_arp and proxy_ndp since the VM handles its own address resolution.
// Silently skips sysctls that don't exist (e.g., in container environments
// where dynamically created interfaces may not have all sysctl entries).
func ConfigureTapSysctls(iface string) error {
	settings := map[string]string{
		fmt.Sprintf("net.ipv4.conf.%s.rp_filter", iface):  "0",
		fmt.Sprintf("net.ipv6.conf.%s.rp_filter", iface):  "0",
		fmt.Sprintf("net.ipv4.conf.%s.forwarding", iface): "1",
		fmt.Sprintf("net.ipv6.conf.%s.forwarding", iface): "1",
	}
	for key, val := range settings {
		_ = gosysctl.Set(key, val) // silently skip missing entries
	}
	return nil
}
