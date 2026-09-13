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

// ConfigureInterfaceSysctls applies the forwarding, reverse-path filter, and
// proxy ARP and NDP settings iface needs for correct VRF packet handling. A
// sysctl that does not exist is skipped silently, as happens for dynamically
// created interfaces in some container environments.
func ConfigureInterfaceSysctls(iface string) error {
	for _, entry := range interfaceSettings {
		key := fmt.Sprintf(entry.format, iface)
		if err := gosysctl.Set(key, entry.value); err != nil {
			logger.Warn("failed to set sysctl (non-fatal)", "sysctl", key, "err", err)
		}
	}
	return nil
}

// ConfigureFIBLookupUplinkSysctls enables IPv6 forwarding on iface, a gateway
// or egress shard node's fabric-facing uplink, and alongside it the
// all-interfaces forwarding sysctl.
//
// Without them, bpf_fib_lookup returns not-forwarded for every lookup, the
// kernel correctly refusing to resolve a forwarding route on an interface not
// configured as a router. Neither datapath's drop accounting can tell that from
// a generic lookup failure, so the symptom is a lookup that simply never
// succeeds.
//
// Both the per-interface and the all-interfaces sysctl are set together because
// that combination is what was confirmed to unblock the lookup. Per-interface
// alone was not independently verified sufficient, and setting only the
// all-interfaces one would affect every interface on the node rather than the
// uplink.
//
// A sysctl that does not exist is skipped silently, as elsewhere here.
func ConfigureFIBLookupUplinkSysctls(iface string) error {
	settings := []struct{ key, value string }{
		{fmt.Sprintf("net.ipv6.conf.%s.forwarding", iface), "1"},
		{"net.ipv6.conf.all.forwarding", "1"},
	}
	for _, s := range settings {
		if err := gosysctl.Set(s.key, s.value); err != nil {
			logger.Warn("failed to set sysctl (non-fatal)", "sysctl", s.key, "err", err)
		}
	}
	return nil
}

// ConfigureFIBLookupUplinkSysctlsIPv4 enables IPv4 forwarding on iface, the
// IPv4 counterpart to ConfigureFIBLookupUplinkSysctls and needed only on a
// shard that performs NAT64.
//
// A NAT64 forward leg hands the kernel a translated IPv4 packet to route,
// exactly as the NAT66 leg hands it an IPv6 one. Without this the kernel drops
// every translated packet after the datapath has already counted it as
// successfully translated, so the shard reads as healthy while no IPv4 traffic
// ever leaves it.
//
// A sysctl that does not exist is skipped silently, as elsewhere here.
func ConfigureFIBLookupUplinkSysctlsIPv4(iface string) error {
	settings := []struct{ key, value string }{
		{fmt.Sprintf("net.ipv4.conf.%s.forwarding", iface), "1"},
		{"net.ipv4.conf.all.forwarding", "1"},
		{"net.ipv4.ip_forward", "1"},
	}
	for _, s := range settings {
		if err := gosysctl.Set(s.key, s.value); err != nil {
			logger.Warn("failed to set sysctl (non-fatal)", "sysctl", s.key, "err", err)
		}
	}
	return nil
}

// ConfigureTapSysctls applies the sysctls appropriate for a tap connected to a
// VM. Unlike ConfigureInterfaceSysctls it skips proxy ARP and NDP, the VM
// handling its own address resolution. A sysctl that does not exist is skipped
// silently.
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
