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

// ConfigureFIBLookupUplinkSysctls enables IPv6 forwarding on iface (a
// galactic-gateway or galactic-nat66 node's public/fabric-facing uplink --
// the interface edgedsr.c's edge_lb and nat66.c's nat66_ingress XDP
// programs each attach to) and, needed alongside it,
// net.ipv6.conf.all.forwarding.
//
// Without this, bpf_fib_lookup() (edgedsr.c's push_outer_header, and
// nat66.c's identical mechanism in both its forward and return paths)
// returns BPF_FIB_LKUP_RET_NOT_FWDED for every lookup -- the kernel
// correctly refusing to resolve a forwarding route on an interface that
// isn't configured as a router -- which neither datapath's own drop-reason
// accounting could distinguish from a generic FIB lookup failure (see
// edgedsr.c's DROP_REASON_FIB_LOOKUP_FAILED fallback and nat66.c's
// equivalent). Found via live-kernel investigation of the containerlab
// veth/XDP_TX blocker (deploy/containerlab/README.md): this sysctl gap,
// not XDP_TX itself, is what actually prevented every gateway node's
// bpf_fib_lookup from ever succeeding in that lab. Both the per-interface
// and the "all" sysctl are set together because that combination is what
// was empirically confirmed to unblock bpf_fib_lookup; per-interface alone
// was not independently verified sufficient, and setting only "all" would
// affect every interface on the node instead of just the uplink -- setting
// both is the validated-safe choice, not a guess. Silently skips sysctls
// that don't exist, matching ConfigureInterfaceSysctls's own convention.
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
