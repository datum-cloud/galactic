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

// procSysPath is the procfs root the FIB-lookup helpers read and write their
// sysctls under. See SetProcSysPath.
var procSysPath = gosysctl.DefaultPath

// SetProcSysPath points ConfigureFIBLookupUplinkSysctls and
// ConfigureFIBLookupUplinkSysctlsIPv4 at a procfs root other than /proc/sys.
//
// An unprivileged container gets /proc/sys read-only, so a host-network pod
// that must change the host's forwarding sysctls mounts the host's
// /proc/sys/net somewhere writable, such as /host/proc/sys/net, and passes the
// parent here. A net sysctl acts on the network namespace of the process that
// opens it, not the mount, so a host-network pod reaches the host's settings.
// The other helpers here are unaffected.
func SetProcSysPath(path string) error {
	if _, err := gosysctl.NewClient(path); err != nil {
		return fmt.Errorf("use %s as the procfs sysctl root: %w", path, err)
	}
	procSysPath = path
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
// It returns an error when either sysctl does not read 1 afterwards, since a
// datapath attached there would drop every packet. A write that fails is not
// an error on its own: a node whose forwarding something else already enabled
// passes even where /proc/sys is read-only.
func ConfigureFIBLookupUplinkSysctls(iface string) error {
	return setForwarding([]struct{ key, value string }{
		{fmt.Sprintf("net.ipv6.conf.%s.forwarding", iface), "1"},
		{"net.ipv6.conf.all.forwarding", "1"},
	})
}

// ConfigureFIBLookupUplinkSysctlsIPv4 enables IPv4 forwarding on iface, the
// IPv4 counterpart to ConfigureFIBLookupUplinkSysctls and needed only on a
// shard that performs NAT64.
//
// bpf_fib_lookup resolves a forwarding next hop, and a kernel with forwarding
// off for the family refuses to give it one. Without this every NAT64 forward
// packet dies at its last instruction, counted under a fib_* reason, so the
// shard reads as healthy while no IPv4 traffic ever leaves it.
//
// It returns an error on the same terms as ConfigureFIBLookupUplinkSysctls.
func ConfigureFIBLookupUplinkSysctlsIPv4(iface string) error {
	return setForwarding([]struct{ key, value string }{
		{fmt.Sprintf("net.ipv4.conf.%s.forwarding", iface), "1"},
		{"net.ipv4.conf.all.forwarding", "1"},
		{"net.ipv4.ip_forward", "1"},
	})
}

// setForwarding writes each setting under procSysPath and reads it back,
// returning an error for the first one that does not hold its value.
func setForwarding(settings []struct{ key, value string }) error {
	client, err := gosysctl.NewClient(procSysPath)
	if err != nil {
		return fmt.Errorf("open procfs sysctl root %s: %w", procSysPath, err)
	}
	for _, s := range settings {
		setErr := client.Set(s.key, s.value)
		got, getErr := client.Get(s.key)
		switch {
		case getErr == nil && got == s.value:
			if setErr != nil {
				logger.Debug("sysctl already set; write failed", "sysctl", s.key, "err", setErr)
			}
		case setErr != nil:
			return fmt.Errorf("set sysctl %s to %s: %w", s.key, s.value, setErr)
		case getErr != nil:
			return fmt.Errorf("read back sysctl %s: %w", s.key, getErr)
		default:
			return fmt.Errorf("sysctl %s reads %s after setting it to %s", s.key, got, s.value)
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
