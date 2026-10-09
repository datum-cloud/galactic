// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package sysctl applies kernel sysctl settings required for VRF-based
// container networking. Requires CAP_NET_ADMIN.
package sysctl

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

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
// sysctls under. See SetProcSysPath. Set once at startup, before any helper
// runs; it is not guarded for concurrent use.
var procSysPath = "/proc/sys"

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
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("use %s as the procfs sysctl root: %w", path, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("use %s as the procfs sysctl root: not a directory", path)
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
	return setForwarding(ipv6ForwardingSysctls(iface))
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
	return setForwarding(ipv4ForwardingSysctls(iface))
}

// ipv6ForwardingSysctls and ipv4ForwardingSysctls are the sysctls, as path
// segments, the two FIB-lookup helpers set for iface.
func ipv6ForwardingSysctls(iface string) [][]string {
	return [][]string{forwardingSysctl("ipv6", iface), forwardingSysctl("ipv6", "all")}
}

func ipv4ForwardingSysctls(iface string) [][]string {
	return [][]string{forwardingSysctl("ipv4", iface), forwardingSysctl("ipv4", "all"), {"net", "ipv4", "ip_forward"}}
}

// forwardingSysctl is the path of family's forwarding sysctl for dev.
func forwardingSysctl(family, dev string) []string {
	return []string{"net", family, "conf", dev, "forwarding"}
}

// setForwarding writes 1 to each sysctl under procSysPath and reads it back,
// returning an error for the first one that does not read 1.
//
// Each sysctl is given as its path segments rather than as a dotted key: an
// interface name may itself contain a dot, as a VLAN such as bond0.100 does,
// and a dotted key cannot tell that dot from a separator.
func setForwarding(sysctls [][]string) error {
	for _, segments := range sysctls {
		path := filepath.Join(append([]string{procSysPath}, segments...)...)
		name := sysctlName(segments)
		writeErr := os.WriteFile(path, []byte("1"), 0o644)
		raw, readErr := os.ReadFile(path)
		got := strings.TrimSpace(string(raw))
		switch {
		case readErr == nil && got == "1":
			if writeErr != nil {
				logger.Debug("sysctl already set; write failed", "sysctl", name, "err", writeErr)
			}
		case writeErr != nil:
			return fmt.Errorf("set sysctl %s to 1: %w", name, writeErr)
		case readErr != nil:
			return fmt.Errorf("read back sysctl %s: %w", name, readErr)
		default:
			return fmt.Errorf("sysctl %s reads %s after setting it to 1", name, got)
		}
	}
	return nil
}

// sysctlName renders path segments as sysctl(8) names them, with a dot inside
// a segment written as a slash, so net.ipv6.conf.bond0/100.forwarding.
func sysctlName(segments []string) string {
	parts := make([]string, len(segments))
	for i, seg := range segments {
		parts[i] = strings.ReplaceAll(seg, ".", "/")
	}
	return strings.Join(parts, ".")
}

// tapSettings are the sysctls ConfigureTapSysctls applies to a tap's host side.
//
// accept_dad is off because duplicate address detection holds the tap's
// link-local address tentative for about a second after its VMM opens it, and
// the node daemon's Router Advertisement sender cannot bind a tentative
// address. A tap is a point-to-point link to one guest, so the address has
// nothing to collide with. The tap is up but without carrier when this runs,
// and the kernel assigns the link-local address only once carrier appears, so
// the setting is in place before the address exists.
var tapSettings = []struct {
	format string
	value  string
}{
	{"net.ipv4.conf.%s.rp_filter", "0"},
	{"net.ipv6.conf.%s.rp_filter", "0"},
	{"net.ipv4.conf.%s.forwarding", "1"},
	{"net.ipv6.conf.%s.forwarding", "1"},
	{"net.ipv6.conf.%s.accept_dad", "0"},
}

// ConfigureTapSysctls applies the sysctls appropriate for a tap connected to a
// VM. Unlike ConfigureInterfaceSysctls it skips proxy ARP and NDP, the VM
// handling its own address resolution. A sysctl that does not exist is skipped
// silently.
func ConfigureTapSysctls(iface string) error {
	for _, entry := range tapSettings {
		name := fmt.Sprintf(entry.format, iface)
		if err := gosysctl.Set(name, entry.value); err != nil {
			// Non-fatal: a sysctl that does not exist is skipped.
			logger.Debug("tap sysctl write failed", "sysctl", name, "err", err)
		}
	}
	return nil
}
