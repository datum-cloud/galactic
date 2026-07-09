// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package loaddr detects the BGP local address by reading the global-unicast
// IPv6 address assigned to the host's `lo` interface. galactic-router runs
// with hostNetwork: true, so `lo` is the real host loopback, and an
// underlay/fabric BGP daemon (e.g. FRR) is expected to have already assigned
// an SRv6 loopback address to it (e.g. fc00:0:2::1/48) before galactic-router
// starts.
package loaddr

import (
	"errors"
	"fmt"

	"github.com/vishvananda/netlink"
)

// Detect returns the first global-unicast IPv6 address assigned to the `lo`
// interface, skipping the loopback address (::1) and link-local addresses
// (fe80::/10). Returns an error if `lo` doesn't exist or has no qualifying
// address.
func Detect() (string, error) {
	link, err := netlink.LinkByName("lo")
	if err != nil {
		return "", fmt.Errorf("find lo interface: %w", err)
	}

	addrs, err := netlink.AddrList(link, netlink.FAMILY_V6)
	if err != nil {
		return "", fmt.Errorf("list lo addresses: %w", err)
	}

	return selectGlobalUnicast(addrs)
}

// selectGlobalUnicast returns the first global-unicast IPv6 address in addrs,
// skipping loopback and link-local addresses.
func selectGlobalUnicast(addrs []netlink.Addr) (string, error) {
	for _, a := range addrs {
		if a.IP == nil || a.IP.IsLoopback() || a.IP.IsLinkLocalUnicast() {
			continue
		}
		return a.IP.String(), nil
	}
	return "", errors.New("no global-unicast IPv6 address found on lo")
}
