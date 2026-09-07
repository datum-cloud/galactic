// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package loaddr detects the BGP local address by reading the global-unicast
// IPv6 address on the host's loopback. The router runs with host networking, so
// that is the real host loopback, and the underlay routing daemon is expected to
// have assigned an SRv6 loopback address there before the router starts.
package loaddr

import (
	"errors"
	"fmt"

	"github.com/vishvananda/netlink"
)

// Detect returns the first global-unicast IPv6 address on the loopback,
// skipping ::1 and link-local addresses. It returns an error when the interface
// does not exist or carries no qualifying address.
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
