// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package sysctl

import (
	"fmt"

	gosysctl "github.com/lorenzosaino/go-sysctl"
)

var INTERFACE_SETTINGS = []struct {
	format string
	value  string
}{
	{"net.ipv4.conf.%s.rp_filter", "0"},
	{"net.ipv4.conf.%s.forwarding", "1"},
	{"net.ipv6.conf.%s.forwarding", "1"},
	{"net.ipv4.conf.%s.proxy_arp", "1"},
	{"net.ipv6.conf.%s.proxy_ndp", "1"},
}

func ConfigureInterfaceSysctls(iface string) error {
	for _, entry := range INTERFACE_SETTINGS {
		key := fmt.Sprintf(entry.format, iface)
		if err := gosysctl.Set(key, entry.value); err != nil {
			return err
		}
	}
	return nil
}
