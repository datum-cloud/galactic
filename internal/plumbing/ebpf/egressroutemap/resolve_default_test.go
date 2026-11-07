// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package egressroutemap

import (
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"
)

func TestResolveLinkAndL2_RejectsADefaultRouteOverAnUplink(t *testing.T) {
	requireRoot(t)

	nearNS, linkIndex, farIP := setUpVethPair(t,
		"vrfdr0", "fd00:beef:3::1/64",
		"vrfdr0p", "fd00:beef:3::2/64")

	restore := uplinkIndexesFn
	uplinkIndexesFn = func() (map[int]struct{}, error) { return map[int]struct{}{linkIndex: {}}, nil }
	t.Cleanup(func() { uplinkIndexesFn = restore })

	sid := net.ParseIP("2001:db8:ff02:2002:e001::")
	_, locator, _ := net.ParseCIDR("2001:db8:ff02:2002::/64")

	var defaultErr, specificErr error
	err := nearNS.Do(func(_ ns.NetNS) error {
		if err := netlink.RouteAdd(&netlink.Route{LinkIndex: linkIndex, Gw: farIP}); err != nil {
			return fmt.Errorf("add default route: %w", err)
		}
		_, _, _, defaultErr = resolveLinkAndL2(sid)

		if err := netlink.RouteAdd(&netlink.Route{LinkIndex: linkIndex, Dst: locator, Gw: farIP}); err != nil {
			return fmt.Errorf("add locator route: %w", err)
		}
		_, _, _, specificErr = resolveLinkAndL2(sid)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if defaultErr == nil || !strings.Contains(defaultErr.Error(), "only a default route matches") {
		t.Errorf("resolve through only a default route over an uplink: err = %v, want a default-route rejection", defaultErr)
	}
	if specificErr != nil {
		t.Errorf("resolve through the advertised locator: %v", specificErr)
	}
}
