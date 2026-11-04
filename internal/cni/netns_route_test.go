// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cni

import (
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// TestForwardsThroughOtherLink pins which existing default routes suppress
// the VPC default on an attachment. Only a route that forwards through
// another link is the guest's primary default; one with no egress link must
// not cost the attachment its default route.
func TestForwardsThroughOtherLink(t *testing.T) {
	const attachment, primary = 7, 3
	tests := []struct {
		name  string
		route netlink.Route
		want  bool
	}{
		{"unicast via another link", netlink.Route{LinkIndex: primary}, true},
		{"kernel unicast via another link", netlink.Route{LinkIndex: primary, Type: unix.RTN_UNICAST}, true},
		{"unicast via the attachment", netlink.Route{LinkIndex: attachment}, false},
		{"blackhole", netlink.Route{Type: unix.RTN_BLACKHOLE}, false},
		{"unreachable", netlink.Route{Type: unix.RTN_UNREACHABLE}, false},
		{"prohibit", netlink.Route{Type: unix.RTN_PROHIBIT}, false},
		{"no egress link", netlink.Route{}, false},
		{"multipath via another link", netlink.Route{MultiPath: []*netlink.NexthopInfo{
			{LinkIndex: attachment}, {LinkIndex: primary},
		}}, true},
		{"multipath via the attachment only", netlink.Route{MultiPath: []*netlink.NexthopInfo{
			{LinkIndex: attachment}, {LinkIndex: 0},
		}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := forwardsThroughOtherLink(tt.route, attachment); got != tt.want {
				t.Fatalf("forwardsThroughOtherLink = %t, want %t", got, tt.want)
			}
		})
	}
}
