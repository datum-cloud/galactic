/*
Copyright © 2026 Datum Technology, Inc. All rights reserved.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

package galactic

import (
	"net/netip"
	"testing"
)

func TestPodSubnet(t *testing.T) {
	const (
		v6Subnet = "fd00:10:ff01:0:1::/80"
		v4Addr   = "192.0.2.7"
	)
	v6 := func(id string) string { return AnnotationAllocatedSubnetIPv6 + "." + id }
	v4 := func(id string) string { return AnnotationAllocatedSubnetIPv4 + "." + id }
	for _, tc := range []struct {
		name        string
		annotations map[string]string
		want        string
		wantOK      bool
	}{
		{name: "none", annotations: map[string]string{AnnotationNetNS + ".a": "/var/run/netns/a"}},
		{name: "ipv6 only", annotations: map[string]string{v6("a"): v6Subnet}, want: v6Subnet, wantOK: true},
		{name: "ipv4 only", annotations: map[string]string{v4("a"): v4Addr}, want: v4Addr + "/32", wantOK: true},
		{
			name:        "dual stack",
			annotations: map[string]string{v6("a"): v6Subnet, v4("a"): v4Addr},
			want:        v6Subnet, wantOK: true,
		},
		{name: "empty ipv4", annotations: map[string]string{v4("a"): ""}},
		{name: "two ipv4 containers", annotations: map[string]string{v4("a"): v4Addr, v4("b"): "192.0.2.8"}},
		{
			name:        "two dual-stack containers",
			annotations: map[string]string{v6("a"): v6Subnet, v4("a"): v4Addr, v6("b"): v6Subnet, v4("b"): v4Addr},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := PodSubnet(tc.annotations)
			if got != tc.want || ok != tc.wantOK {
				t.Fatalf("PodSubnet = (%q, %v), want (%q, %v)", got, ok, tc.want, tc.wantOK)
			}
			if ok {
				if _, err := netip.ParsePrefix(got); err != nil {
					t.Fatalf("PodSubnet returned a non-CIDR %q: %v", got, err)
				}
			}
		})
	}
}
