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

package controller

import (
	"context"
	"testing"

	"k8s.io/apimachinery/pkg/api/meta"

	cloudv1alpha1 "go.datum.net/galactic/api/cloud/v1alpha1"
	"go.datum.net/galactic/internal/cloud/galactic"
)

// TestAttachmentPodSubnetPerFamily: an IPv4-only pod's attachment reports its
// address as a /32, and a dual-stack pod's attachment reports its IPv6
// subnet, alongside the node and the Programmed condition.
func TestAttachmentPodSubnetPerFamily(t *testing.T) {
	const container = "0123456789ab"
	for _, tc := range []struct {
		name        string
		annotations map[string]string
		want        string
	}{
		{
			name:        "ipv4 only",
			annotations: map[string]string{galactic.AnnotationAllocatedSubnetIPv4 + "." + container: "192.0.2.7"},
			want:        "192.0.2.7/32",
		},
		{
			name: "dual stack",
			annotations: map[string]string{
				galactic.AnnotationAllocatedSubnetIPv6 + "." + container: "fd00:10:ff01:0:1::/80",
				galactic.AnnotationAllocatedSubnetIPv4 + "." + container: "192.0.2.7",
			},
			want: "fd00:10:ff01:0:1::/80",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newOwnershipFixture(t, false)
			f.tenantAdv.Annotations = tc.annotations
			if err := f.client.Update(context.Background(), f.tenantAdv); err != nil {
				t.Fatal(err)
			}
			f.reconcile(t, f.tenantAdv)
			status := f.attachmentStatus(t)
			if status.PodSubnet != tc.want || status.Node != "node-a" ||
				!meta.IsStatusConditionTrue(status.Conditions, cloudv1alpha1.ConditionTypeProgrammed) {
				t.Fatalf("attachment status = %+v, want podSubnet %q on node-a and Programmed", status, tc.want)
			}
		})
	}
}
