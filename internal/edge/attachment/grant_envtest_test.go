// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package attachment

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"

	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
	"go.datum.net/galactic/internal/edge/admission"
)

// TestGrantConflict: granted prefixes are exclusive within a VPC. The later
// of two services whose grants overlap admits no attachment, whichever of
// the two changed its grant, and is admitted again once they no longer
// overlap.
func TestGrantConflict(t *testing.T) {
	f := startFixture(t)
	earlier := f.service("earlier", poolA, 1)
	f.grant(earlier, "fd00:10:0:f::/64")
	later := f.laterService("later", "fd00:10:0:d::/120")
	f.grant(later, "fd00:10:0:f:1::/80")
	p := f.pod("p1")
	f.create(attachmentFor("refused", later, p))

	conflict := string(admission.PrefixConflict)
	f.waitCondition("refused", galacticv1alpha1.EdgeAttachmentAdmitted, metav1.ConditionFalse, conflict)
	f.waitService("later", metav1.ConditionFalse, conflict)
	f.waitService("earlier", metav1.ConditionTrue, ReasonAdmitted)
	if got := f.allocations(later); len(got) != 0 {
		t.Fatalf("conflicting service allocated %v", got)
	}

	// The later grant narrowed off the earlier one's: admitted.
	f.grant(later, "fd00:10:0:c::/64")
	f.waitService("later", metav1.ConditionTrue, ReasonAdmitted)
	f.waitCondition("refused", galacticv1alpha1.EdgeAttachmentAllocated, metav1.ConditionTrue, "")

	// The earlier grant widened over it: the later service's attachment
	// drains, though its own service did not change.
	f.grant(earlier, "fd00:10:0:f::/64", "fd00:10:0:c::/80")
	f.waitService("later", metav1.ConditionFalse, conflict)
	f.waitCondition("refused", galacticv1alpha1.EdgeAttachmentDraining, metav1.ConditionTrue, conflict)
}

// grant sets the service's granted prefixes.
func (f *fixture) grant(svc *galacticv1alpha1.EdgeService, prefixes ...string) {
	f.t.Helper()
	ctx := context.Background()
	if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var s galacticv1alpha1.EdgeService
		if err := f.admin.Get(ctx, client.ObjectKeyFromObject(svc), &s); err != nil {
			return err
		}
		s.Spec.Prefixes = prefixes
		return f.admin.Update(ctx, &s)
	}); err != nil {
		f.t.Fatal(err)
	}
}
