// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package route_test

import (
	"os"
	"testing"

	"go.datum.net/galactic/internal/cni/route"
	"go.datum.net/galactic/internal/plumbing/vrf"
)

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("test requires root (CAP_NET_ADMIN) to create real VRF interfaces; re-run via sudo")
	}
}

// TestAdd_IdempotentAcrossSharedAttachment is the regression test for #332:
// a second pod (or attachment) in the same VPC installs a termination route
// that its predecessor already put in the shared per-VPC table. The kernel
// returns EEXIST for the identical route, and Add must treat that as success
// (created=false) rather than a fatal error — otherwise the second pod cannot
// attach.
func TestAdd_IdempotentAcrossSharedAttachment(t *testing.T) {
	requireRoot(t)
	const vpc = "vtshr"

	t.Cleanup(func() { _ = vrf.Delete(vpc) })
	if err := vrf.Add(vpc); err != nil {
		t.Fatalf("create VRF: %v", err)
	}

	// A dev-scoped route on the loopback interface avoids assemblateRoute's
	// gateway-reachability validation (a bare `via` into the empty VRF table
	// is rejected with ENETUNREACH), while still exercising the identical
	// route hitting EEXIST on the second install — the exact shape a second
	// pod on a shared attachment hits.
	const prefix = "2001:db8::/32"
	const via = ""
	const dev = "lo"

	created, err := route.Add(vpc, prefix, via, dev)
	if err != nil {
		t.Fatalf("first Add: %v", err)
	}
	if !created {
		t.Error("first Add should report created=true")
	}

	// The second install of the identical route hits EEXIST, which Add must
	// swallow and report as not-created (a shared, pre-existing route).
	created, err = route.Add(vpc, prefix, via, dev)
	if err != nil {
		t.Fatalf("second Add (EEXIST) should be treated as success, got: %v", err)
	}
	if created {
		t.Error("second Add should report created=false for a pre-existing route")
	}
}
