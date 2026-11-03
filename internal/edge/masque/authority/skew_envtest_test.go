// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package authority

import (
	"context"
	"testing"
	"time"

	"go.datum.net/galactic/internal/edge/connectip"
	"go.datum.net/galactic/internal/edge/timing"
)

func (f *fixture) set(now time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.now = now
}

// TestStoppedGrantIsNotRenewed covers an incarnation within the cell's
// MaxSkew of its validUntil: core already refused its attachments with
// GrantExpired and never readmits them, so the authority must not renew it in
// place under the same UID.
func TestStoppedGrantIsNotRenewed(t *testing.T) {
	f := startFixture(t)
	ctx := context.Background()
	podA := podID(testPodA)
	stopped := func(g Grant) { f.set(g.NotAfter.Add(-timing.Params.MaxSkew / 2)) }
	next := func() { f.set(f.clock().Add(time.Minute)) }

	t.Run("authorize", func(t *testing.T) {
		c := f.connector()
		g := f.authorize(podA, c.Credential, "nonceK0000000001")
		stopped(g)
		r, err := f.tryAuthorize(podA, c.Credential, "nonceK0000000002")
		if err == nil && r.Service == g.Service {
			t.Fatalf("Authorize renewed stopped incarnation %s to %v", g.Service.UID, r.NotAfter)
		}
		// Core still holds the incarnation's pool, so no successor exists yet.
		expectErr(t, "Authorize while core holds the stopped incarnation", err, ErrUnavailable)
		if s := f.service(g); s == nil || !retired(s) {
			t.Fatal("the stopped incarnation was left live")
		}
		f.set(f.clock().Add(RetryWindow))
		r = f.authorize(podA, c.Credential, "nonceK0000000007")
		if r.Service.UID == g.Service.UID || f.service(g) != nil {
			t.Fatalf("Authorize after core released the stopped incarnation = %+v, want a successor", r.Service)
		}
	})
	t.Run("refresh", func(t *testing.T) {
		next()
		c := f.connector()
		g := f.authorize(podA, c.Credential, "nonceK0000000003")
		f.set(g.NotAfter.Add(-timing.Params.MaxSkew - time.Second))
		if _, err := f.auth.Refresh(ctx, podA, g.Authorization, g.Revision, g.Service); err != nil {
			t.Fatalf("Refresh before core stops the incarnation: %v", err)
		}
		g = f.authorize(podA, c.Credential, "nonceK0000000004")
		stopped(g)
		_, err := f.auth.Refresh(ctx, podA, g.Authorization, g.Revision, g.Service)
		expectErr(t, "Refresh of a stopped incarnation", err, connectip.ErrForbidden)
	})
	t.Run("credential expiring within MaxSkew", func(t *testing.T) {
		next()
		is, err := f.grants.Create(ctx, CreateRequest{
			VPC: VPCRef{Namespace: tenantNS, Name: vpcName}, Cell: testCell, Lifetime: time.Minute,
		})
		if err != nil {
			t.Fatal(err)
		}
		f.set(f.clock().Add(time.Minute - timing.Params.MaxSkew/2))
		_, err = f.tryAuthorize(podA, is.Credential, "nonceK0000000006")
		expectErr(t, "Authorize with a credential core would refuse", err, connectip.ErrUnauthenticated)
	})
	t.Run("sweep", func(t *testing.T) {
		next()
		c := f.connector()
		g := f.authorize(podA, c.Credential, "nonceK0000000005")
		stopped(g)
		if err := f.auth.Sweep(ctx); err != nil {
			t.Fatal(err)
		}
		if s := f.service(g); s == nil || !retired(s) {
			t.Fatal("the sweep left a stopped incarnation unretired")
		}
	})
}
