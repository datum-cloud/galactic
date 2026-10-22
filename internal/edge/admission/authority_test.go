// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package admission

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"go.datum.net/galactic/internal/edge/claim"
)

// fakeTimers is a manual clock whose timers fire only when Advance passes
// their deadline.
type fakeTimers struct {
	mu     sync.Mutex
	now    time.Time
	timers []*fakeTimer
}

type fakeTimer struct {
	at      time.Time
	f       func()
	stopped bool
}

func (c *fakeTimers) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeTimers) AfterFunc(d time.Duration, f func()) func() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := &fakeTimer{at: c.now.Add(d), f: f}
	c.timers = append(c.timers, t)
	return func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		was := !t.stopped
		t.stopped = true
		return was
	}
}

func (c *fakeTimers) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	var due []func()
	for _, t := range c.timers {
		if !t.stopped && !c.now.Before(t.at) {
			t.stopped = true
			due = append(due, t.f)
		}
	}
	c.mu.Unlock()
	for _, f := range due {
		f()
	}
}

func (c *fakeTimers) pending() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, t := range c.timers {
		if !t.stopped {
			n++
		}
	}
	return n
}

func newTestAuthority(t *testing.T) (*Authority, *fakeTimers) {
	t.Helper()
	clock := &fakeTimers{now: epoch}
	a := NewAuthority(maxSkew)
	a.now, a.afterFunc = clock.Now, clock.AfterFunc
	for _, p := range registry() {
		a.SetProvider(p)
	}
	a.SetGrant(grant())
	return a, clock
}

func admitted(t *testing.T, a *Authority, req Request) *Authorization {
	t.Helper()
	d := a.Admit(req)
	if !d.Admitted {
		t.Fatalf("Admit = %+v, want admitted", d)
	}
	return d.Authorization
}

func ended(z *Authorization) bool {
	select {
	case <-z.Done():
		return true
	default:
		return false
	}
}

func TestAuthorityEndsAuthorizations(t *testing.T) {
	tests := []struct {
		name   string
		change func(*Authority, *fakeTimers)
		want   Reason
	}{
		{"GrantDeleted", func(a *Authority, _ *fakeTimers) { a.DeleteGrant(grantUID) }, GrantRevoked},
		{"GrantBeingDeleted", func(a *Authority, _ *fakeTimers) {
			g := grant()
			g.Revoked = true
			a.SetGrant(g)
		}, GrantRevoked},
		{"GrantChanged", func(a *Authority, _ *fakeTimers) {
			g := grant()
			g.Generation++
			a.SetGrant(g)
		}, StaleGrant},
		{"GrantExpires", func(_ *Authority, c *fakeTimers) { c.Advance(time.Hour - maxSkew) }, GrantExpired},
		{"ProviderUnapproved", func(a *Authority, _ *fakeTimers) {
			p := registry()[connectIP]
			p.Approved = false
			a.SetProvider(p)
		}, ProviderNotApproved},
		{"ProviderDeleted", func(a *Authority, _ *fakeTimers) { a.DeleteProvider(connectIP) }, UnknownProvider},
		{"ServiceAccountRemoved", func(a *Authority, _ *fakeTimers) {
			p := registry()[connectIP]
			p.ServiceAccounts = []ServiceAccount{{Namespace: providerNS, Name: otherName}}
			a.SetProvider(p)
		}, IdentityNotAuthorized},
		{"CapabilityDropped", func(a *Authority, _ *fakeTimers) {
			p := registry()[connectIP]
			p.Capabilities = []Capability{{Name: socketAccess, Version: "v1"}}
			a.SetProvider(p)
		}, UnsupportedCapability},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, clock := newTestAuthority(t)
			z := admitted(t, a, request())
			if ended(z) {
				t.Fatal("authorization ended at admission")
			}
			tt.change(a, clock)
			if !ended(z) || z.Reason() != tt.want {
				t.Fatalf("ended %t with %q, want ended with %q", ended(z), z.Reason(), tt.want)
			}
			if len(a.issued) != 0 || clock.pending() != 0 {
				t.Fatalf("still tracking %d authorizations and %d timers", len(a.issued), clock.pending())
			}
		})
	}
}

func TestAuthorityKeepsUnaffectedAuthorizations(t *testing.T) {
	a, clock := newTestAuthority(t)
	z := admitted(t, a, request())

	// Changes that still admit the request leave it in force.
	other := grant()
	other.UID = "grant-uid-2"
	a.SetGrant(other)
	a.DeleteGrant(other.UID)
	p := registry()[connectIP]
	p.ServiceAccounts = append(p.ServiceAccounts, ServiceAccount{Namespace: providerNS, Name: "second"})
	a.SetProvider(p)
	a.SetGrant(grant())
	clock.Advance(time.Hour - maxSkew - time.Second)

	if ended(z) {
		t.Fatalf("authorization ended with %q", z.Reason())
	}
}

func TestAuthorityRelease(t *testing.T) {
	a, clock := newTestAuthority(t)
	z := admitted(t, a, request())
	a.Release(z)
	a.Release(z)
	if !ended(z) || z.Reason() != "" {
		t.Fatalf("released authorization ended %t with %q", ended(z), z.Reason())
	}
	if len(a.issued) != 0 || clock.pending() != 0 {
		t.Fatalf("still tracking %d authorizations and %d timers", len(a.issued), clock.pending())
	}
	// A later revocation does not overwrite the release.
	a.DeleteGrant(grantUID)
	if z.Reason() != "" {
		t.Fatalf("reason after release = %q", z.Reason())
	}
}

func TestAuthorityRefusalsAreNotTracked(t *testing.T) {
	a, clock := newTestAuthority(t)
	req := request()
	req.Grant.Generation = 2
	if d := a.Admit(req); d.Reason != StaleGrant {
		t.Fatalf("Admit = %+v, want StaleGrant", d)
	}
	if len(a.issued) != 0 || clock.pending() != 0 {
		t.Fatalf("refusal tracked: %d authorizations, %d timers", len(a.issued), clock.pending())
	}
}

func TestAuthorityCopiesConfiguration(t *testing.T) {
	a, _ := newTestAuthority(t)
	g := grant()
	a.SetGrant(g)
	z := admitted(t, a, request())
	g.Prefixes[0] = netip.MustParsePrefix("fd00:6::/48")
	g.Capabilities[0] = socketAccess
	req := request()
	if d := a.Admit(req); !d.Admitted {
		t.Fatalf("caller's grant slices leaked into the Authority: %+v", d)
	}
	if ended(z) {
		t.Fatal("caller's grant slices ended an authorization")
	}
}

// TestCeilingCapsClaimLease shows the hand-off to forwarding enforcement: a
// claim instance given an authorization's Ceiling and the Authority's skew
// refuses to grant forwarding past NotAfter, without the Authority's help.
func TestCeilingCapsClaimLease(t *testing.T) {
	a, clock := newTestAuthority(t)
	z := admitted(t, a, request())
	in := &claim.Instance{
		ID:      "instance",
		Clock:   func() time.Duration { return 0 },
		Params:  claim.Params{Duration: 15 * time.Second, MaxSkew: maxSkew},
		Wall:    func() time.Time { return z.NotAfter() },
		Ceiling: z.Ceiling(),
	}
	if _, err := in.Acquire(context.Background(), "prefix"); !errors.Is(err, claim.ErrCeiling) {
		t.Fatalf("Acquire at NotAfter = %v, want ErrCeiling", err)
	}
	clock.Advance(time.Hour - maxSkew)
	if !ended(z) || z.Reason() != GrantExpired {
		t.Fatalf("authorization at NotAfter ended %t with %q", ended(z), z.Reason())
	}
}
