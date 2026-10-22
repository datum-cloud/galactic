// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package admission

import (
	"net/netip"
	"slices"
	"sync"
	"time"
)

// Authorization is the immutable record of one admitted request: who was
// admitted, for what, under which grant generation and until when. Accessors
// return copies. Done closes when the authorization ends; consumers must stop
// using it then, whatever their own deadlines say.
type Authorization struct {
	req        Request
	validUntil time.Time
	notAfter   time.Time

	done   chan struct{}
	once   sync.Once
	mu     sync.Mutex
	reason Reason
}

func newAuthorization(req Request, g Grant, maxSkew time.Duration) *Authorization {
	req.Capabilities = slices.Clone(req.Capabilities)
	req.Prefixes = slices.Clone(req.Prefixes)
	z := &Authorization{req: req, validUntil: g.ValidUntil, done: make(chan struct{})}
	if !g.ValidUntil.IsZero() {
		z.notAfter = g.ValidUntil.Add(-maxSkew)
	}
	return z
}

// Provider is the admitted provider's name.
func (z *Authorization) Provider() string { return z.req.Provider }

// Identity is the authenticated caller that was admitted.
func (z *Authorization) Identity() Identity { return z.req.Identity }

// VPC is the admitted VPC's UID.
func (z *Authorization) VPC() string { return z.req.VPC }

// Grant is the grant and generation the authorization was decided on.
func (z *Authorization) Grant() GrantRef { return z.req.Grant }

// Capabilities are the admitted capabilities.
func (z *Authorization) Capabilities() []Capability { return slices.Clone(z.req.Capabilities) }

// Prefixes are the admitted prefixes.
func (z *Authorization) Prefixes() []netip.Prefix { return slices.Clone(z.req.Prefixes) }

// Ceiling is the grant's ValidUntil, or zero when it has none. It is the
// value for claim.Instance.Ceiling, which applies its own MaxSkew; that
// MaxSkew must be the one the Authority was built with.
func (z *Authorization) Ceiling() time.Time { return z.validUntil }

// NotAfter is the wall-clock instant at which the authorization expires,
// Ceiling less the maximum clock skew, or zero when the grant has no
// ValidUntil.
func (z *Authorization) NotAfter() time.Time { return z.notAfter }

// Done closes when the authorization is revoked, expires or is released.
func (z *Authorization) Done() <-chan struct{} { return z.done }

// Reason is why the authorization ended, or empty while it is in force or
// after it was released.
func (z *Authorization) Reason() Reason {
	z.mu.Lock()
	defer z.mu.Unlock()
	return z.reason
}

func (z *Authorization) end(r Reason) {
	z.once.Do(func() {
		z.mu.Lock()
		z.reason = r
		z.mu.Unlock()
		close(z.done)
	})
}

// Authority holds a cell's trust configuration, the registered providers and
// the tenant grants, admits requests against it, and ends every
// authorization it issued as soon as the configuration no longer admits it
// or its grant expires. It is safe for concurrent use.
type Authority struct {
	maxSkew time.Duration
	now     func() time.Time
	// afterFunc schedules f after d and returns a function that cancels it.
	afterFunc func(d time.Duration, f func()) (stop func() bool)

	mu        sync.Mutex
	providers map[string]Provider
	grants    map[string]Grant
	issued    map[*Authorization]func() bool
}

// NewAuthority returns an empty Authority that expires grants maxSkew before
// their ValidUntil, on the system wall clock.
func NewAuthority(maxSkew time.Duration) *Authority {
	return &Authority{
		maxSkew: maxSkew,
		now:     time.Now,
		afterFunc: func(d time.Duration, f func()) func() bool {
			return time.AfterFunc(d, f).Stop
		},
		providers: map[string]Provider{},
		grants:    map[string]Grant{},
		issued:    map[*Authorization]func() bool{},
	}
}

// Admit decides req against the current configuration, as the package-level
// Admit does. An admitted Authorization is tracked until it ends or is
// released.
func (a *Authority) Admit(req Request) Decision {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	d := Admit(a.providers, a.grants, req, now, a.maxSkew)
	if !d.Admitted {
		return d
	}
	z := d.Authorization
	stop := func() bool { return false }
	if !z.notAfter.IsZero() {
		stop = a.afterFunc(z.notAfter.Sub(now), func() { a.expire(z) })
	}
	a.issued[z] = stop
	return d
}

// Release ends z without a reason and stops tracking it. It is idempotent.
func (a *Authority) Release(z *Authorization) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.forget(z, "")
}

// SetProvider registers or replaces p and ends every authorization it no
// longer admits.
func (a *Authority) SetProvider(p Provider) {
	p.ContractVersions = slices.Clone(p.ContractVersions)
	p.Capabilities = slices.Clone(p.Capabilities)
	p.ServiceAccounts = slices.Clone(p.ServiceAccounts)
	a.mu.Lock()
	defer a.mu.Unlock()
	a.providers[p.Name] = p
	a.revalidate()
}

// DeleteProvider removes the named provider and ends its authorizations.
func (a *Authority) DeleteProvider(name string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.providers, name)
	a.revalidate()
}

// SetGrant records or replaces g, keyed by its UID, and ends every
// authorization it no longer admits. Any authorization decided on another
// generation of g ends with StaleGrant.
func (a *Authority) SetGrant(g Grant) {
	g.Capabilities = slices.Clone(g.Capabilities)
	g.Prefixes = slices.Clone(g.Prefixes)
	a.mu.Lock()
	defer a.mu.Unlock()
	a.grants[g.UID] = g
	a.revalidate()
}

// DeleteGrant removes the grant with uid and ends its authorizations with
// GrantRevoked.
func (a *Authority) DeleteGrant(uid string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.grants, uid)
	a.revalidate()
}

// revalidate re-decides every issued authorization's request and ends those
// now refused. a.mu must be held.
func (a *Authority) revalidate() {
	now := a.now()
	for z := range a.issued {
		if d := Admit(a.providers, a.grants, z.req, now, a.maxSkew); !d.Admitted {
			a.forget(z, d.Reason)
		}
	}
}

func (a *Authority) expire(z *Authorization) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, ok := a.issued[z]; ok {
		a.forget(z, GrantExpired)
	}
}

// forget stops tracking z and ends it with r. a.mu must be held.
func (a *Authority) forget(z *Authorization, r Reason) {
	if stop, ok := a.issued[z]; ok {
		stop()
		delete(a.issued, z)
	}
	z.end(r)
}
