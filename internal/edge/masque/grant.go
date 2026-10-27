// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package masque

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"time"
)

// ErrUnavailable is returned by Admit when the request is authorized but
// cannot be served now: the instance holds no lease, the attachment is not
// programmed or was refused, or core has not accepted the route. The
// connectip server answers it with 503.
var ErrUnavailable = errors.New("masque: connector unavailable")

// ServiceRef identifies an EdgeService.
type ServiceRef struct {
	Namespace string
	Name      string
	UID       string
}

// Grant is a trusted authorization of one connector, as the MASQUE grant
// authority issues it. Neither the client nor the provider chooses any of
// its fields.
type Grant struct {
	// Connector is the connector's immutable identity.
	Connector string
	// Principal names the authenticated client for logs.
	Principal string
	// VPC is the request's VPC selector, which the grant matched.
	VPC string
	// VPCUID is the VPC's UID; route names derive from it.
	VPCUID string
	// VPCID is the VPC's base62 identifier, which core reports in an
	// admitted attachment's status.
	VPCID string
	// Service is the EdgeService that grants the connector's /96.
	Service ServiceRef
	// Prefix is the connector's masked IPv6 /96.
	Prefix netip.Prefix
	// Routes are the destinations advertised to the client.
	Routes []netip.Prefix
	// NotAfter is when the grant stops authorizing forwarding.
	NotAfter time.Time
}

// Authorizer authenticates a CONNECT-IP request's credential and authorizes
// it for the VPC the request selects, and keeps each issued grant current
// while its request is open.
type Authorizer interface {
	// Authorize returns the connector's grant. It returns an error wrapping
	// connectip.ErrUnauthenticated for an invalid credential and
	// connectip.ErrForbidden for a VPC the credential may not use; any
	// other error is retryable. It must honor ctx and must not log or
	// retain credential.
	Authorize(ctx context.Context, credential, vpc string) (Grant, error)
	// Refresh revalidates g against the authority's current records and
	// returns it with a new deadline. It never accepts a new credential
	// revision. It returns an error wrapping connectip.ErrUnauthenticated
	// or connectip.ErrForbidden once g is revoked, retired or rotated; any
	// other error is retryable and leaves g's deadline unchanged.
	Refresh(ctx context.Context, g Grant) (Grant, error)
	// Retire ends g's authorization, so that no later Authorize or Refresh
	// of it succeeds and its EdgeService stops being renewed.
	Retire(ctx context.Context, g Grant) error
}

// sameAuthority reports whether a refreshed grant r still authorizes what g
// did: the same connector, principal, VPC, service, /96 and routes. Only
// the deadline may change.
func (g *Grant) sameAuthority(r *Grant) bool {
	return g.Connector == r.Connector && g.Principal == r.Principal && g.VPC == r.VPC && g.VPCUID == r.VPCUID &&
		g.VPCID == r.VPCID && g.Service == r.Service && g.Prefix == r.Prefix && slices.Equal(g.Routes, r.Routes)
}

// validate reports why g cannot admit a request for vpc at now.
func (g *Grant) validate(vpc string, now time.Time) error {
	p := g.Prefix
	switch {
	case g.Connector == "" || g.Principal == "":
		return errors.New("grant has no connector or principal")
	case g.VPC != vpc:
		return fmt.Errorf("grant is for VPC %q, not the requested %q", g.VPC, vpc)
	case g.VPCUID == "" || g.VPCID == "":
		return errors.New("grant has no VPC UID or identifier")
	case g.Service.Namespace == "" || g.Service.Name == "" || g.Service.UID == "":
		return errors.New("grant names no EdgeService")
	case !p.IsValid() || !p.Addr().Is6() || p.Addr().Is4In6() || p.Bits() != 96 || p != p.Masked():
		return fmt.Errorf("grant prefix %s is not a masked IPv6 /96", p)
	case !now.Before(g.NotAfter):
		return errors.New("grant has expired")
	}
	for _, r := range g.Routes {
		if !r.IsValid() || r != r.Masked() {
			return fmt.Errorf("grant route %s is not a masked prefix", r)
		}
	}
	return nil
}
