// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package webhook implements galactic-router's admission webhooks.
//
// It exists for NetworkRule specifically: that resource is tenant-writable and
// names the target VPC and attachment directly, so without validation a tenant
// could write a rule targeting another tenant's, redirecting or intercepting
// their ingress traffic.
package webhook

import (
	"context"

	authenticationv1 "k8s.io/api/authentication/v1"

	networkv1alpha1 "go.datum.net/network/api/v1alpha1"
)

// Authorizer decides whether a requester may create or update a NetworkRule
// targeting the VPC and attachment it names.
//
// It is a pluggable interface rather than a concrete implementation because VPC
// ownership resolution lives in a separate companion operator this repo does
// not own, and to which it has no client, API, or network path today.
type Authorizer interface {
	// Authorize reports whether requester may act on the VPC and attachment
	// named in rule. False with a nil error is an authoritative denial; a
	// non-nil error means the check itself failed and the webhook should fail
	// closed.
	Authorize(ctx context.Context, requester authenticationv1.UserInfo, rule *networkv1alpha1.NetworkRule) (bool, error)
}

// AllowAllAuthorizer unconditionally allows every request.
//
// TODO(edge-gateway): this is not real authorization. Real authorization means
// calling out to the companion operator that owns VPC ownership resolution to
// confirm the requester may attach to the VPC and attachment the rule names,
// and that integration does not exist yet: no client, no API contract, no
// network path.
//
// Until it lands, every create and update is admitted whoever is asking and
// whatever they name, so a tenant can write a rule targeting another tenant's
// VPC, the exact vulnerability admission control exists to close. This must not
// be deployed with real tenant traffic before Authorizer has a real
// implementation.
type AllowAllAuthorizer struct{}

// Authorize always returns true. See the type's doc comment for why this is
// not safe to run in production and is only a wiring placeholder.
func (AllowAllAuthorizer) Authorize(
	context.Context, authenticationv1.UserInfo, *networkv1alpha1.NetworkRule,
) (bool, error) {
	return true, nil
}
