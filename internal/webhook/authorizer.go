// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package webhook implements galactic-router's admission webhooks. This is
// the first webhook in this repository — required for NetworkRule
// specifically: NetworkRule is tenant-writable and carries the target
// vpc/vpcattachment identifier directly, so without validation a tenant
// could write a rule targeting another tenant's vpc/vpcattachment,
// redirecting or intercepting their ingress traffic.
package webhook

import (
	"context"

	authenticationv1 "k8s.io/api/authentication/v1"
)

// Authorizer decides whether requester is authorized to create or update a
// resource targeting the given vpcRef/vpcAttachmentRef pair. Both
// NetworkRuleValidator and NetworkEgressPolicyValidator (datum-cloud/
// enhancements#865) share this one interface — vpcRef/vpcAttachmentRef
// ownership is the entire authorization question either object poses, so
// there is no need for two near-identical interfaces typed to their own
// concrete CRD. (Before #865, this interface was typed directly to
// *networkv1alpha1.NetworkRule; it was narrowed to just the two fields
// every caller actually needs once a second caller arrived.)
//
// This is a pluggable interface, not a concrete implementation, because VPC
// and VPCAttachment ownership resolution lives in a separate companion
// operator this repo does not own (per CLAUDE.md's "VPC and VPCAttachment
// CRD management lives in a separate companion operator") — this repo has
// no client, API, or even network path to that operator today.
type Authorizer interface {
	// Authorize reports whether requester is authorized for the given
	// vpc/vpcattachment. A false result (with a nil error) means
	// "authoritatively denied"; a non-nil error means the check itself
	// failed (e.g. the companion operator was unreachable) and the
	// webhook should fail closed.
	Authorize(ctx context.Context, requester authenticationv1.UserInfo, vpcRef, vpcAttachmentRef string) (bool, error)
}

// AllowAllAuthorizer is the TODO-marked placeholder Authorizer
// implementation. It unconditionally allows every request.
//
// TODO(edge-gateway): this is NOT real authorization. Real authorization
// requires calling out to the companion operator that owns VPC/
// VPCAttachment ownership resolution (see CLAUDE.md's "VPC and
// VPCAttachment CRD management lives in a separate companion operator")
// to confirm requester is actually permitted to attach to the named vpc/
// vpcattachment — that integration does not exist yet (no client, no API
// contract, no network path from this repo to that operator). Until it
// lands, every NetworkRule/NetworkEgressPolicy create/update is admitted
// regardless of who's asking or what vpc/vpcattachment they name, which
// means a tenant CAN currently write an object targeting another tenant's
// vpc/vpcattachment (the exact vulnerability admission control exists to
// close) — this must not be treated as production-ready and must not be
// deployed with real tenant traffic before the Authorizer above is given a
// real implementation.
type AllowAllAuthorizer struct{}

// Authorize always returns true. See the type's doc comment for why this is
// not safe to run in production and is only a wiring placeholder.
func (AllowAllAuthorizer) Authorize(context.Context, authenticationv1.UserInfo, string, string) (bool, error) {
	return true, nil
}
