// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package webhook

import (
	"context"
	"fmt"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	networkv1alpha1 "go.datum.net/network/api/v1alpha1"
)

// NetworkRuleValidator implements the typed admission.Validator generic
// interface for NetworkRule, verifying (via the pluggable Authorizer) that
// the requesting identity is authorized for the vpc/vpcattachment named in
// the rule before a create or update is admitted.
type NetworkRuleValidator struct {
	// Authorizer performs the actual authorization check. Production
	// callers must not leave this as AllowAllAuthorizer{} — see that
	// type's doc comment.
	Authorizer Authorizer
}

var _ admission.Validator[*networkv1alpha1.NetworkRule] = &NetworkRuleValidator{}

// ValidateCreate verifies the requester is authorized for the NetworkRule's
// vpc/vpcattachment before create is admitted.
func (v *NetworkRuleValidator) ValidateCreate(
	ctx context.Context, rule *networkv1alpha1.NetworkRule,
) (admission.Warnings, error) {
	return nil, v.authorize(ctx, rule)
}

// ValidateUpdate re-verifies authorization on update — a rule's vpcRef/
// vpcAttachmentRef could otherwise be changed post-creation to point at a
// different tenant's resources without ever re-running the create-time
// check.
func (v *NetworkRuleValidator) ValidateUpdate(
	ctx context.Context, _, newRule *networkv1alpha1.NetworkRule,
) (admission.Warnings, error) {
	return nil, v.authorize(ctx, newRule)
}

// ValidateDelete performs no additional authorization check: deleting a
// NetworkRule that already exists in the cluster is scoped by Kubernetes'
// own RBAC on the delete verb, not by vpc/vpcattachment ownership.
func (v *NetworkRuleValidator) ValidateDelete(
	context.Context, *networkv1alpha1.NetworkRule,
) (admission.Warnings, error) {
	return nil, nil
}

// authorize resolves the requesting identity from the admission.Request
// carried on ctx (controller-runtime's Validator interface does not pass
// the request directly) and calls the configured Authorizer. A denial
// surfaces to the requester as the admission rejection message; the
// Accepted condition on the NetworkRule itself is set by the future
// NetworkRule controller once the object has passed admission and been
// persisted, since a validating webhook cannot itself write to the
// object's status subresource on a create/update it hasn't yet admitted.
func (v *NetworkRuleValidator) authorize(ctx context.Context, rule *networkv1alpha1.NetworkRule) error {
	req, err := admission.RequestFromContext(ctx)
	if err != nil {
		return fmt.Errorf("resolve admission request: %w", err)
	}

	ok, err := v.Authorizer.Authorize(ctx, req.UserInfo, rule.Spec.VPCRef, rule.Spec.VPCAttachmentRef)
	if err != nil {
		// Fail closed: an authorization check that itself failed (e.g. the
		// companion operator was unreachable) must never be treated as an
		// implicit allow.
		return fmt.Errorf("authorization check failed: %w", err)
	}
	if !ok {
		return fmt.Errorf(
			"%s is not authorized for vpcRef %q / vpcAttachmentRef %q (%s)",
			req.UserInfo.Username, rule.Spec.VPCRef, rule.Spec.VPCAttachmentRef,
			networkv1alpha1.AcceptedReasonOwnershipDenied)
	}
	return nil
}

// SetupWebhookWithManager registers the NetworkRule validating webhook with
// mgr, using controller-runtime's generic builder API — the shape
// sigs.k8s.io/controller-runtime v0.24.1 (this repo's go.mod) actually
// exposes: NewWebhookManagedBy[T] infers T from the object argument, and
// WithValidator takes the typed admission.Validator[T] this type
// implements above.
func (v *NetworkRuleValidator) SetupWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr, &networkv1alpha1.NetworkRule{}).
		WithValidator(v).
		Complete()
}

// Production webhook registration additionally requires a
// ValidatingWebhookConfiguration/Service manifest, plus a cert-manager (or
// equivalent) TLS provisioning step -- Phase D of the design plan, not
// wired up yet.
