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

// NetworkEgressPolicyValidator implements the typed admission.Validator
// generic interface for NetworkEgressPolicy (datum-cloud/enhancements#865),
// mirroring NetworkRuleValidator exactly: it verifies (via the same
// pluggable Authorizer) that the requesting identity is authorized for the
// vpc/vpcattachment named in the policy before a create or update is
// admitted. Unlike NetworkRule, NetworkEgressPolicy carries no VIP/backend/
// port to validate — enablement is existence-implies-enabled for a
// (vpcRef, vpcAttachmentRef) pair (design plan §4.1) — so this validator's
// only job, like NetworkRuleValidator's, is ownership verification.
type NetworkEgressPolicyValidator struct {
	// Authorizer performs the actual authorization check — the same
	// instance a caller wires into NetworkRuleValidator, since both
	// validators pose the identical vpc/vpcattachment ownership question.
	// Production callers must not leave this as AllowAllAuthorizer{} —
	// see that type's doc comment.
	Authorizer Authorizer
}

var _ admission.Validator[*networkv1alpha1.NetworkEgressPolicy] = &NetworkEgressPolicyValidator{}

// ValidateCreate verifies the requester is authorized for the
// NetworkEgressPolicy's vpc/vpcattachment before create is admitted.
func (v *NetworkEgressPolicyValidator) ValidateCreate(
	ctx context.Context, policy *networkv1alpha1.NetworkEgressPolicy,
) (admission.Warnings, error) {
	return nil, v.authorize(ctx, policy)
}

// ValidateUpdate re-verifies authorization on update — a policy's vpcRef/
// vpcAttachmentRef could otherwise be changed post-creation to point at a
// different tenant's resources without ever re-running the create-time
// check (same reasoning as NetworkRuleValidator.ValidateUpdate).
func (v *NetworkEgressPolicyValidator) ValidateUpdate(
	ctx context.Context, _, newPolicy *networkv1alpha1.NetworkEgressPolicy,
) (admission.Warnings, error) {
	return nil, v.authorize(ctx, newPolicy)
}

// ValidateDelete performs no additional authorization check: deleting a
// NetworkEgressPolicy that already exists in the cluster is scoped by
// Kubernetes' own RBAC on the delete verb, not by vpc/vpcattachment
// ownership (same reasoning as NetworkRuleValidator.ValidateDelete).
func (v *NetworkEgressPolicyValidator) ValidateDelete(
	context.Context, *networkv1alpha1.NetworkEgressPolicy,
) (admission.Warnings, error) {
	return nil, nil
}

// authorize resolves the requesting identity from the admission.Request
// carried on ctx and calls the configured Authorizer — identical shape to
// NetworkRuleValidator.authorize, differing only in which CRD's spec
// fields it reads.
func (v *NetworkEgressPolicyValidator) authorize(
	ctx context.Context, policy *networkv1alpha1.NetworkEgressPolicy,
) error {
	req, err := admission.RequestFromContext(ctx)
	if err != nil {
		return fmt.Errorf("resolve admission request: %w", err)
	}

	ok, err := v.Authorizer.Authorize(ctx, req.UserInfo, policy.Spec.VPCRef, policy.Spec.VPCAttachmentRef)
	if err != nil {
		// Fail closed — same reasoning as NetworkRuleValidator.authorize.
		return fmt.Errorf("authorization check failed: %w", err)
	}
	if !ok {
		return fmt.Errorf(
			"%s is not authorized for vpcRef %q / vpcAttachmentRef %q (%s)",
			req.UserInfo.Username, policy.Spec.VPCRef, policy.Spec.VPCAttachmentRef,
			networkv1alpha1.AcceptedReasonOwnershipDenied)
	}
	return nil
}

// SetupWebhookWithManager registers the NetworkEgressPolicy validating
// webhook with mgr — same builder shape as
// NetworkRuleValidator.SetupWebhookWithManager.
func (v *NetworkEgressPolicyValidator) SetupWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr, &networkv1alpha1.NetworkEgressPolicy{}).
		WithValidator(v).
		Complete()
}

// Production webhook registration additionally requires a
// ValidatingWebhookConfiguration/Service manifest, plus a cert-manager (or
// equivalent) TLS provisioning step — same deferral as
// NetworkRuleValidator's identical doc comment.
