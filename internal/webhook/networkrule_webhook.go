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

// NetworkRuleValidator is the admission validator for NetworkRule, verifying
// through the pluggable Authorizer that the requesting identity may act on the
// VPC and attachment the rule names before a create or update is admitted.
type NetworkRuleValidator struct {
	// Authorizer performs the actual check. Production callers must not leave
	// this as AllowAllAuthorizer.
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

// ValidateUpdate re-verifies authorization on update: a rule's VPC and
// attachment references could otherwise be changed after creation to point at
// another tenant's resources without the create-time check running again.
func (v *NetworkRuleValidator) ValidateUpdate(
	ctx context.Context, _, newRule *networkv1alpha1.NetworkRule,
) (admission.Warnings, error) {
	return nil, v.authorize(ctx, newRule)
}

// ValidateDelete performs no additional check. Deleting a rule that already
// exists is scoped by the cluster's own access control on the delete verb, not
// by VPC ownership.
func (v *NetworkRuleValidator) ValidateDelete(
	context.Context, *networkv1alpha1.NetworkRule,
) (admission.Warnings, error) {
	return nil, nil
}

// authorize resolves the requesting identity from the admission request carried
// on ctx, the validator interface not passing it directly, and calls the
// configured Authorizer. A denial surfaces to the requester as the rejection
// message.
//
// The Accepted condition on the rule itself is set by the reconciler once the
// object has passed admission and been persisted: a validating webhook cannot
// write to the status of a request it has not yet admitted.
func (v *NetworkRuleValidator) authorize(ctx context.Context, rule *networkv1alpha1.NetworkRule) error {
	req, err := admission.RequestFromContext(ctx)
	if err != nil {
		return fmt.Errorf("resolve admission request: %w", err)
	}

	ok, err := v.Authorizer.Authorize(ctx, req.UserInfo, rule)
	if err != nil {
		// Fail closed: a check that itself failed, because the companion
		// operator was unreachable, must never be treated as an implicit
		// allow.
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
// mgr, through controller-runtime's generic builder: the constructor infers the
// object type from its argument, and the validator argument takes the typed
// interface this type implements.
func (v *NetworkRuleValidator) SetupWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr, &networkv1alpha1.NetworkRule{}).
		WithValidator(v).
		Complete()
}

// Production registration additionally requires a webhook configuration and
// service manifest, plus TLS provisioning, neither of which is wired up here.
