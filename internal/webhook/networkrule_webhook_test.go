// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package webhook

import (
	"context"
	"errors"
	"testing"

	authenticationv1 "k8s.io/api/authentication/v1"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	networkv1alpha1 "go.datum.net/network/api/v1alpha1"
)

// fakeAuthorizer lets tests control the Authorize outcome deterministically.
type fakeAuthorizer struct {
	allow bool
	err   error
}

func (f fakeAuthorizer) Authorize(
	context.Context, authenticationv1.UserInfo, *networkv1alpha1.NetworkRule,
) (bool, error) {
	return f.allow, f.err
}

func contextWithRequester(username string) context.Context {
	req := admission.Request{}
	req.UserInfo = authenticationv1.UserInfo{Username: username}
	return admission.NewContextWithRequest(context.Background(), req)
}

func testRule() *networkv1alpha1.NetworkRule {
	return &networkv1alpha1.NetworkRule{
		Spec: networkv1alpha1.NetworkRuleSpec{
			VPCRef:           "vpc-1",
			VPCAttachmentRef: "attach-1",
		},
	}
}

func TestNetworkRuleValidator_ValidateCreate_Allowed(t *testing.T) {
	v := &NetworkRuleValidator{Authorizer: fakeAuthorizer{allow: true}}
	_, err := v.ValidateCreate(contextWithRequester("alice"), testRule())
	if err != nil {
		t.Fatalf("ValidateCreate: unexpected error: %v", err)
	}
}

func TestNetworkRuleValidator_ValidateCreate_Denied(t *testing.T) {
	v := &NetworkRuleValidator{Authorizer: fakeAuthorizer{allow: false}}
	_, err := v.ValidateCreate(contextWithRequester("mallory"), testRule())
	if err == nil {
		t.Fatal("ValidateCreate: expected error when Authorizer denies")
	}
}

func TestNetworkRuleValidator_ValidateCreate_AuthorizerErrorFailsClosed(t *testing.T) {
	v := &NetworkRuleValidator{Authorizer: fakeAuthorizer{allow: true, err: errors.New("companion operator unreachable")}}
	_, err := v.ValidateCreate(contextWithRequester("alice"), testRule())
	if err == nil {
		t.Fatal("ValidateCreate: expected error when Authorizer itself fails (fail-closed)")
	}
}

func TestNetworkRuleValidator_ValidateUpdate_ReChecksNewObject(t *testing.T) {
	v := &NetworkRuleValidator{Authorizer: fakeAuthorizer{allow: false}}
	oldRule := testRule()
	newRule := testRule()
	newRule.Spec.VPCRef = "someone-elses-vpc"
	_, err := v.ValidateUpdate(contextWithRequester("mallory"), oldRule, newRule)
	if err == nil {
		t.Fatal("ValidateUpdate: expected error when Authorizer denies the updated object")
	}
}

func TestNetworkRuleValidator_ValidateDelete_NoAuthorizationCheck(t *testing.T) {
	v := &NetworkRuleValidator{Authorizer: fakeAuthorizer{allow: false}}
	if _, err := v.ValidateDelete(context.Background(), testRule()); err != nil {
		t.Fatalf("ValidateDelete: unexpected error: %v", err)
	}
}

func TestNetworkRuleValidator_MissingAdmissionRequestErrors(t *testing.T) {
	v := &NetworkRuleValidator{Authorizer: fakeAuthorizer{allow: true}}
	// No admission.Request on the context.
	_, err := v.ValidateCreate(context.Background(), testRule())
	if err == nil {
		t.Fatal("ValidateCreate: expected error when no admission.Request is present on context")
	}
}

func TestAllowAllAuthorizer_AlwaysAllows(t *testing.T) {
	a := AllowAllAuthorizer{}
	ok, err := a.Authorize(context.Background(), authenticationv1.UserInfo{Username: "anyone"}, testRule())
	if err != nil {
		t.Fatalf("Authorize: unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("AllowAllAuthorizer must always allow")
	}
}
