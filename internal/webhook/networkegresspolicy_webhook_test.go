// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package webhook

import (
	"context"
	"errors"
	"testing"

	networkv1alpha1 "go.datum.net/network/api/v1alpha1"
)

func testEgressPolicy() *networkv1alpha1.NetworkEgressPolicy {
	return &networkv1alpha1.NetworkEgressPolicy{
		Spec: networkv1alpha1.NetworkEgressPolicySpec{
			VPCRef:           "vpc-1",
			VPCAttachmentRef: "attach-1",
		},
	}
}

func TestNetworkEgressPolicyValidator_ValidateCreate_Allowed(t *testing.T) {
	v := &NetworkEgressPolicyValidator{Authorizer: fakeAuthorizer{allow: true}}
	_, err := v.ValidateCreate(contextWithRequester("alice"), testEgressPolicy())
	if err != nil {
		t.Fatalf("ValidateCreate: unexpected error: %v", err)
	}
}

func TestNetworkEgressPolicyValidator_ValidateCreate_Denied(t *testing.T) {
	v := &NetworkEgressPolicyValidator{Authorizer: fakeAuthorizer{allow: false}}
	_, err := v.ValidateCreate(contextWithRequester("mallory"), testEgressPolicy())
	if err == nil {
		t.Fatal("ValidateCreate: expected error when Authorizer denies")
	}
}

func TestNetworkEgressPolicyValidator_ValidateCreate_AuthorizerErrorFailsClosed(t *testing.T) {
	v := &NetworkEgressPolicyValidator{
		Authorizer: fakeAuthorizer{allow: true, err: errors.New("companion operator unreachable")},
	}
	_, err := v.ValidateCreate(contextWithRequester("alice"), testEgressPolicy())
	if err == nil {
		t.Fatal("ValidateCreate: expected error when Authorizer itself fails (fail-closed)")
	}
}

func TestNetworkEgressPolicyValidator_ValidateUpdate_ReChecksNewObject(t *testing.T) {
	v := &NetworkEgressPolicyValidator{Authorizer: fakeAuthorizer{allow: false}}
	oldPolicy := testEgressPolicy()
	newPolicy := testEgressPolicy()
	newPolicy.Spec.VPCRef = "someone-elses-vpc"
	_, err := v.ValidateUpdate(contextWithRequester("mallory"), oldPolicy, newPolicy)
	if err == nil {
		t.Fatal("ValidateUpdate: expected error when Authorizer denies the updated object")
	}
}

func TestNetworkEgressPolicyValidator_ValidateDelete_NoAuthorizationCheck(t *testing.T) {
	v := &NetworkEgressPolicyValidator{Authorizer: fakeAuthorizer{allow: false}}
	if _, err := v.ValidateDelete(context.Background(), testEgressPolicy()); err != nil {
		t.Fatalf("ValidateDelete: unexpected error: %v", err)
	}
}

func TestNetworkEgressPolicyValidator_MissingAdmissionRequestErrors(t *testing.T) {
	v := &NetworkEgressPolicyValidator{Authorizer: fakeAuthorizer{allow: true}}
	// No admission.Request on the context.
	_, err := v.ValidateCreate(context.Background(), testEgressPolicy())
	if err == nil {
		t.Fatal("ValidateCreate: expected error when no admission.Request is present on context")
	}
}

func TestNetworkEgressPolicyValidator_SharesAuthorizerWithNetworkRule(t *testing.T) {
	// The same Authorizer instance must satisfy both validators without
	// modification — the whole point of narrowing the interface to
	// vpcRef/vpcAttachmentRef strings (design plan §4.1).
	auth := fakeAuthorizer{allow: true}
	ruleValidator := &NetworkRuleValidator{Authorizer: auth}
	policyValidator := &NetworkEgressPolicyValidator{Authorizer: auth}

	if _, err := ruleValidator.ValidateCreate(contextWithRequester("alice"), testRule()); err != nil {
		t.Errorf("NetworkRuleValidator.ValidateCreate: unexpected error: %v", err)
	}
	if _, err := policyValidator.ValidateCreate(contextWithRequester("alice"), testEgressPolicy()); err != nil {
		t.Errorf("NetworkEgressPolicyValidator.ValidateCreate: unexpected error: %v", err)
	}
}
