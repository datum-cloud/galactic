// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package webhook is the validating admission webhook for TrafficPolicy. It
// rejects what the CRD schema cannot: an explicit null at an optional match
// constraint, addresses that only fail once parsed and canonicalized, a
// policy that would exceed the datapath's compiled entry limit, and any
// write to the reserved default policy name by anyone but the controller.
package webhook

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"

	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
	"go.datum.net/galactic/internal/trafficpolicy"
)

// ManagedByLabel marks the default policy galactic-controller provisions.
const (
	ManagedByLabel = "galactic.datumapis.com/managed-by"
	ManagedByValue = "galactic-controller"
)

// Path is where the webhook is served.
const Path = "/validate-galactic-datumapis-com-v1alpha1-trafficpolicy"

// nullableMatchFields are the match fields whose explicit null the schema
// preserves for this webhook to reject. The enum fields are absent: the
// schema's enum already rejects a null there.
var nullableMatchFields = []string{
	"sourceIPs", "destinationIPs", "sourceCIDRs", "destinationCIDRs",
	"sourcePorts", "destinationPorts", "icmp",
}

// PolicyValidator validates TrafficPolicy writes.
type PolicyValidator struct {
	// ControllerUsername is the authenticated user galactic-controller
	// runs as, the only one allowed to write the reserved default policy.
	ControllerUsername string

	// Reader reads the namespace of a reserved-name delete, which is
	// allowed while the namespace is being torn down.
	Reader client.Reader
}

var _ admission.Handler = (*PolicyValidator)(nil)

// Handle implements admission.Handler.
func (v *PolicyValidator) Handle(ctx context.Context, req admission.Request) admission.Response {
	switch req.Operation {
	case admissionv1.Create, admissionv1.Update:
		return v.validateWrite(req)
	case admissionv1.Delete:
		return v.validateDelete(ctx, req)
	default:
		return admission.Allowed("")
	}
}

func (v *PolicyValidator) validateWrite(req admission.Request) admission.Response {
	var raw map[string]any
	if err := json.Unmarshal(req.Object.Raw, &raw); err != nil {
		return admission.Errored(http.StatusBadRequest, fmt.Errorf("decode object: %w", err))
	}
	if errs := nullErrors(raw); len(errs) > 0 {
		return denied(req, errs)
	}

	var policy galacticv1alpha1.TrafficPolicy
	if err := json.Unmarshal(req.Object.Raw, &policy); err != nil {
		return admission.Errored(http.StatusBadRequest, fmt.Errorf("decode TrafficPolicy: %w", err))
	}
	if policy.Name == galacticv1alpha1.DefaultPolicyName {
		if req.UserInfo.Username != v.ControllerUsername && !isUnmanagedUpdate(req, &policy) {
			return admission.Denied(fmt.Sprintf("%q is reserved for the built-in default policy, which only "+
				"galactic-controller writes; reference it, or omit the reference to get the same default",
				galacticv1alpha1.DefaultPolicyName))
		}
		if !equality.Semantic.DeepEqual(policy.Spec, DefaultSpec()) {
			return admission.Denied(fmt.Sprintf("%q must have exactly one rule, %q with action Deny and no match",
				galacticv1alpha1.DefaultPolicyName, galacticv1alpha1.DefaultRuleName))
		}
	}

	p, errs := trafficpolicy.FromAPI(policy.Spec, field.NewPath("spec"))
	if len(errs) > 0 {
		return denied(req, errs)
	}
	resp := admission.Allowed("")
	for _, i := range p.Unreachable() {
		resp.Warnings = append(resp.Warnings, fmt.Sprintf("spec.rules[%d] (%s) can never match: its address lists "+
			"and family leave no packet that satisfies them", i, p.Rules[i].Name))
	}
	shadowed := trafficpolicy.Shadowed(p)
	for _, later := range slices.Sorted(maps.Keys(shadowed)) {
		earlier := shadowed[later]
		resp.Warnings = append(resp.Warnings, fmt.Sprintf("spec.rules[%d] (%s) is never reached: spec.rules[%d] (%s) "+
			"matches every packet it would", later, p.Rules[later].Name, earlier, p.Rules[earlier].Name))
	}
	return resp
}

func (v *PolicyValidator) validateDelete(ctx context.Context, req admission.Request) admission.Response {
	if req.Name != galacticv1alpha1.DefaultPolicyName || req.UserInfo.Username == v.ControllerUsername {
		return admission.Allowed("")
	}
	// An object holding the reserved name that the controller does not own
	// predates the webhook; deleting it is how its owner clears the
	// conflict so the controller can provision the real one.
	var old galacticv1alpha1.TrafficPolicy
	if err := json.Unmarshal(req.OldObject.Raw, &old); err != nil {
		return admission.Errored(http.StatusBadRequest, fmt.Errorf("decode old TrafficPolicy: %w", err))
	}
	if old.Labels[ManagedByLabel] != ManagedByValue {
		return admission.Allowed("not the controller's default policy")
	}
	var ns corev1.Namespace
	if err := v.Reader.Get(ctx, client.ObjectKey{Name: req.Namespace}, &ns); err != nil {
		return admission.Errored(http.StatusInternalServerError, fmt.Errorf("read namespace %s: %w", req.Namespace, err))
	}
	if !ns.DeletionTimestamp.IsZero() {
		return admission.Allowed("namespace is being deleted")
	}
	return admission.Denied(fmt.Sprintf("%q is managed by galactic-controller and is deleted with its namespace",
		galacticv1alpha1.DefaultPolicyName))
}

// isUnmanagedUpdate reports whether req updates an object holding the
// reserved name that the controller does not own and that stays unowned.
// Such an object predates the webhook; its owner may still edit it, for
// example to remove a finalizer before deleting it. It resolves to a deny
// whatever its spec says, so the edit grants nothing.
func isUnmanagedUpdate(req admission.Request, policy *galacticv1alpha1.TrafficPolicy) bool {
	if req.Operation != admissionv1.Update || policy.Labels[ManagedByLabel] == ManagedByValue {
		return false
	}
	var old galacticv1alpha1.TrafficPolicy
	if err := json.Unmarshal(req.OldObject.Raw, &old); err != nil {
		return false
	}
	return old.Labels[ManagedByLabel] != ManagedByValue
}

// DefaultSpec is the spec of the reserved default policy.
func DefaultSpec() galacticv1alpha1.TrafficPolicySpec {
	return galacticv1alpha1.TrafficPolicySpec{Rules: []galacticv1alpha1.TrafficRule{{
		Name: galacticv1alpha1.DefaultRuleName, Action: galacticv1alpha1.ActionDeny,
	}}}
}

// nullErrors finds explicit nulls at the optional match constraints of a
// decoded object, before Go's decoding turns them into omissions.
func nullErrors(obj map[string]any) field.ErrorList {
	spec, _ := obj["spec"].(map[string]any)
	rules, _ := spec["rules"].([]any)
	var errs field.ErrorList
	for i, r := range rules {
		rule, ok := r.(map[string]any)
		if !ok {
			continue
		}
		mp := field.NewPath("spec", "rules").Index(i).Child("match")
		m, present := rule["match"]
		if !present {
			continue
		}
		if m == nil {
			errs = append(errs, nullError(mp))
			continue
		}
		match, ok := m.(map[string]any)
		if !ok {
			continue
		}
		for _, f := range nullableMatchFields {
			if v, present := match[f]; present && v == nil {
				errs = append(errs, nullError(mp.Child(f)))
			}
		}
		if icmp, ok := match["icmp"].(map[string]any); ok {
			if v, present := icmp["code"]; present && v == nil {
				errs = append(errs, nullError(mp.Child("icmp", "code")))
			}
		}
	}
	return errs
}

func nullError(p *field.Path) *field.Error {
	return field.Invalid(p, nil, "must not be null; omit the field to match anything")
}

// denied is a rejection carrying every field error, so the client sees all
// of them at once.
func denied(req admission.Request, errs field.ErrorList) admission.Response {
	msgs := make([]string, len(errs))
	for i, e := range errs {
		msgs[i] = e.Error()
	}
	resp := admission.Denied(fmt.Sprintf("TrafficPolicy %s/%s is invalid: %s",
		req.Namespace, req.Name, strings.Join(msgs, "; ")))
	resp.Result.Code = http.StatusUnprocessableEntity
	return resp
}
