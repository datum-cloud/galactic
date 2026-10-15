// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package webhook

import (
	"context"
	"strings"
	"testing"

	admissionv1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
)

const (
	controller = "system:serviceaccount:galactic-system:galactic-controller"
	tenant     = "tenant"
	ns         = "tenant-a"
	web        = "web"
)

func request(op admissionv1.Operation, user, name, object string) admission.Request {
	r := admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{
		Operation: op, Name: name, Namespace: ns,
		UserInfo: authenticationv1.UserInfo{Username: user},
	}}
	if op == admissionv1.Delete {
		r.OldObject = runtime.RawExtension{Raw: []byte(object)}
	} else {
		r.Object = runtime.RawExtension{Raw: []byte(object)}
	}
	return r
}

func policyJSON(name, rules string) string {
	return `{"apiVersion":"galactic.datumapis.com/v1alpha1","kind":"TrafficPolicy",` +
		`"metadata":{"name":"` + name + `","namespace":"` + ns + `"},"spec":{"rules":` + rules + `}}`
}

func TestHandleWrites(t *testing.T) {
	v := &PolicyValidator{ControllerUsername: controller}
	tests := []struct {
		name, user, policy, rules string
		allowed                   bool
		wantMsg, wantWarning      string
	}{
		{name: "valid", user: tenant, policy: web, rules: `[{"name":"a","action":"Allow"}]`, allowed: true},
		{name: "null match", user: tenant, policy: web, rules: `[{"name":"a","action":"Allow","match":null}]`,
			wantMsg: "spec.rules[0].match: Invalid value: null"},
		{name: "null icmp code", user: tenant, policy: web,
			rules:   `[{"name":"a","action":"Allow","match":{"protocol":"ICMP","icmp":{"type":3,"code":null}}}]`,
			wantMsg: "spec.rules[0].match.icmp.code"},
		{name: "every null reported", user: tenant, policy: web,
			rules: `[{"name":"a","action":"Allow","match":{"sourceIPs":null}},` +
				`{"name":"b","action":"Allow","match":{"icmp":null}}]`,
			wantMsg: "spec.rules[1].match.icmp"},
		{name: "invalid spec", user: tenant, policy: web,
			rules:   `[{"name":"a","action":"Allow","match":{"sourceCIDRs":["10.0.0.1/8"]}}]`,
			wantMsg: "no host bits"},
		{name: "shadowed warns", user: tenant, policy: web,
			rules: `[{"name":"all","action":"Deny"},{"name":"web","action":"Allow","match":{"protocol":"TCP"}}]`, allowed: true,
			wantWarning: "spec.rules[1] (web) is never reached"},
		{name: "unreachable warns", user: tenant, policy: web,
			rules: `[{"name":"x","action":"Allow",` +
				`"match":{"sourceIPs":["192.0.2.1"],"destinationIPs":["2001:db8::1"]}}]`,
			allowed:     true,
			wantWarning: "spec.rules[0] (x) can never match"},
		{name: "reserved name by tenant", user: tenant, policy: galacticv1alpha1.DefaultPolicyName,
			rules: `[{"name":"deny-all","action":"Deny"}]`, wantMsg: "reserved"},
		{name: "reserved name by controller", user: controller, policy: galacticv1alpha1.DefaultPolicyName,
			rules: `[{"name":"deny-all","action":"Deny"}]`, allowed: true},
		{name: "reserved name with another spec", user: controller, policy: galacticv1alpha1.DefaultPolicyName,
			rules: `[{"name":"deny-all","action":"Allow"}]`, wantMsg: "exactly one rule"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := v.Handle(context.Background(), request(admissionv1.Create, tt.user, tt.policy,
				policyJSON(tt.policy, tt.rules)))
			if resp.Allowed != tt.allowed {
				t.Fatalf("allowed = %v (%v), want %v", resp.Allowed, resp.Result, tt.allowed)
			}
			if tt.wantMsg != "" && !strings.Contains(resp.Result.Message, tt.wantMsg) {
				t.Errorf("message %q does not contain %q", resp.Result.Message, tt.wantMsg)
			}
			if tt.wantWarning != "" && (len(resp.Warnings) == 0 || !strings.Contains(strings.Join(resp.Warnings, "\n"),
				tt.wantWarning)) {
				t.Errorf("warnings %v do not contain %q", resp.Warnings, tt.wantWarning)
			}
		})
	}
}

func TestHandleReservedDelete(t *testing.T) {
	active := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}}
	terminating := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
		Name: ns, DeletionTimestamp: new(metav1.Now()), Finalizers: []string{"kubernetes"},
	}}
	managed := `{"metadata":{"name":"default-deny-all","namespace":"tenant-a",` +
		`"labels":{"galactic.datumapis.com/managed-by":"galactic-controller"}}}`
	unmanaged := `{"metadata":{"name":"default-deny-all","namespace":"tenant-a"}}`
	tests := []struct {
		name    string
		ns      *corev1.Namespace
		user    string
		policy  string
		old     string
		allowed bool
	}{
		{"tenant, active namespace", active, tenant, galacticv1alpha1.DefaultPolicyName, managed, false},
		{"tenant, terminating namespace", terminating, tenant, galacticv1alpha1.DefaultPolicyName, managed, true},
		{"tenant, a conflicting object", active, tenant, galacticv1alpha1.DefaultPolicyName, unmanaged, true},
		{"controller", active, controller, galacticv1alpha1.DefaultPolicyName, managed, true},
		{"ordinary policy", active, tenant, web, `{}`, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &PolicyValidator{
				ControllerUsername: controller,
				Reader:             fake.NewClientBuilder().WithObjects(tt.ns).Build(),
			}
			resp := v.Handle(context.Background(), request(admissionv1.Delete, tt.user, tt.policy, tt.old))
			if resp.Allowed != tt.allowed {
				t.Errorf("allowed = %v (%v), want %v", resp.Allowed, resp.Result, tt.allowed)
			}
		})
	}
}

// TestHandleUnmanagedReservedUpdate lets the owner of a conflicting object
// that predates the webhook edit it, but never turn it into the managed one.
func TestHandleUnmanagedReservedUpdate(t *testing.T) {
	v := &PolicyValidator{ControllerUsername: controller}
	unmanaged := policyJSON(galacticv1alpha1.DefaultPolicyName, `[{"name":"deny-all","action":"Deny"}]`)
	labeled := `{"apiVersion":"galactic.datumapis.com/v1alpha1","kind":"TrafficPolicy",` +
		`"metadata":{"name":"default-deny-all","namespace":"tenant-a",` +
		`"labels":{"galactic.datumapis.com/managed-by":"galactic-controller"}},` +
		`"spec":{"rules":[{"name":"deny-all","action":"Deny"}]}}`
	update := func(oldObj, newObj string) admission.Response {
		r := request(admissionv1.Update, tenant, galacticv1alpha1.DefaultPolicyName, newObj)
		r.OldObject = runtime.RawExtension{Raw: []byte(oldObj)}
		return v.Handle(context.Background(), r)
	}
	if resp := update(unmanaged, unmanaged); !resp.Allowed {
		t.Errorf("owner edit of an unmanaged object denied: %v", resp.Result)
	}
	if resp := update(unmanaged, labeled); resp.Allowed {
		t.Error("tenant adopted the reserved name by adding the managed-by label")
	}
	if resp := update(labeled, labeled); resp.Allowed {
		t.Error("tenant updated the controller's default policy")
	}
}
