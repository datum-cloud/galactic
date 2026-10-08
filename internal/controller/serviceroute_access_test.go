// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"context"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	cloudv1alpha1 "go.datum.net/cloud/api/v1alpha1"
	networkv1alpha1 "go.datum.net/network/api/v1alpha1"
)

const (
	testPSCVPCName       = "vpc"
	testPSCEligibleLabel = "yes"
	testPSCProducerLabel = "producer"
	testPSCCompetingName = "psc-other"
)

func TestTranslatedPolicyRequiresLiveConsumerPin(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = cloudv1alpha1.AddToScheme(scheme)
	vpc := &cloudv1alpha1.VPC{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testServiceRouteConsumerName,
			Name:      testPSCVPCName,
			UID:       "live",
		},
		Status: cloudv1alpha1.VPCStatus{
			VPC: "identity",
		},
	}
	r := &ServiceRoutePolicyReconciler{Client: fake.NewClientBuilder().WithScheme(scheme).WithObjects(vpc).Build()}
	for _, tt := range []struct {
		name      string
		ref       *networkv1alpha1.ServiceRouteVPCReference
		frontend  bool
		wantError bool
	}{
		{
			"LegacyDirect",
			nil,
			false,
			false,
		}, {
			"Missing",
			nil,
			true,
			true,
		}, {
			"Incomplete",
			&networkv1alpha1.ServiceRouteVPCReference{
				Name: testPSCVPCName,
			},
			true,
			true,
		},
		{
			"WrongUID",
			&networkv1alpha1.ServiceRouteVPCReference{
				Name: testPSCVPCName,
				UID:  "old",
			},
			true,
			true,
		}, {
			"Current",
			&networkv1alpha1.ServiceRouteVPCReference{
				Name: testPSCVPCName,
				UID:  "live",
			},
			true,
			false,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p := &networkv1alpha1.ServiceRoutePolicy{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: testServiceRouteConsumerName,
				},
				Spec: networkv1alpha1.ServiceRoutePolicySpec{
					ConsumerVPCRef: tt.ref,
				},
			}
			if tt.frontend {
				p.Spec.Frontend = &networkv1alpha1.ServiceRouteFrontend{Address: "fd53::53"}
			}
			_, err := r.consumerVPCIdentity(context.Background(), p)
			if (err != nil) != tt.wantError {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestTranslatedAuthorizationBound(t *testing.T) {
	now := time.Unix(1000, 0)
	r := &ServiceRoutePolicyReconciler{Now: func() time.Time { return now }}
	for _, tt := range []struct {
		name      string
		offset    time.Duration
		wantError bool
	}{
		{
			"Expired",
			-time.Second,
			true,
		},
		{
			"AtDeadline",
			0,
			true,
		},
		{
			"Current",
			90 * time.Second,
			false,
		},
		{
			"Unbounded",
			121 * time.Second,
			true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p := &networkv1alpha1.ServiceRoutePolicy{
				Spec: networkv1alpha1.ServiceRoutePolicySpec{
					Frontend: &networkv1alpha1.ServiceRouteFrontend{},
					Authorization: &networkv1alpha1.ServiceRouteAuthorization{
						ValidUntil: metav1.NewTime(now.Add(tt.offset)),
					},
				},
			}
			if err := r.validateAuthorization(p); (err != nil) != tt.wantError {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func pscFixture(t *testing.T) (
	*ServiceRoutePolicyReconciler, *networkv1alpha1.ServiceRoutePolicy, *networkv1alpha1.ServiceEndpoint,
) {
	t.Helper()
	scheme := runtime.NewScheme()
	_ = cloudv1alpha1.AddToScheme(scheme)
	_ = networkv1alpha1.AddToScheme(scheme)
	now := time.Now()
	p := &networkv1alpha1.ServiceRoutePolicy{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:  testServiceRouteConsumerName,
			Name:       testServiceRouteName,
			UID:        "policy",
			Generation: 1,
		},
		Spec: networkv1alpha1.ServiceRoutePolicySpec{
			ServiceRef: networkv1alpha1.ServiceEndpointReference{
				Name: testServiceRouteName,
			},
			ConsumerVPCRef: &networkv1alpha1.ServiceRouteVPCReference{
				Name: testPSCVPCName,
				UID:  testPSCVPCName,
			},
			Frontend: &networkv1alpha1.ServiceRouteFrontend{
				Address: "fd53::53",
			},
			Authorization: &networkv1alpha1.ServiceRouteAuthorization{
				ValidUntil: metav1.NewTime(now.Add(90 * time.Second)),
			},
			AttachmentSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{
					testServiceRouteConsumerName: testPSCEligibleLabel,
				},
			},
		},
	}
	e := &networkv1alpha1.ServiceEndpoint{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:  testServiceRouteConsumerName,
			Name:       testServiceRouteName,
			UID:        "endpoint",
			Generation: 1,
		},
		Spec: networkv1alpha1.ServiceEndpointSpec{
			Address:      "fd70::10",
			Protocol:     networkv1alpha1.NetworkRuleProtocolUDP,
			Port:         53,
			DeliveryMode: networkv1alpha1.ServiceEndpointDeliveryModeNodeLocal,
			AttachmentSelector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					testPSCProducerLabel: testPSCEligibleLabel,
				},
			},
		},
	}
	v := &cloudv1alpha1.VPC{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testServiceRouteConsumerName,
			Name:      testPSCVPCName,
			UID:       testPSCVPCName,
		},
		Status: cloudv1alpha1.VPCStatus{
			VPC: "vpc-identity",
		},
	}
	attachment := func(ns, name, role, vpc string) *cloudv1alpha1.VPCAttachment {
		return &cloudv1alpha1.VPCAttachment{
			ObjectMeta: metav1.ObjectMeta{
				Namespace:  ns,
				Name:       name,
				UID:        types.UID(name),
				Generation: 1,
				Labels: map[string]string{
					role: testPSCEligibleLabel,
				},
			},
			Spec: cloudv1alpha1.VPCAttachmentSpec{
				VPC: cloudv1alpha1.VPCRef{
					Name: testPSCVPCName,
				},
			},
			Status: cloudv1alpha1.VPCAttachmentStatus{
				ObservedGeneration: 1,
				Node:               "node-a",
				VPC:                vpc,
				VPCAttachment:      name,
				HostInterface:      name,
				Conditions: []metav1.Condition{
					{
						Type:   "Ready",
						Status: metav1.ConditionTrue,
					},
					{
						Type:   "Programmed",
						Status: metav1.ConditionTrue,
					},
				},
			},
		}
	}
	c := attachment(testServiceRouteConsumerName, "client", testServiceRouteConsumerName, "vpc-identity")
	s := attachment("service", "server", testPSCProducerLabel, "service-vpc")
	r := &ServiceRoutePolicyReconciler{
		Client: fake.NewClientBuilder().WithScheme(scheme).
			WithStatusSubresource(&networkv1alpha1.ServiceRoutePolicy{}).WithObjects(p, e, v, c, s).Build(),
		NodeName:        "node-a",
		FrontendEnabled: true,
		Programmer:      &retryRouteProgrammer{},
		Now:             func() time.Time { return now },
	}
	return r, p, e
}

func TestConflictingPoliciesFailClosedAndRecover(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		t.Run(map[bool]string{false: "Forward", true: "Reverse"}[reverse], func(t *testing.T) {
			r, p, e := pscFixture(t)
			ctx := context.Background()
			other := p.DeepCopy()
			other.Name = testPSCCompetingName
			other.UID = testPSCCompetingName
			other.ResourceVersion = ""
			e2 := e.DeepCopy()
			e2.Name = testPSCCompetingName
			e2.UID = "other-endpoint"
			e2.ResourceVersion = ""
			e2.Spec.Address = "fd70::20"
			other.Spec.ServiceRef.Name = e2.Name
			if err := r.Create(ctx, e2); err != nil {
				t.Fatal(err)
			}
			if err := r.Create(ctx, other); err != nil {
				t.Fatal(err)
			}
			policies := []*networkv1alpha1.ServiceRoutePolicy{p, other}
			if reverse {
				policies[0], policies[1] = policies[1], policies[0]
			}
			for _, policy := range policies {
				key := types.NamespacedName{Namespace: policy.Namespace, Name: policy.Name}
				if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: key}); err != nil {
					t.Fatal(err)
				}
				got := &networkv1alpha1.ServiceRoutePolicy{}
				_ = r.Get(ctx, key, got)
				if len(got.Status.Conditions) == 0 || got.Status.Conditions[0].Reason != "ConflictingPolicies" {
					t.Fatalf("status=%+v", got.Status)
				}
			}
			if len(r.Applied) != 0 {
				t.Fatal("conflicting winner retained")
			}
			if err := r.syncAllPolicies(ctx); err != nil {
				t.Fatal(err)
			}
			if len(r.Applied) != 0 {
				t.Fatal("startup adopted conflicting policies")
			}
			if err := r.Delete(ctx, other); err != nil {
				t.Fatal(err)
			}
			if _, err := r.Reconcile(ctx, ctrl.Request{
				NamespacedName: types.NamespacedName{
					Namespace: p.Namespace,
					Name:      p.Name,
				},
			}); err != nil {
				t.Fatal(err)
			}
			if len(r.Applied) != 1 {
				t.Fatal("surviving policy did not recover")
			}
		})
	}
}
