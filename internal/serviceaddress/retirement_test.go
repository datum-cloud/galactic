// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package serviceaddress

import (
	"context"
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	api "go.datum.net/galactic/api/network/v1alpha1"
)

const (
	retiredName      = "retired"
	allocationUID    = "claim"
	gatewayNamespace = "gateways"
)

func TestPreemptiveRetirementWithoutGateways(t *testing.T) {
	for _, tc := range []struct {
		name       string
		generation int64
		pending    bool
		want       bool
	}{
		{"NeverActivated", 1, false, true}, {"HistoricalAllocation", 2, false, false}, {"BindingPending", 1, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			scheme := runtime.NewScheme()
			if err := api.AddToScheme(scheme); err != nil {
				t.Fatal(err)
			}
			address := &api.NetworkServiceAddress{
				ObjectMeta: metav1.ObjectMeta{
					Name:       retiredName,
					Namespace:  "project",
					UID:        "anchor",
					Generation: tc.generation,
				},
				Spec: api.NetworkServiceAddressSpec{
					Retired:    true,
					VIPAddress: "2001:db8::1",
					Group:      api.NetworkServiceAddressGroup{UID: allocationUID, Generation: 1, Revision: retiredName},
				},
			}
			builder := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(address).WithObjects(address)
			if tc.pending {
				builder = builder.WithObjects(
					&api.ServiceVIPBinding{
						ObjectMeta: metav1.ObjectMeta{Name: "pending", Namespace: gatewayNamespace},
						Spec: api.ServiceVIPBindingSpec{
							SourceRef: &api.ServiceVIPBindingSourceReference{AllocationUID: allocationUID},
						},
					},
				)
			}
			c := builder.Build()
			r := &RetirementReconciler{Client: c, APIReader: c}
			if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(address)}); err != nil {
				t.Fatal(err)
			}
			if err := c.Get(ctx, client.ObjectKeyFromObject(address), address); err != nil {
				t.Fatal(err)
			}
			if got := meta.IsStatusConditionTrue(address.Status.Conditions, api.ConditionTypeAddressRetired); got != tc.want {
				t.Fatalf("retired=%t want=%t", got, tc.want)
			}
			if tc.want && len(address.Finalizers) == 0 {
				t.Fatal("terminal authority was not retained")
			}
			if tc.pending {
				c := meta.FindStatusCondition(address.Status.Conditions, api.ConditionTypeAddressRetired)
				if c == nil || c.Reason != reasonForwardingState ||
					!strings.Contains(c.Message, "ServiceVIPBinding gateways/pending") {
					t.Fatalf("pending condition = %+v", c)
				}
			}
		})
	}
}

func retirementFixture(t *testing.T) (*runtime.Scheme, *api.NetworkServiceAddress) {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := api.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	return scheme, &api.NetworkServiceAddress{
		ObjectMeta: metav1.ObjectMeta{Name: retiredName, Namespace: "project", UID: "anchor", Generation: 1},
		Spec: api.NetworkServiceAddressSpec{
			Retired:    true,
			VIPAddress: "2001:db8::1",
			Group:      api.NetworkServiceAddressGroup{UID: allocationUID, Generation: 1, Revision: retiredName},
		},
	}
}

func gateway(name, node string) *api.NetworkGateway {
	return &api.NetworkGateway{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: gatewayNamespace},
		Spec:       api.NetworkGatewaySpec{TargetRef: api.TargetRef{Name: node}},
	}
}

func TestRetirementBacksOffWhileGatewayNeverAcknowledges(t *testing.T) {
	ctx := context.Background()
	scheme, address := retirementFixture(t)
	c := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(address).WithObjects(
		address, gateway("gw-d", "node-d"), gateway("gw-b", "node-b"), gateway("gw-a", "node-a"), gateway("gw-c", "node-c"),
	).Build()
	r := &RetirementReconciler{Client: c, APIReader: c}
	key := client.ObjectKeyFromObject(address)
	reconcile := func() time.Duration {
		t.Helper()
		result, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: key})
		if err != nil {
			t.Fatal(err)
		}
		if err := c.Get(ctx, key, address); err != nil {
			t.Fatal(err)
		}
		return result.RequeueAfter
	}

	if got := reconcile(); got != minRetirementBackoff {
		t.Fatalf("first wait = %s, want %s", got, minRetirementBackoff)
	}
	condition := meta.FindStatusCondition(address.Status.Conditions, api.ConditionTypeAddressRetired)
	if condition == nil || condition.Status != metav1.ConditionFalse || condition.Reason != reasonAwaitingGateway {
		t.Fatalf("waiting condition = %+v", condition)
	}
	want := "NetworkGateways: gateways/gw-a (node node-a), gateways/gw-b (node node-b), " +
		"gateways/gw-c (node node-c) and 1 more"
	if !strings.HasSuffix(condition.Message, want) {
		t.Fatalf("message = %q, want suffix %q", condition.Message, want)
	}

	version := address.ResourceVersion
	reconcile()
	if address.ResourceVersion != version {
		t.Fatal("an unchanged wait rewrote status")
	}

	for _, tc := range []struct {
		waited   time.Duration
		min, max time.Duration
	}{
		{30 * time.Second, 30 * time.Second, 31 * time.Second},
		{time.Hour, maxRetirementBackoff, maxRetirementBackoff},
	} {
		meta.FindStatusCondition(address.Status.Conditions, api.ConditionTypeAddressRetired).LastTransitionTime =
			metav1.NewTime(time.Now().Add(-tc.waited))
		if err := c.Status().Update(ctx, address); err != nil {
			t.Fatal(err)
		}
		if got := reconcile(); got < tc.min || got > tc.max {
			t.Fatalf("after waiting %s: requeue = %s, want within [%s, %s]", tc.waited, got, tc.min, tc.max)
		}
	}
	if meta.IsStatusConditionTrue(address.Status.Conditions, api.ConditionTypeAddressRetired) {
		t.Fatal("retired without a gateway acknowledgement")
	}
}

func TestRetirementConfirmsEmptyCacheWithAPIServer(t *testing.T) {
	ctx := context.Background()
	scheme, address := retirementFixture(t)
	cache := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(address).
		WithObjects(address.DeepCopy()).Build()
	apiServer := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(address.DeepCopy(), gateway("gw-a", "node-a")).Build()
	r := &RetirementReconciler{Client: cache, APIReader: apiServer}
	key := client.ObjectKeyFromObject(address)
	result, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: key})
	if err != nil {
		t.Fatal(err)
	}
	if result.RequeueAfter != minRetirementBackoff {
		t.Fatalf("requeue = %s, want %s", result.RequeueAfter, minRetirementBackoff)
	}
	if err := cache.Get(ctx, key, address); err != nil {
		t.Fatal(err)
	}
	c := meta.FindStatusCondition(address.Status.Conditions, api.ConditionTypeAddressRetired)
	if c == nil || c.Reason != reasonAwaitingGateway {
		t.Fatalf("condition = %+v, want %s", c, reasonAwaitingGateway)
	}
}

func TestRetirementNamesReferrersDeterministically(t *testing.T) {
	ctx := context.Background()
	scheme, address := retirementFixture(t)
	builder := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(address).WithObjects(address)
	for _, name := range []string{"binding-c", "binding-a", "binding-b"} {
		builder = builder.WithObjects(&api.ServiceVIPBinding{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: gatewayNamespace},
			Spec: api.ServiceVIPBindingSpec{
				SourceRef: &api.ServiceVIPBindingSourceReference{AllocationUID: allocationUID},
			},
		})
	}
	c := builder.Build()
	r := &RetirementReconciler{Client: c, APIReader: c}
	key := client.ObjectKeyFromObject(address)
	version := ""
	for pass := range 5 {
		if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: key}); err != nil {
			t.Fatal(err)
		}
		if err := c.Get(ctx, key, address); err != nil {
			t.Fatal(err)
		}
		c := meta.FindStatusCondition(address.Status.Conditions, api.ConditionTypeAddressRetired)
		if c == nil || !strings.Contains(c.Message, "ServiceVIPBinding gateways/binding-a ") {
			t.Fatalf("pass %d condition = %+v", pass, c)
		}
		if pass > 0 && address.ResourceVersion != version {
			t.Fatalf("pass %d rewrote status", pass)
		}
		version = address.ResourceVersion
	}
}

func TestReferrerPicksLowestName(t *testing.T) {
	var r referrer
	refs := [][2]string{{"zone", "a"}, {gatewayNamespace, "c"}, {gatewayNamespace, "a"}, {gatewayNamespace, "b"}}
	for _, ref := range refs {
		r.offer(ref[0], ref[1])
	}
	if got := r.pending("ServiceVIPBinding"); got == nil || !strings.Contains(got.message, " gateways/a ") {
		t.Fatalf("pending = %+v, want gateways/a", got)
	}
	if (&referrer{}).pending("ServiceVIPBinding") != nil {
		t.Fatal("empty referrer reported pending")
	}
}
