// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	authorizationv1 "k8s.io/api/authorization/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

// accessReviewClient returns a client that answers every
// SelfSubjectAccessReview with allowed(verb, resource), or fails the review
// with reviewErr when it is set.
func accessReviewClient(
	t *testing.T, allowed func(verb, resource string) bool, reviewErr error,
) (client.Client, *[]string) {
	return failingAccessReviewClient(t, allowed, reviewErr, -1)
}

// failingAccessReviewClient is accessReviewClient whose first failures access
// reviews return reviewErr; a negative failures fails every review.
func failingAccessReviewClient(
	t *testing.T, allowed func(verb, resource string) bool, reviewErr error, failures int,
) (client.Client, *[]string) {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := authorizationv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	var asked []string
	c := fake.NewClientBuilder().WithScheme(scheme).WithInterceptorFuncs(interceptor.Funcs{
		Create: func(_ context.Context, _ client.WithWatch, obj client.Object, _ ...client.CreateOption) error {
			review, ok := obj.(*authorizationv1.SelfSubjectAccessReview)
			if !ok {
				t.Fatalf("unexpected create of %T", obj)
			}
			attrs := review.Spec.ResourceAttributes
			asked = append(asked, attrs.Verb+" "+attrs.Resource)
			if reviewErr != nil && failures != 0 {
				failures--
				return reviewErr
			}
			review.Status.Allowed = allowed(attrs.Verb, attrs.Resource)
			return nil
		},
	}).Build()
	return c, &asked
}

// TestResolveIPv4VIPs covers the IPv4 VIP RBAC pre-flight: IPv4 VIPs stay on
// only when they are requested and ServiceVIPBindings can be listed and
// watched, and a denied verb or a review that cannot be submitted turns them
// off, naming what is missing, so the gateway keeps serving IPv6 rather than
// stalling on a cache that never syncs.
func TestResolveIPv4VIPs(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name      string
		requested bool
		allowed   func(verb, resource string) bool
		reviewErr error
		failures  int
		want      bool
		wantErr   bool
		wantAsked bool
	}{
		{name: "NotRequested", allowed: func(string, string) bool { return true }},
		{
			name: "Allowed", requested: true, want: true, wantAsked: true,
			allowed: func(_, resource string) bool { return resource == resourceServiceVIPBinding },
		},
		{
			name: "WatchDenied", requested: true, wantAsked: true,
			allowed: func(verb, _ string) bool { return verb == "list" },
		},
		{
			// A review that cannot be made is not a denial: it fails startup
			// rather than turning IPv4 off.
			name: "ReviewFails", requested: true, wantErr: true, wantAsked: true,
			allowed:   func(string, string) bool { return true },
			reviewErr: errors.New("injected review failure"), failures: -1,
		},
		{
			name: "ReviewFailsThenSucceeds", requested: true, want: true, wantAsked: true,
			allowed:   func(string, string) bool { return true },
			reviewErr: errors.New("injected review failure"), failures: 2,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			saved := ipv4ReviewRetry
			ipv4ReviewRetry = time.Millisecond
			t.Cleanup(func() { ipv4ReviewRetry = saved })
			ctx, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
			defer cancel()
			c, asked := failingAccessReviewClient(t, tc.allowed, tc.reviewErr, tc.failures)
			got, err := resolveIPv4VIPs(ctx, c, tc.requested)
			if got != tc.want || (err != nil) != tc.wantErr {
				t.Errorf("resolveIPv4VIPs = %v, %v; want %v, error %v", got, err, tc.want, tc.wantErr)
			}
			if (len(*asked) > 0) != tc.wantAsked {
				t.Errorf("access reviews = %v, want any: %v", *asked, tc.wantAsked)
			}
		})
	}

	c, _ := accessReviewClient(t, func(string, string) bool { return false }, nil)
	err := ipv4VIPsAllowed(ctx, c)
	if err == nil || !strings.Contains(err.Error(), "list and watch on servicevipbindings") {
		t.Errorf("ipv4VIPsAllowed error = %v, want one naming list and watch on servicevipbindings", err)
	}
}

// TestCheckWatchPermissions covers the startup RBAC pre-flight: a denied
// watch fails startup, and VPCs are checked only with project services on.
func TestCheckWatchPermissions(t *testing.T) {
	ctx := context.Background()
	allowAll := func(string, string) bool { return true }
	denyVPCs := func(_, resource string) bool { return resource != resourceVPCs }

	c, asked := accessReviewClient(t, denyVPCs, nil)
	if err := checkWatchPermissions(ctx, c, false); err != nil {
		t.Fatalf("project services off: %v, want nil", err)
	}
	for _, a := range *asked {
		if strings.HasSuffix(a, " "+resourceVPCs) {
			t.Errorf("checked %q with project services off", a)
		}
	}

	c, _ = accessReviewClient(t, denyVPCs, nil)
	err := checkWatchPermissions(ctx, c, true)
	if err == nil || !strings.Contains(err.Error(), resourceVPCs) {
		t.Fatalf("project services on without VPC access: %v, want an error naming %s", err, resourceVPCs)
	}

	c, _ = accessReviewClient(t, allowAll, nil)
	if err := checkWatchPermissions(ctx, c, true); err != nil {
		t.Fatalf("all granted: %v, want nil", err)
	}

	c, _ = accessReviewClient(t, allowAll, errors.New("unavailable"))
	if err := checkWatchPermissions(ctx, c, true); err != nil {
		t.Fatalf("reviews that cannot be made: %v, want nil", err)
	}
}
