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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	bgpv1alpha1 "go.datum.net/network/api/v1alpha1"
)

const (
	testEncapNode    = "dfw-worker2"
	testEncapLocator = "2001:db8:ff01::/48"
	testEncapDerived = "2001:db8:ff01:1002::"
)

func testEncapRouter(namespace, name, node, locator string, nodeID int32) *bgpv1alpha1.BGPRouter {
	return &bgpv1alpha1.BGPRouter{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Spec: bgpv1alpha1.BGPRouterSpec{
			TargetRef:   bgpv1alpha1.TargetRef{Kind: "Node", Name: node},
			SRv6Locator: locator,
			NodeID:      nodeID,
		},
	}
}

func testEncapReader(t *testing.T, objs ...client.Object) client.Reader {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := bgpv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("add scheme: %v", err)
	}
	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build()
}

func TestResolveEncapSource(t *testing.T) {
	tests := []struct {
		name       string
		configured string
		routers    []client.Object
		want       string
		wantErr    string
	}{
		{
			name:       "configured value wins over the router",
			configured: "2001:db8:ffff::1",
			routers:    []client.Object{testEncapRouter("galactic-system", "r", testEncapNode, testEncapLocator, 0x1002)},
			want:       "2001:db8:ffff::1",
		},
		{
			name:    "derived from this node's router",
			routers: []client.Object{testEncapRouter("galactic-system", "r", testEncapNode, testEncapLocator, 0x1002)},
			want:    testEncapDerived,
		},
		{
			name: "other nodes' routers and routers without an identity are skipped",
			routers: []client.Object{
				testEncapRouter("galactic-system", "other", "dfw-worker3", testEncapLocator, 0x1003),
				testEncapRouter("tenant", "bare", testEncapNode, "", 0),
				testEncapRouter("galactic-system", "r", testEncapNode, testEncapLocator, 0x1002),
			},
			want: testEncapDerived,
		},
		{
			name: "routers targeting a non-Node object with the same name are skipped",
			routers: []client.Object{
				&bgpv1alpha1.BGPRouter{
					ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: "machine"},
					Spec: bgpv1alpha1.BGPRouterSpec{
						TargetRef:   bgpv1alpha1.TargetRef{Kind: "Machine", Name: testEncapNode},
						SRv6Locator: "2001:db8:aaaa::/48",
						NodeID:      0x1002,
					},
				},
				testEncapRouter("galactic-system", "r", testEncapNode, testEncapLocator, 0x1002),
			},
			want: testEncapDerived,
		},
		{
			name: "a router with no target kind still matches the node",
			routers: []client.Object{
				&bgpv1alpha1.BGPRouter{
					ObjectMeta: metav1.ObjectMeta{Namespace: "galactic-system", Name: "bare-kind"},
					Spec: bgpv1alpha1.BGPRouterSpec{
						TargetRef:   bgpv1alpha1.TargetRef{Name: testEncapNode},
						SRv6Locator: testEncapLocator,
						NodeID:      0x1002,
					},
				},
			},
			want: testEncapDerived,
		},
		{
			name: "two routers agreeing on the address",
			routers: []client.Object{
				testEncapRouter("a", "r", testEncapNode, testEncapLocator, 0x1002),
				testEncapRouter("b", "r", testEncapNode, testEncapLocator, 0x1002),
			},
			want: testEncapDerived,
		},
		{
			name: "two routers disagreeing on the address",
			routers: []client.Object{
				testEncapRouter("a", "r", testEncapNode, testEncapLocator, 0x1002),
				testEncapRouter("b", "r", testEncapNode, testEncapLocator, 0x1003),
			},
			wantErr: "derive different SRv6 encapsulation sources",
		},
		{
			name:    "router with an invalid locator",
			routers: []client.Object{testEncapRouter("galactic-system", "r", testEncapNode, "2001:db8::/64", 0x1002)},
			wantErr: "must be a /48",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveEncapSource(context.Background(), testEncapReader(t, tc.routers...),
				testEncapNode, tc.configured)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("resolveEncapSource() = %q, %v; want error containing %q", got, err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveEncapSource() error: %v", err)
			}
			if got != tc.want {
				t.Errorf("resolveEncapSource() = %q, want %q", got, tc.want)
			}
		})
	}
}

// appearingReader lists nothing until its first List call has returned, then
// lists the router: a node whose BGPRouter lands after the gateway starts.
type appearingReader struct {
	client.Reader
	calls int
}

func (r *appearingReader) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	r.calls++
	if r.calls == 1 {
		return nil
	}
	return r.Reader.List(ctx, list, opts...)
}

func TestResolveEncapSourceWaitsForRouter(t *testing.T) {
	reader := &appearingReader{
		Reader: testEncapReader(t, testEncapRouter("galactic-system", "r", testEncapNode, testEncapLocator, 0x1002)),
	}
	got, err := resolveEncapSource(context.Background(), reader, testEncapNode, "")
	if err != nil {
		t.Fatalf("resolveEncapSource() error: %v", err)
	}
	if got != testEncapDerived {
		t.Errorf("resolveEncapSource() = %q, want %q", got, testEncapDerived)
	}
	if reader.calls != 2 {
		t.Errorf("List called %d times, want 2", reader.calls)
	}
}

func TestResolveEncapSourceStopsWithContext(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := resolveEncapSource(ctx, testEncapReader(t), testEncapNode, "")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("resolveEncapSource() error = %v, want context.DeadlineExceeded", err)
	}
	if !strings.Contains(err.Error(), testEncapNode) {
		t.Errorf("resolveEncapSource() error = %v, want it to name node %s", err, testEncapNode)
	}
}
