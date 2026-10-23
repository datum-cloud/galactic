// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package maintenance

import (
	"context"
	"errors"
	"maps"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
	"go.datum.net/galactic/internal/edge/hostattach"
	"go.datum.net/galactic/internal/edge/ownership"
)

const node = "edge-1"

func scheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := galacticv1alpha1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	return s
}

func attachment(name, nodeName, vpc string, released bool) *galacticv1alpha1.EdgeAttachment {
	a := &galacticv1alpha1.EdgeAttachment{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "edge"},
		Status:     galacticv1alpha1.EdgeAttachmentStatus{NodeName: nodeName, VPC: vpc},
	}
	if released {
		a.Status.Conditions = []metav1.Condition{{
			Type: galacticv1alpha1.EdgeAttachmentReleased, Status: metav1.ConditionTrue,
			Reason: "Released", LastTransitionTime: metav1.NewTime(time.Unix(1, 0)),
		}}
	}
	return a
}

// newGuard returns a guard over a fresh fence directory, the given objects
// and host links.
func newGuard(t *testing.T, c client.Client, links ...hostattach.ObservedAttachment) *Guard {
	t.Helper()
	auth, err := ownership.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return &Guard{Reader: c, NodeName: node, Ownership: auth,
		HostLinks: func() ([]hostattach.ObservedAttachment, error) { return links, nil }}
}

func TestVPCs(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(scheme(t)).WithObjects(
		attachment("pending", node, "00000000a", false),
		attachment("other-node", "edge-2", "b", false),
		attachment("released", node, "c", true),
		attachment("unallocated", node, "", false),
	).Build()
	g := newGuard(t, c,
		hostattach.ObservedAttachment{ID: hostattach.LinkID("00000000d", "uid"), HostIndex: 7},
		hostattach.ObservedAttachment{ID: "not-an-edge-id", HostIndex: 8},
	)
	got, err := g.VPCs(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if keys := slices.Sorted(maps.Keys(got)); !slices.Equal(keys, []string{"a", "d"}) {
		t.Fatalf("VPCs = %v, want [a d]: this node's unreleased attachments and its stamped links", keys)
	}
}

// TestAllZeroVPCIsOneScope uses an all-zero VPC identifier, padded on one side
// and not on the other: the guard and the write fence treat them as one VPC.
func TestAllZeroVPCIsOneScope(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(scheme(t)).
		WithObjects(attachment("zero", node, "0", false)).Build()
	g := newGuard(t, c)
	got, err := g.VPCs(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := got[strings.TrimPrefix(ownership.VPCScope("000000000"), "vpc-")]; !ok {
		t.Fatalf("VPCs = %v, want the padded all-zero VPC's scope key", got)
	}
	err = g.Reclaim(context.Background(), "000000000", func() error {
		t.Error("reclaim ran for a VPC an attachment uses")
		return nil
	})
	if !errors.Is(err, ErrInUse) {
		t.Fatalf("Reclaim of the padded all-zero VPC = %v, want ErrInUse", err)
	}
}

func TestVPCsWithoutTheCRD(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(scheme(t)).WithInterceptorFuncs(interceptor.Funcs{
		List: func(context.Context, client.WithWatch, client.ObjectList, ...client.ListOption) error {
			return &meta.NoKindMatchError{GroupKind: schema.GroupKind{Group: "galactic.datumapis.com", Kind: "EdgeAttachment"}}
		},
	}).Build()
	got, err := newGuard(t, c).VPCs(context.Background())
	if err != nil || len(got) != 0 {
		t.Fatalf("VPCs without the EdgeAttachment CRD = %v, %v; want none", got, err)
	}
}

// TestUnknownUseReclaimsNothing fails the API read and then the host read:
// either leaves the answer unknown, and nothing is reclaimed.
func TestUnknownUseReclaimsNothing(t *testing.T) {
	denied := fake.NewClientBuilder().WithScheme(scheme(t)).WithInterceptorFuncs(interceptor.Funcs{
		List: func(context.Context, client.WithWatch, client.ObjectList, ...client.ListOption) error {
			return errors.New("forbidden")
		},
	}).Build()
	hostDown := newGuard(t, fake.NewClientBuilder().WithScheme(scheme(t)).Build())
	hostDown.HostLinks = func() ([]hostattach.ObservedAttachment, error) { return nil, errors.New("netlink") }
	for name, g := range map[string]*Guard{"api": newGuard(t, denied), "host": hostDown} {
		if _, err := g.VPCs(context.Background()); err == nil {
			t.Errorf("%s: VPCs succeeded without knowing every user", name)
		}
		err := g.Reclaim(context.Background(), "a", func() error {
			t.Errorf("%s: reclaim ran without knowing every user", name)
			return nil
		})
		if err == nil || errors.Is(err, ErrInUse) {
			t.Errorf("%s: Reclaim = %v, want the read error", name, err)
		}
	}
}

func TestReclaim(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(scheme(t)).
		WithObjects(attachment("a", node, "a", false)).Build()
	g := newGuard(t, c)
	ctx := context.Background()

	// The edge agent owns both scopes and holds a ticket for each.
	tickets := map[string]ownership.Ticket{}
	for _, vpc := range []string{"a", "b"} {
		tk, err := g.Ownership.Claim(ownership.VPCScope(vpc), "galactic-edge/test")
		if err != nil {
			t.Fatal(err)
		}
		tickets[vpc] = tk
	}

	err := g.Reclaim(ctx, "00000000a", func() error {
		t.Error("reclaim ran for a VPC an attachment uses")
		return nil
	})
	if !errors.Is(err, ErrInUse) {
		t.Fatalf("Reclaim of a used VPC = %v, want ErrInUse", err)
	}
	// A refused reclaim wrote nothing: the agent's ticket is still current.
	if _, err := g.Ownership.CommitSnapshot(tickets["a"], func() error { return nil }); err != nil {
		t.Fatalf("agent commit after a refused reclaim = %v", err)
	}

	ran := false
	if err := g.Reclaim(ctx, "b", func() error { ran = true; return nil }); err != nil || !ran {
		t.Fatalf("Reclaim of an unused VPC = %v, ran %t", err, ran)
	}
	// The agent's change prepared before the reclaim is refused.
	if _, err := g.Ownership.CommitSnapshot(tickets["b"], func() error {
		t.Error("stale snapshot ran after a reclaim")
		return nil
	}); !errors.Is(err, ownership.ErrStale) {
		t.Fatalf("agent commit after a reclaim = %v, want ErrStale", err)
	}
	if rec, err := g.Ownership.Read(ownership.VPCScope("b")); err != nil || rec.Owner != "galactic-edge/test" {
		t.Fatalf("scope after reclaim = %+v, %v; want the agent still owning it", rec, err)
	}
}

// TestReclaimDecidesUnderTheFence admits an attachment after garbage
// collection decided its VPC was unused but before the reclaim: the reclaim
// reads again under the fence and keeps the VPC.
func TestReclaimDecidesUnderTheFence(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(scheme(t)).Build()
	g := newGuard(t, c)
	ctx := context.Background()
	if got, err := g.VPCs(ctx); err != nil || len(got) != 0 {
		t.Fatalf("VPCs = %v, %v; want none", got, err)
	}
	if err := c.Create(ctx, attachment("late", node, "a", false)); err != nil {
		t.Fatal(err)
	}
	err := g.Reclaim(ctx, "a", func() error {
		t.Error("reclaim ran for a VPC an attachment started using")
		return nil
	})
	if !errors.Is(err, ErrInUse) {
		t.Fatalf("Reclaim = %v, want ErrInUse", err)
	}
}

// TestReclaimHeldWhileTheAgentCommits holds the agent's commit open: the
// reclaim waits for it, then sees the link it made.
func TestReclaimHeldWhileTheAgentCommits(t *testing.T) {
	var (
		mu    sync.Mutex
		links []hostattach.ObservedAttachment
	)
	g := newGuard(t, fake.NewClientBuilder().WithScheme(scheme(t)).Build())
	g.HostLinks = func() ([]hostattach.ObservedAttachment, error) {
		mu.Lock()
		defer mu.Unlock()
		return links, nil
	}
	tk, err := g.Ownership.Claim(ownership.VPCScope("a"), "galactic-edge/test")
	if err != nil {
		t.Fatal(err)
	}
	inside, release := make(chan struct{}), make(chan struct{})
	committed := make(chan error, 1)
	go func() {
		_, err := g.Ownership.CommitSnapshot(tk, func() error {
			close(inside)
			<-release
			mu.Lock()
			links = []hostattach.ObservedAttachment{{ID: hostattach.LinkID("a", "uid"), HostIndex: 9}}
			mu.Unlock()
			return nil
		})
		committed <- err
	}()
	<-inside
	reclaimed := make(chan error, 1)
	go func() {
		reclaimed <- g.Reclaim(context.Background(), "a", func() error {
			return errors.New("reclaim ran during the agent's commit")
		})
	}()
	time.Sleep(50 * time.Millisecond)
	close(release)
	if err := <-committed; err != nil {
		t.Fatal(err)
	}
	if err := <-reclaimed; !errors.Is(err, ErrInUse) {
		t.Fatalf("Reclaim = %v, want ErrInUse once the agent's link exists", err)
	}
}

func TestUnavailable(t *testing.T) {
	u := Unavailable{Err: errors.New("no fence")}
	if _, err := u.VPCs(context.Background()); err == nil {
		t.Error("VPCs succeeded")
	}
	if err := u.Reclaim(context.Background(), "a", func() error {
		t.Error("reclaim ran")
		return nil
	}); err == nil {
		t.Error("Reclaim succeeded")
	}
}
