// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package authority

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

// recordWrites decides the outcome of each grant record create: nil
// writes it, errLost writes it and still fails, any other error fails
// without writing.
type recordWrites func() error

var errLost = errors.New("reply lost")

func TestConfiguredCellIsolation(t *testing.T) {
	owner, ref := faultyGrants(t, func() error { return nil })
	other := owner
	other.Cell = "other-cell"
	if err := other.ledgers().Init(t.Context(), ref, other.Cell,
		netip.MustParsePrefix("fd20:a1b:2c3d:10:3::/80"), netip.MustParsePrefix("fd20:a1b:2c3d:10:4::/80")); err != nil {
		t.Fatal(err)
	}
	issued, err := owner.Create(t.Context(), CreateRequest{VPC: ref, Lifetime: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	sibling, err := other.Create(t.Context(), CreateRequest{VPC: ref, Lifetime: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	for _, configured := range []string{"", other.Cell} {
		foreign := owner
		foreign.Cell = configured
		if _, err := foreign.Rotate(t.Context(), issued.Connector, time.Hour); err == nil {
			t.Fatal("foreign/empty cell rotated grant")
		}
		if err := foreign.Disable(t.Context(), issued.Connector); err == nil {
			t.Fatal("foreign/empty cell disabled grant")
		}
		if err := foreign.Retire(t.Context(), issued.Connector); err == nil {
			t.Fatal("foreign/empty cell retired grant")
		}
	}
	empty := owner
	empty.Cell = ""
	if _, err := empty.Create(t.Context(), CreateRequest{VPC: ref, Lifetime: time.Hour}); err == nil {
		t.Fatal("empty cell minted grant")
	}
	if rotated, err := owner.Rotate(t.Context(), issued.Connector, time.Hour); err != nil || rotated.Revision != 2 {
		t.Fatalf("foreign attempts changed grant: %+v %v", rotated, err)
	}
	if err := owner.Retire(t.Context(), issued.Connector); err != nil {
		t.Fatal(err)
	}
	if _, err := other.Rotate(t.Context(), sibling.Connector, time.Hour); err != nil {
		t.Fatalf("sibling cell disrupted: %v", err)
	}
}

func TestConfiguredCellUnrecordedRetirement(t *testing.T) {
	owner, ref := faultyGrants(t, failOnce())
	if _, err := owner.Create(t.Context(), CreateRequest{VPC: ref, Lifetime: time.Hour}); err == nil {
		t.Fatal("expected record write failure")
	}
	allocation := owner.entries(t)[0]
	other := owner
	other.Cell = "other-cell"
	if err := other.Retire(t.Context(), allocation.Connector); err == nil {
		t.Fatal("foreign cell retired unrecorded allocation")
	}
	if owner.entries(t)[0] != allocation {
		t.Fatal("foreign cell mutated allocation")
	}
	if err := owner.Retire(t.Context(), allocation.Connector); err != nil {
		t.Fatal(err)
	}
}

// faultyGrants returns Grants over a fake API holding one VPC and its
// ledger, whose grant record creates go through writes.
func faultyGrants(t *testing.T, writes recordWrites) (Grants, VPCRef) {
	t.Helper()
	vpc := testVPC()
	c := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(vpc).WithInterceptorFuncs(interceptor.Funcs{
		Create: func(ctx context.Context, c client.WithWatch, o client.Object, opts ...client.CreateOption) error {
			if _, ok := o.(*corev1.Secret); !ok {
				return c.Create(ctx, o, opts...)
			}
			switch err := writes(); {
			case err == nil:
				return c.Create(ctx, o, opts...)
			case errors.Is(err, errLost):
				if cerr := c.Create(ctx, o, opts...); cerr != nil {
					return cerr
				}
				return err
			default:
				return err
			}
		},
	}).Build()
	g := Grants{Client: c, Namespace: testNS, Cell: testCell, Now: time.Now}
	ref := VPCRef{Namespace: tenantNS, Name: vpcName, UID: string(vpc.UID)}
	if err := g.ledgers().Init(context.Background(), ref, testCell, testConnectors, testPools); err != nil {
		t.Fatal(err)
	}
	return g, VPCRef{Namespace: tenantNS, Name: vpcName}
}

// entries returns the test VPC's ledger entries.
func (g Grants) entries(t *testing.T) []Entry {
	t.Helper()
	l, _, err := g.ledgers().Read(context.Background(), string(testVPC().UID), testCell)
	if err != nil {
		t.Fatal(err)
	}
	return l.Entries
}

// failOnce fails the first record write without writing it.
func failOnce() recordWrites {
	n := 0
	return func() error {
		if n++; n == 1 {
			return errors.New("injected")
		}
		return nil
	}
}

// TestCreateRetryKeepsAllocation: a record write that fails leaves the
// connector's /96 allocated, and creating the same connector again uses
// that /96 rather than another.
func TestCreateRetryKeepsAllocation(t *testing.T) {
	g, ref := faultyGrants(t, failOnce())
	ctx := context.Background()
	_, err := g.Create(ctx, CreateRequest{VPC: ref, Lifetime: time.Hour})
	if err == nil {
		t.Fatal("create with a failed record write succeeded")
	}
	e := g.entries(t)
	if len(e) != 1 || !strings.Contains(err.Error(), e[0].Connector) ||
		!strings.Contains(err.Error(), e[0].Prefix.String()) {
		t.Fatalf("failed create = %v with entries %+v; want an error naming the one connector and its /96", err, e)
	}
	issued, err := g.Create(ctx, CreateRequest{VPC: ref, Connector: e[0].Connector, Lifetime: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if issued.Prefix != e[0].Prefix || len(g.entries(t)) != 1 {
		t.Fatalf("retry got %s with %d entries; want %s and one entry", issued.Prefix, len(g.entries(t)),
			e[0].Prefix)
	}
}

// TestCreateLostReply: a record written whose reply was lost is refused on
// retry, and rotating it issues a credential for the same /96.
func TestCreateLostReply(t *testing.T) {
	n := 0
	g, ref := faultyGrants(t, func() error {
		if n++; n == 1 {
			return errLost
		}
		return nil
	})
	ctx := context.Background()
	if _, err := g.Create(ctx, CreateRequest{VPC: ref, Lifetime: time.Hour}); !errors.Is(err, errLost) {
		t.Fatalf("create with a lost reply = %v", err)
	}
	e := g.entries(t)
	_, err := g.Create(ctx, CreateRequest{VPC: ref, Connector: e[0].Connector, Lifetime: time.Hour})
	if !apierrors.IsAlreadyExists(err) || !strings.Contains(err.Error(), "rotate") {
		t.Fatalf("retry after a lost reply = %v; want AlreadyExists pointing at rotate", err)
	}
	issued, err := g.Rotate(ctx, e[0].Connector, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if issued.Prefix != e[0].Prefix || issued.Credential == "" || len(g.entries(t)) != 1 {
		t.Fatalf("rotate after a lost reply = %+v with %d entries; want %s", issued, len(g.entries(t)), e[0].Prefix)
	}
}

// TestRetireUnrecorded: a connector whose record was never written can be
// retired, which tombstones its /96 so no connector gets it again.
func TestRetireUnrecorded(t *testing.T) {
	g, ref := faultyGrants(t, failOnce())
	ctx := context.Background()
	if _, err := g.Create(ctx, CreateRequest{VPC: ref, Lifetime: time.Hour}); err == nil {
		t.Fatal("create with a failed record write succeeded")
	}
	stranded := g.entries(t)[0]
	if err := g.Retire(ctx, stranded.Connector); err != nil {
		t.Fatalf("retire a connector without a record: %v", err)
	}
	if e := g.entries(t); len(e) != 1 || !e[0].Retired {
		t.Fatalf("entries after retire %+v; want one tombstone", e)
	}
	if _, err := g.Create(ctx, CreateRequest{VPC: ref, Connector: stranded.Connector,
		Lifetime: time.Hour}); err == nil {
		t.Fatal("a retired connector was created again")
	}
	issued, err := g.Create(ctx, CreateRequest{VPC: ref, Lifetime: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if issued.Prefix == stranded.Prefix {
		t.Fatalf("new connector got the retired %s", stranded.Prefix)
	}
	err = g.Retire(ctx, "33333333-3333-3333-3333-333333333333")
	if !apierrors.IsNotFound(err) {
		t.Fatalf("retire an unknown connector = %v, want NotFound", err)
	}
}
