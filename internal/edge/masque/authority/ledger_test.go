// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package authority

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"sync"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	cloudv1alpha1 "go.datum.net/galactic/api/cloud/v1alpha1"
	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
)

const (
	testNS   = "masque-system"
	tenantNS = "tenant"
	testCell = "cell-1"
	vpcName  = "vpc"
	cell2    = "cell-2"
)

var (
	testConnectors = netip.MustParsePrefix("fd20:a1b:2c3d:10:1::/80")
	testPools      = netip.MustParsePrefix("fd20:a1b:2c3d:10:2::/80")
)

func testScheme() *runtime.Scheme {
	s := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(s))
	utilruntime.Must(galacticv1alpha1.AddToScheme(s))
	utilruntime.Must(cloudv1alpha1.AddToScheme(s))
	return s
}

// testVPC returns the VPC the ledgers under test belong to.
func testVPC() *cloudv1alpha1.VPC {
	return &cloudv1alpha1.VPC{
		ObjectMeta: metav1.ObjectMeta{Namespace: tenantNS, Name: vpcName, UID: "11111111-1111-1111-1111-111111111111"},
		Spec:       cloudv1alpha1.VPCSpec{Networks: []cloudv1alpha1.Network{"fd20:a1b:2c3d::/48"}},
	}
}

func fakeLedgers(t *testing.T) (Ledgers, VPCRef) {
	t.Helper()
	vpc := testVPC()
	c := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(vpc).Build()
	l := Ledgers{Client: c, Namespace: testNS, Now: time.Now}
	ref := VPCRef{Namespace: tenantNS, Name: vpcName, UID: string(vpc.UID)}
	if err := l.Init(context.Background(), ref, testCell, testConnectors, testPools); err != nil {
		t.Fatal(err)
	}
	return l, ref
}

func TestLedgerInitValidates(t *testing.T) {
	l, ref := fakeLedgers(t)
	ctx := context.Background()
	other := VPCRef{Namespace: tenantNS, Name: vpcName, UID: "22222222-2222-2222-2222-222222222222"}
	for name, tc := range map[string]struct {
		vpc               VPCRef
		cell              string
		connectors, pools netip.Prefix
	}{
		"exists":      {ref, testCell, testConnectors, testPools},
		"wrong UID":   {other, cell2, testConnectors, testPools},
		"not a /80":   {ref, cell2, netip.MustParsePrefix("fd20:a1b:2c3d:10:1::/96"), testPools},
		"unmasked":    {ref, cell2, netip.MustParsePrefix("fd20:a1b:2c3d:10:1:1::/80"), testPools},
		"outside VPC": {ref, cell2, netip.MustParsePrefix("fd99::/80"), testPools},
		"overlapping": {ref, cell2, testConnectors, testConnectors},
		"bad cell":    {ref, "Cell_2", testConnectors, testPools},
		"IPv4":        {ref, cell2, netip.MustParsePrefix("10.0.0.0/8"), testPools},
	} {
		if err := l.Init(ctx, tc.vpc, tc.cell, tc.connectors, tc.pools); err == nil {
			t.Errorf("%s: Init succeeded, want an error", name)
		}
	}
}

func TestLedgerInitAcrossCells(t *testing.T) {
	l, ref := fakeLedgers(t)
	ctx := context.Background()
	c2 := netip.MustParsePrefix("fd20:a1b:2c3d:20:1::/80")
	p2 := netip.MustParsePrefix("fd20:a1b:2c3d:20:2::/80")
	if err := l.Init(ctx, ref, cell2, testConnectors, p2); err == nil {
		t.Error("a second cell sharing a connector range was accepted")
	}
	if err := l.Init(ctx, ref, cell2, c2, testPools); err == nil {
		t.Error("a second cell sharing a pool range was accepted")
	}
	if err := l.Init(ctx, ref, cell2, p2, c2); err != nil {
		t.Fatalf("a second cell with disjoint ranges: %v", err)
	}
	if err := l.Init(ctx, ref, "cell-3", c2, p2); err == nil {
		t.Error("a third cell reusing the second cell's ranges was accepted")
	}
}

func TestLedgerAllocates(t *testing.T) {
	l, ref := fakeLedgers(t)
	ctx := context.Background()
	a, err := l.Allocate(ctx, ref.UID, testCell, "a")
	if err != nil {
		t.Fatal(err)
	}
	if a.Prefix != netip.MustParsePrefix("fd20:a1b:2c3d:10:1:1::/96") ||
		a.Pool != netip.MustParsePrefix("fd20:a1b:2c3d:10:2::100/120") || a.Allocation == "" {
		t.Fatalf("first allocation %+v", a)
	}
	again, err := l.Allocate(ctx, ref.UID, testCell, "a")
	if err != nil || again != a {
		t.Fatalf("allocating again = %+v, %v; want the same %+v", again, err, a)
	}
	if err := l.Retire(ctx, ref.UID, testCell, "a"); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Allocate(ctx, ref.UID, testCell, "a"); err == nil {
		t.Fatal("allocating a retired connector succeeded")
	}
	b, err := l.Allocate(ctx, ref.UID, testCell, "b")
	if err != nil {
		t.Fatal(err)
	}
	if b.Prefix == a.Prefix || b.Pool == a.Pool || b.Prefix != netip.MustParsePrefix("fd20:a1b:2c3d:10:1:2::/96") {
		t.Fatalf("allocation after a tombstone %+v reuses or skips %+v", b, a)
	}
	if _, err := l.Allocate(ctx, ref.UID, "cell-9", "c"); !errors.Is(err, ErrLedgerMissing) {
		t.Fatalf("allocating without a ledger = %v, want %v", err, ErrLedgerMissing)
	}
}

func TestLedgerFull(t *testing.T) {
	l, ref := fakeLedgers(t)
	ctx := context.Background()
	for i := range MaxEntries {
		if _, err := l.Allocate(ctx, ref.UID, testCell, strconv.Itoa(i)); err != nil {
			t.Fatalf("allocation %d: %v", i, err)
		}
	}
	if _, err := l.Allocate(ctx, ref.UID, testCell, "one-more"); err == nil {
		t.Fatal("allocating past MaxEntries succeeded")
	}
}

// TestLedgerConcurrentAllocations: concurrent writers conflict on the
// resourceVersion and retry from a fresh read, so no two connectors share a
// /96 or pool.
func TestLedgerConcurrentAllocations(t *testing.T) {
	l, ref := fakeLedgers(t)
	ctx := context.Background()
	const n = 8
	var wg sync.WaitGroup
	got := make([]Entry, n)
	errs := make([]error, n)
	for i := range n {
		wg.Go(func() { got[i], errs[i] = l.Allocate(ctx, ref.UID, testCell, fmt.Sprint("c", i)) })
	}
	wg.Wait()
	prefixes, pools := map[netip.Prefix]bool{}, map[netip.Prefix]bool{}
	for i := range n {
		if errs[i] != nil {
			// A writer can lose every retry; it must not have
			// allocated.
			continue
		}
		if prefixes[got[i].Prefix] || pools[got[i].Pool] {
			t.Fatalf("allocation %+v duplicates another", got[i])
		}
		prefixes[got[i].Prefix], pools[got[i].Pool] = true, true
	}
	lg, _, err := l.Read(ctx, ref.UID, testCell)
	if err != nil {
		t.Fatal(err)
	}
	if len(lg.Entries) != len(prefixes) {
		t.Fatalf("ledger holds %d entries, %d allocations succeeded", len(lg.Entries), len(prefixes))
	}
}

func TestWithIndex(t *testing.T) {
	base := netip.MustParseAddr("fd00::ffff:ffff:ff00")
	if got := withIndex(base, 0x100); got != netip.MustParseAddr("fd00::1:0:0:0") {
		t.Fatalf("withIndex carries to %s", got)
	}
}

func TestRecordRoutesBounded(t *testing.T) {
	r := Record{Connector: "6f1c0a3e-8f43-4f6e-9a55-1f6f1f0b5c2d", Cell: testCell, Revision: 1,
		VPC: VPCRef{Namespace: tenantNS, Name: vpcName, UID: "u"}, Digest: Digest(NewCredential()),
		Expires: time.Now().Add(time.Hour)}
	for i := range MaxRoutes + 1 {
		r.Routes = append(r.Routes, netip.PrefixFrom(withIndex(netip.MustParseAddr("fd00::"), uint64(i)<<16), 112))
	}
	if err := r.validate(); err == nil {
		t.Fatalf("a record with %d routes validated", len(r.Routes))
	}
	r.Routes = r.Routes[:MaxRoutes]
	if err := r.validate(); err != nil {
		t.Fatalf("a record with %d routes: %v", MaxRoutes, err)
	}
}
