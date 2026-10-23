// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package route

import (
	"context"
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"

	cloudv1alpha1 "go.datum.net/galactic/api/cloud/v1alpha1"
	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
)

// TestSubnetConflict is failure-matrix rows 7a and 7c's control-plane half:
// a route overlapping a workload subnet of the VPC is refused, and a subnet
// created over an accepted route revokes it.
func TestSubnetConflict(t *testing.T) {
	f := startAPI(t)
	a := f.newHolder("a", nodeA, "fd00:10:0:e::1")
	f.newRoute("r", prefixA)
	f.claim("r", a)
	f.clearRebuilt()
	f.expectAccepted("r", a, 1)

	f.subnet("wl", "fd00:10:0:f:5::/80")
	f.newRoute("s", "fd00:10:0:f:5::/96")
	f.claim("s", a)
	f.reconcile("s")
	if got := f.claimReason("s"); got != ReasonPrefixConflict {
		t.Fatalf("route inside a workload subnet: %s", got)
	}

	// A subnet of another VPC in the namespace does not conflict.
	other := &cloudv1alpha1.VPC{
		ObjectMeta: metav1.ObjectMeta{Name: "second", Namespace: tenantNS},
		Spec:       cloudv1alpha1.VPCSpec{Networks: []cloudv1alpha1.Network{"fd00:10::/48"}},
	}
	f.create(other)
	f.subnetIn("second", "elsewhere", "fd00:10:0:f::/96")
	f.reconcile("r")
	f.expectAccepted("r", a, 1)

	f.subnet("late", "fd00:10:0:f::/96")
	f.reconcile("r")
	rt := f.route("r")
	c := meta.FindStatusCondition(rt.Status.Conditions, galacticv1alpha1.EdgeRouteAccepted)
	if c.Status != metav1.ConditionFalse || c.Reason != ReasonRevoked ||
		!strings.Contains(c.Message, ReasonPrefixConflict) {
		t.Fatalf("route under a later subnet: %s", conditions(rt))
	}
	if e := f.indexEntries(); len(e) != 1 || e[0].Removing != RemovingRevoked {
		t.Fatalf("index after the subnet revoked the route %+v", e)
	}
}

// TestPoolAndGrantConflict: a route may cover part of its own service's
// client pool, a delegated client prefix, but never another attachment's
// address there, another service's client pool, or anything when an earlier
// service's grant overlaps its own.
func TestPoolAndGrantConflict(t *testing.T) {
	f := startAPI(t)
	ctx := context.Background()
	a := f.newHolder("a", nodeA, "fd00:10:0:e::1")
	b := f.newHolder("b", nodeB, "fd00:10:0:e::90")
	f.update(f.svc, func(s *galacticv1alpha1.EdgeService) {
		s.Spec.Prefixes = []string{grantPrefix, "fd00:10:0:e::/120"}
	})
	if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var s galacticv1alpha1.EdgeService
		if err := f.admin.Get(ctx, client.ObjectKeyFromObject(f.svc), &s); err != nil {
			return err
		}
		s.Status.Allocations = []galacticv1alpha1.EdgeAllocation{
			{Address: "fd00:10:0:e::1", Attachment: providerNS + "/" + a.att.Name, AttachmentUID: string(a.att.UID)},
			{Address: "fd00:10:0:e::90", Attachment: providerNS + "/" + b.att.Name, AttachmentUID: string(b.att.UID)},
		}
		return f.admin.Status().Update(ctx, &s)
	}); err != nil {
		t.Fatal(err)
	}

	f.newRoute("d", "fd00:10:0:e::40/122")
	f.claim("d", a)
	f.reconcile("d")
	f.clock.advance(params.TakeoverWait())
	f.reconcile("d")
	f.expectAccepted("d", a, 1)

	f.newRoute("x", "fd00:10:0:e::80/121")
	f.claim("x", a)
	f.reconcile("x")
	if got := f.claimReason("x"); got != ReasonPrefixConflict {
		t.Fatalf("route over another attachment's address: %s", got)
	}

	// A later service's pool inside this service's grant.
	f.laterService("pooled", func(s *galacticv1alpha1.EdgeService) { s.Spec.ClientPool = "fd00:10:0:f:9::/120" })
	f.newRoute("p", "fd00:10:0:f:9::/112")
	f.claim("p", a)
	f.reconcile("p")
	if got := f.claimReason("p"); got != ReasonPrefixConflict {
		t.Fatalf("route over another service's client pool: %s", got)
	}

	// A later service granted a prefix inside this service's grant routes
	// nothing; this service's routes are untouched.
	late := f.laterService("late", func(s *galacticv1alpha1.EdgeService) {
		s.Spec.Prefixes = []string{"fd00:10:0:f:a::/80"}
		s.Spec.ClientPool = "fd00:10:0:d::/120"
	})
	c := f.newHolderIn(late, "c", nodeA, "fd00:10:0:d::1")
	f.newRoute("g", "fd00:10:0:f:a::/96")
	f.claim("g", c)
	f.reconcile("g")
	if got := f.claimReason("g"); got != ReasonPrefixConflict {
		t.Fatalf("route under a later overlapping grant: %s", got)
	}
	f.reconcile("d")
	f.expectAccepted("d", a, 1)
}

// subnet creates a workload attachment of the fixture's VPC with podSubnet.
func (f *fixture) subnet(name, podSubnet string) {
	f.t.Helper()
	f.subnetIn(f.vpc.Name, name, podSubnet)
}

func (f *fixture) subnetIn(vpc, name, podSubnet string) {
	f.t.Helper()
	va := &cloudv1alpha1.VPCAttachment{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: tenantNS},
		Spec: cloudv1alpha1.VPCAttachmentSpec{VPC: cloudv1alpha1.VPCRef{Name: vpc},
			Interface: cloudv1alpha1.VPCAttachmentInterface{Name: "eth0"}},
	}
	f.create(va)
	va.Status.PodSubnet = podSubnet
	if err := f.admin.Status().Update(context.Background(), va); err != nil {
		f.t.Fatal(err)
	}
}

// laterService creates a service granting the fixture's VPC to the provider,
// created after every existing service: creation time has one-second
// resolution.
func (f *fixture) laterService(name string, mutate func(*galacticv1alpha1.EdgeService),
) *galacticv1alpha1.EdgeService {
	f.t.Helper()
	time.Sleep(time.Until(time.Now().Truncate(time.Second).Add(time.Second)))
	s := &galacticv1alpha1.EdgeService{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: tenantNS},
		Spec: galacticv1alpha1.EdgeServiceSpec{
			ProviderRef:  galacticv1alpha1.EdgeProviderReference{Name: providerName},
			VPCRef:       galacticv1alpha1.EdgeVPCReference{Name: f.vpc.Name, UID: string(f.vpc.UID)},
			Capabilities: []string{socketAccess, PrefixReachability},
		},
	}
	mutate(s)
	f.create(s)
	return s
}

func (f *fixture) update(svc *galacticv1alpha1.EdgeService, mutate func(*galacticv1alpha1.EdgeService)) {
	f.t.Helper()
	ctx := context.Background()
	if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var s galacticv1alpha1.EdgeService
		if err := f.admin.Get(ctx, client.ObjectKeyFromObject(svc), &s); err != nil {
			return err
		}
		mutate(&s)
		return f.admin.Update(ctx, &s)
	}); err != nil {
		f.t.Fatal(err)
	}
}
