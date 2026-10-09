// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	cloudv1alpha1 "go.datum.net/cloud/api/v1alpha1"
	"go.datum.net/galactic/internal/plumbing/srv6"
	bgpv1alpha1 "go.datum.net/network/api/v1alpha1"
)

// collidingAddrs returns two addresses in fd00:10::/64 whose srv6.BackendSlot
// on port is equal, found by search: a 16-bit slot space makes one turn up
// within a few hundred candidates.
func collidingAddrs(t *testing.T, port uint16) (netip.Addr, netip.Addr) {
	t.Helper()
	seen := make(map[uint16]netip.Addr)
	for i := 1; i < 1<<20; i++ {
		addr := netip.MustParseAddr(fmt.Sprintf("fd00:10::%x:%x", i>>16, i&0xffff))
		slot := srv6.BackendSlot(addr, port)
		if first, ok := seen[slot]; ok {
			return first, addr
		}
		seen[slot] = addr
	}
	t.Fatal("no two addresses share a slot")
	return netip.Addr{}, netip.Addr{}
}

func TestDropConflictingBackends(t *testing.T) {
	const port = 8443
	att := func(name string) types.NamespacedName { return types.NamespacedName{Namespace: "tenant", Name: name} }
	a, b := collidingAddrs(t, port)
	other := netip.MustParseAddr("fd00:10::ffff:1")

	backends := []ruleBackend{
		{attachment: att("first"), node: testNAT66NodeA, addr: a, port: port},
		{attachment: att("dup"), node: testNAT66NodeB, addr: a, port: port},
		{attachment: att("slot"), node: testNAT66NodeA, addr: b, port: port},
		{attachment: att("slot-elsewhere"), node: testNAT66NodeB, addr: b, port: port},
		{attachment: att("plain"), node: testNAT66NodeA, addr: other, port: port},
	}
	// The slot entry is dropped for its slot on node-a, so it claims no
	// address, and slot-elsewhere, the same address on node-b where the slot
	// is free, is kept.

	kept, rejected := dropConflictingBackends(backends)

	keptNames := make([]string, 0, len(kept))
	for _, k := range kept {
		keptNames = append(keptNames, k.attachment.Name)
	}
	if strings.Join(keptNames, ",") != "first,slot-elsewhere,plain" {
		t.Errorf("kept = %v, want [first slot-elsewhere plain]", keptNames)
	}
	if len(rejected) != 2 {
		t.Fatalf("rejected = %v, want 2 entries", rejected)
	}
	if !strings.Contains(rejected[0], "tenant/dup: address") {
		t.Errorf("rejected[0] = %q, want the duplicate address", rejected[0])
	}
	if !strings.Contains(rejected[1], "tenant/slot: backend") || !strings.Contains(rejected[1], "shares slot") {
		t.Errorf("rejected[1] = %q, want the slot collision on the first node", rejected[1])
	}
}

// TestDropConflictingBackends_SlotOnOtherNode covers two backends whose slots
// match on different nodes: each node keys its own rows, so both are kept.
func TestDropConflictingBackends_SlotOnOtherNode(t *testing.T) {
	const port = 8443
	a, b := collidingAddrs(t, port)
	kept, rejected := dropConflictingBackends([]ruleBackend{
		{attachment: types.NamespacedName{Name: "a"}, node: testNAT66NodeA, addr: a, port: port},
		{attachment: types.NamespacedName{Name: "b"}, node: testNAT66NodeB, addr: b, port: port},
	})
	if len(kept) != 2 || len(rejected) != 0 {
		t.Errorf("kept = %d, rejected = %v, want both kept", len(kept), rejected)
	}
}

// TestSelectRuleBackends_DropsConflictingBackends covers the selection both
// the gateway and the binding writer use: an attachment repeating another's
// address, and one whose backend shares a slot with another on its node, are
// left out and reported as pending, so neither side plans flows or bindings
// for them.
func TestSelectRuleBackends_DropsConflictingBackends(t *testing.T) {
	rule := newTestRule(testRuleName, testVPCRef, testVIP)
	a, b := collidingAddrs(t, testBackendPort)

	first := newBackendAttachment(testVPCRef, a.String())
	first.Name = "first"
	dup := newBackendAttachment(testVPCRef, a.String())
	dup.Name = "dup"
	slot := newBackendAttachment(testVPCRef, b.String())
	slot.Name = "slot"

	sel, err := selectRuleBackends(rule, []*cloudv1alpha1.VPCAttachment{slot, dup, first}, nil)
	if err != nil {
		t.Fatalf("selectRuleBackends: %v", err)
	}
	backends, pending := sel.backends, sel.pending
	if len(backends) != 1 || backends[0].addr != a || backends[0].attachment.Name != "dup" {
		t.Errorf("backends = %+v, want only %s from the first attachment by name", backends, a)
	}
	joined := strings.Join(pending, "\n")
	if !strings.Contains(joined, "/first: address") || !strings.Contains(joined, "/slot: backend") {
		t.Errorf("pending = %v, want the repeated address and the slot collision reported", pending)
	}
}

// newSharingRule returns a rule named name with the IPv6 VIP vip, created at
// second created, selecting newBackendAttachment's attachments in testVPCRef.
func newSharingRule(name, vip string, created int64) *bgpv1alpha1.NetworkRule {
	rule := newTestRule(name, testVPCRef, vip)
	rule.CreationTimestamp = metav1.NewTime(time.Unix(created, 0))
	return rule
}

// TestRuleBackendOwners covers which rule owns a backend that several rules
// select: the oldest one using the backend on the same backend port and
// protocol, and only a rule its backend nodes would write bindings for.
func TestRuleBackendOwners(t *testing.T) {
	const (
		olderVIP = "2001:db8:100::32"
		newerVIP = "2001:db8:100::33"
	)
	tests := []struct {
		name string
		// change edits the older rule "a", then the newer rule "b".
		changeA, changeB func(*bgpv1alpha1.NetworkRule)
		wantOwner        string
		wantBClaimed     bool
	}{
		{
			name:         "older rule wins a shared backend",
			wantOwner:    "a",
			wantBClaimed: true,
		},
		{
			name:         "creation time decides before name",
			changeA:      func(r *bgpv1alpha1.NetworkRule) { r.CreationTimestamp = metav1.NewTime(time.Unix(300, 0)) },
			wantOwner:    "b",
			wantBClaimed: false,
		},
		{
			name:         "a creation time tie falls to the name",
			changeB:      func(r *bgpv1alpha1.NetworkRule) { r.CreationTimestamp = metav1.NewTime(time.Unix(100, 0)) },
			wantOwner:    "a",
			wantBClaimed: true,
		},
		{
			name:      "different backend ports do not collide",
			changeB:   func(r *bgpv1alpha1.NetworkRule) { r.Spec.BackendPort = testBackendPort + 1 },
			wantOwner: "a",
		},
		{
			name:      "different protocols do not collide",
			changeB:   func(r *bgpv1alpha1.NetworkRule) { r.Spec.Protocol = bgpv1alpha1.NetworkRuleProtocolUDP },
			wantOwner: "a",
		},
		{
			name: "a rule with two IPv6 VIPs claims nothing",
			changeA: func(r *bgpv1alpha1.NetworkRule) {
				r.Spec.VIPAddresses = append(r.Spec.VIPAddresses, "2001:db8:100::34")
			},
			wantOwner: "b",
		},
		{
			name:      "a rule with no IPv6 VIP claims nothing",
			changeA:   func(r *bgpv1alpha1.NetworkRule) { r.Spec.VIPAddresses = []string{testVIP} },
			wantOwner: "b",
		},
		{
			name: "a rule being deleted keeps its claim",
			changeA: func(r *bgpv1alpha1.NetworkRule) {
				now := metav1.NewTime(time.Unix(400, 0))
				r.DeletionTimestamp = &now
			},
			wantOwner:    "a",
			wantBClaimed: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := newSharingRule("a", olderVIP, 100)
			b := newSharingRule("b", newerVIP, 200)
			if tt.changeA != nil {
				tt.changeA(a)
			}
			if tt.changeB != nil {
				tt.changeB(b)
			}
			attachments := []*cloudv1alpha1.VPCAttachment{newBackendAttachment(testVPCRef)}
			// The list order must not matter: the newer rule comes first.
			owners := ruleBackendOwners([]bgpv1alpha1.NetworkRule{*b, *a}, attachments)

			owner := owners[backendClaimFor(a, ruleBackend{
				addr: netip.MustParseAddr(testBackendAddr), port: testBackendPort,
			})]
			if owner.Name != tt.wantOwner {
				t.Errorf("owner of rule a's backend = %q, want %q", owner.Name, tt.wantOwner)
			}

			selB, err := selectRuleBackends(b, attachments, owners)
			if err != nil {
				t.Fatalf("selectRuleBackends(b): %v", err)
			}
			if gotClaimed := len(selB.claimed) == 1; gotClaimed != tt.wantBClaimed {
				t.Fatalf("rule b claimed = %+v, want claimed %v", selB.claimed, tt.wantBClaimed)
			}
			if tt.wantBClaimed {
				if len(selB.backends) != 0 {
					t.Errorf("rule b backends = %+v, want none", selB.backends)
				}
				msg := selB.claimed[0].String()
				if !strings.Contains(msg, "[fd00:10::1]:8443") || !strings.Contains(msg, "NetworkRule ns/a") {
					t.Errorf("claimed message = %q, want it to name the backend and NetworkRule ns/a", msg)
				}
			} else if len(selB.backends) != 1 {
				t.Errorf("rule b backends = %+v, want its one backend", selB.backends)
			}

			selA, err := selectRuleBackends(a, attachments, owners)
			if err != nil {
				t.Fatalf("selectRuleBackends(a): %v", err)
			}
			if tt.wantOwner == "a" && (len(selA.backends) != 1 || len(selA.claimed) != 0) {
				t.Errorf("rule a selection = %+v, want it to keep its backend", selA)
			}
		})
	}
}

// TestAttachmentsByVPC_SelectSameBackends covers both ways a rule's candidate
// attachments are narrowed to its VPC: galactic-router's indexed list
// (listVPCAttachmentsInVPC) and the gateway's grouping of one full list
// (groupAttachmentsByVPC). For every rule, each must select exactly the
// backends and pending attachments the unfiltered list does.
func TestAttachmentsByVPC_SelectSameBackends(t *testing.T) {
	inBlue := newBackendAttachment("vpc-blue", "fd00:10::1")
	alsoBlue := newBackendAttachment("vpc-blue", "fd00:10::2")
	alsoBlue.Name = "also-blue"
	alsoBlue.Status.Node = ""
	inGreen := newBackendAttachment("vpc-green", "fd00:20::1")
	unobserved := newBackendAttachment("vpc-blue", "fd00:10::3")
	unobserved.Name = "unobserved"
	unobserved.Status.VPC = ""

	scheme := newRuleTestScheme(t)
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithIndex(&cloudv1alpha1.VPCAttachment{}, VPCAttachmentByVPC, vpcAttachmentVPC).
		WithObjects(inBlue, alsoBlue, inGreen, unobserved).
		Build()
	ctx := context.Background()

	all, err := listVPCAttachments(ctx, c)
	if err != nil {
		t.Fatalf("listVPCAttachments: %v", err)
	}
	if len(all) != 4 {
		t.Fatalf("full list = %d attachments, want 4", len(all))
	}
	byVPC := groupAttachmentsByVPC(all)

	for _, vpc := range []string{"vpc-blue", "vpc-green", "vpc-empty"} {
		t.Run(vpc, func(t *testing.T) {
			rule := newTestRule(testRuleName, vpc, testVIP)
			want, err := selectRuleBackends(rule, all, nil)
			if err != nil {
				t.Fatalf("selectRuleBackends over the full list: %v", err)
			}

			indexed, err := listVPCAttachmentsInVPC(ctx, c, vpc)
			if err != nil {
				t.Fatalf("listVPCAttachmentsInVPC: %v", err)
			}
			for _, a := range indexed {
				if a.Status.VPC != vpc {
					t.Errorf("indexed list for %s holds %s/%s in VPC %q", vpc, a.Namespace, a.Name, a.Status.VPC)
				}
			}

			for name, candidates := range map[string][]*cloudv1alpha1.VPCAttachment{
				"indexed list": indexed,
				"grouped list": byVPC[vpc],
			} {
				got, err := selectRuleBackends(rule, candidates, nil)
				if err != nil {
					t.Fatalf("selectRuleBackends over the %s: %v", name, err)
				}
				if !slices.Equal(got.backends, want.backends) || !slices.Equal(got.pending, want.pending) {
					t.Errorf("%s selects backends %v, pending %v; full list selects %v, pending %v",
						name, got.backends, got.pending, want.backends, want.pending)
				}
			}
		})
	}
}

// TestListVPCAttachmentsInVPC_RequiresIndex covers the index being part of
// the contract: a client without it fails the list rather than silently
// returning every attachment or none.
func TestListVPCAttachmentsInVPC_RequiresIndex(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(newRuleTestScheme(t)).
		WithObjects(newBackendAttachment(testVPCRef)).Build()
	if _, err := listVPCAttachmentsInVPC(context.Background(), c, testVPCRef); err == nil {
		t.Fatal("listVPCAttachmentsInVPC without the index: err = nil, want an error")
	}
}
