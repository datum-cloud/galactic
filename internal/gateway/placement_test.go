// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gateway

import (
	"errors"
	"testing"
)

// Shared fixture identifiers reused across this package's test files.
const (
	testNodeA = "gw-a"
	testNodeB = "gw-b"
)

func TestAssignPrimaryNode_NoNodes(t *testing.T) {
	if _, err := AssignPrimaryNode("vpc-1", nil); !errors.Is(err, ErrNoGatewayNodes) {
		t.Fatalf("AssignPrimaryNode with no nodes: got err %v, want ErrNoGatewayNodes", err)
	}
	if _, err := AssignPrimaryNode("vpc-1", []string{}); !errors.Is(err, ErrNoGatewayNodes) {
		t.Fatalf("AssignPrimaryNode with empty slice: got err %v, want ErrNoGatewayNodes", err)
	}
}

func TestAssignPrimaryNode_Deterministic(t *testing.T) {
	nodes := []string{testNodeA, testNodeB}
	first, err := AssignPrimaryNode("vpc-123", nodes)
	if err != nil {
		t.Fatalf("AssignPrimaryNode: unexpected error: %v", err)
	}
	for range 100 {
		got, err := AssignPrimaryNode("vpc-123", nodes)
		if err != nil {
			t.Fatalf("AssignPrimaryNode: unexpected error: %v", err)
		}
		if got != first {
			t.Fatalf("AssignPrimaryNode not deterministic: got %q, want %q", got, first)
		}
	}
}

func TestAssignPrimaryNode_OrderIndependent(t *testing.T) {
	got1, err := AssignPrimaryNode("vpc-abc", []string{testNodeA, testNodeB})
	if err != nil {
		t.Fatalf("AssignPrimaryNode: unexpected error: %v", err)
	}
	got2, err := AssignPrimaryNode("vpc-abc", []string{testNodeB, testNodeA})
	if err != nil {
		t.Fatalf("AssignPrimaryNode: unexpected error: %v", err)
	}
	if got1 != got2 {
		t.Fatalf("AssignPrimaryNode depends on input order: %q vs %q", got1, got2)
	}
}

func TestAssignPrimaryNode_ReturnsGivenNode(t *testing.T) {
	nodes := []string{testNodeA, testNodeB}
	got, err := AssignPrimaryNode("vpc-xyz", nodes)
	if err != nil {
		t.Fatalf("AssignPrimaryNode: unexpected error: %v", err)
	}
	if got != testNodeA && got != testNodeB {
		t.Fatalf("AssignPrimaryNode returned unknown node %q", got)
	}
}

// TestAssignPrimaryNode_RoughlyEvenSplit is not a correctness requirement
// (the design plan explicitly disclaims capacity-aware or perfectly-even
// placement) but guards against a degenerate hash that always picks the
// same index regardless of input.
func TestAssignPrimaryNode_RoughlyEvenSplit(t *testing.T) {
	nodes := []string{testNodeA, testNodeB}
	counts := map[string]int{}
	const n = 2000
	for i := range n {
		vpc := "vpc-" + string(rune('a'+i%26)) + string(rune('0'+i%10)) + string(rune(i))
		node, err := AssignPrimaryNode(vpc, nodes)
		if err != nil {
			t.Fatalf("AssignPrimaryNode: unexpected error: %v", err)
		}
		counts[node]++
	}
	if len(counts) != 2 {
		t.Fatalf("AssignPrimaryNode only ever selected %d distinct node(s): %v", len(counts), counts)
	}
	for node, c := range counts {
		if c < n/10 {
			t.Fatalf("AssignPrimaryNode split too skewed: node %q got %d/%d", node, c, n)
		}
	}
}

func TestAssignPrimaryNode_SingleNode(t *testing.T) {
	got, err := AssignPrimaryNode("vpc-1", []string{"gw-only"})
	if err != nil {
		t.Fatalf("AssignPrimaryNode: unexpected error: %v", err)
	}
	if got != "gw-only" {
		t.Fatalf("AssignPrimaryNode with single node: got %q, want %q", got, "gw-only")
	}
}
