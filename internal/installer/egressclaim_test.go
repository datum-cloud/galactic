// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package installer

import (
	"context"
	"errors"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	bgpv1alpha1 "go.datum.net/network/api/v1alpha1"
)

const testClaimNode = "node-a"

func TestPlanEgressClaims(t *testing.T) {
	grace := time.Minute
	claimed := map[uint32]struct{}{100: {}, 300: {}}
	vrfs := []egressVRF{
		{TableID: 100, Argument: 1, Age: 0, HasRoute: false},               // claimed, missing: install
		{TableID: 200, Argument: 2, Age: 2 * time.Minute, HasRoute: true},  // unclaimed, old: withdraw
		{TableID: 300, Argument: 3, Age: 0, HasRoute: true},                // claimed, present: nothing
		{TableID: 400, Argument: 4, Age: 10 * time.Second, HasRoute: true}, // unclaimed, young: wait
		{TableID: 500, Argument: 5, Age: time.Hour, HasRoute: false},       // unclaimed, absent: nothing
	}

	got := planEgressClaims(vrfs, claimed, grace)

	want := []egressAction{
		{TableID: 100, Argument: 1, Install: true},
		{TableID: 200, Argument: 2, Install: false},
	}
	if len(got) != len(want) {
		t.Fatalf("planEgressClaims() = %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("planEgressClaims()[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestPlanEgressClaims_WithdrawsExactlyAtTheGrace(t *testing.T) {
	got := planEgressClaims(
		[]egressVRF{{TableID: 7, Argument: 9, Age: time.Minute, HasRoute: true}},
		map[uint32]struct{}{}, time.Minute)
	if len(got) != 1 || got[0].Install {
		t.Fatalf("planEgressClaims() = %+v, want one withdraw", got)
	}
}

func TestClaimedTableIDs_SkipsAVPCWithNoVRFHere(t *testing.T) {
	claims := []bgpv1alpha1.EgressShardClaim{
		newTestClaim("a", "vpc-here"),
		newTestClaim("b", "vpc-gone"),
		newTestClaim("c", "vpc-here"),
	}
	resolve := func(vpc string) (uint32, error) {
		if vpc == "vpc-here" {
			return 42, nil
		}
		return 0, errors.New("no such VRF")
	}

	got := claimedTableIDs(claims, resolve)

	if len(got) != 1 {
		t.Fatalf("claimedTableIDs() = %v, want only table 42", got)
	}
	if _, ok := got[42]; !ok {
		t.Errorf("claimedTableIDs() = %v, want table 42", got)
	}
}

func TestListNodeEgressClaims_ReadsOnlyThisNode(t *testing.T) {
	mine := newTestClaim("mine", "vpc-a")
	mine.Labels = map[string]string{bgpv1alpha1.LabelEgressShardClaimNode: testClaimNode}
	theirs := newTestClaim("theirs", "vpc-a")
	theirs.Labels = map[string]string{bgpv1alpha1.LabelEgressShardClaimNode: "node-b"}
	unlabelled := newTestClaim("unlabelled", "vpc-a")

	k8s := fake.NewClientBuilder().WithScheme(scheme).WithObjects(&mine, &theirs, &unlabelled).Build()

	got, err := listNodeEgressClaims(context.Background(), k8s, testClaimNode)
	if err != nil {
		t.Fatalf("listNodeEgressClaims() error = %v, want nil", err)
	}
	if len(got) != 1 || got[0].Name != "mine" {
		t.Errorf("listNodeEgressClaims() = %v, want only the claim labelled node-a", names(got))
	}
}

func TestRunEgressClaimSweep_DoesNothingWithoutAClient(t *testing.T) {
	runEgressClaimSweep(context.Background(), ebpfDatapathState{nodeName: testClaimNode})
	k8s := fake.NewClientBuilder().WithScheme(scheme).Build()
	runEgressClaimSweep(context.Background(), ebpfDatapathState{k8sClient: k8s})
}

func newTestClaim(name, vpc string) bgpv1alpha1.EgressShardClaim {
	return bgpv1alpha1.EgressShardClaim{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "tenant"},
		Spec: bgpv1alpha1.EgressShardClaimSpec{
			Attachment: bgpv1alpha1.EgressShardClaimAttachmentRef{Name: name},
			VPC:        bgpv1alpha1.EgressShardClaimVPCRef{Name: vpc},
			NodeName:   testClaimNode,
			Families:   []bgpv1alpha1.EgressAddressFamily{bgpv1alpha1.EgressAddressFamilyIPv6},
		},
	}
}

func names(claims []bgpv1alpha1.EgressShardClaim) []string {
	out := make([]string, 0, len(claims))
	for _, c := range claims {
		out = append(out, c.Name)
	}
	return out
}
