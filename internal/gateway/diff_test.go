// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gateway

import (
	"reflect"
	"testing"
)

const (
	testKeyA    = "ns/a"
	testKeyB    = "ns/b"
	testKeyKeep = "ns/keep"
)

func TestDiffRuleKeys_ApplyAndRemove(t *testing.T) {
	active := map[string]DesiredRule{
		testKeyKeep: {Key: testKeyKeep},
		testKeyA:    {Key: testKeyA},
	}
	desired := map[string]DesiredRule{
		testKeyKeep: {Key: testKeyKeep},
		testKeyB:    {Key: testKeyB},
	}

	toApply, toRemove := diffRuleKeys(active, desired)

	if want := []string{testKeyB, testKeyKeep}; !reflect.DeepEqual(toApply, want) {
		t.Errorf("toApply = %v, want %v", toApply, want)
	}
	if want := []string{testKeyA}; !reflect.DeepEqual(toRemove, want) {
		t.Errorf("toRemove = %v, want %v", toRemove, want)
	}
}

func TestDiffRuleKeys_EmptyInputs(t *testing.T) {
	toApply, toRemove := diffRuleKeys(nil, nil)
	if len(toApply) != 0 || len(toRemove) != 0 {
		t.Errorf("diffRuleKeys(nil, nil) = (%v, %v), want both empty", toApply, toRemove)
	}
}

func TestDiffRuleKeys_AllNewNoActive(t *testing.T) {
	desired := map[string]DesiredRule{testKeyA: {Key: testKeyA}, testKeyB: {Key: testKeyB}}
	toApply, toRemove := diffRuleKeys(nil, desired)
	if want := []string{testKeyA, testKeyB}; !reflect.DeepEqual(toApply, want) {
		t.Errorf("toApply = %v, want %v", toApply, want)
	}
	if len(toRemove) != 0 {
		t.Errorf("toRemove = %v, want empty", toRemove)
	}
}

func TestDiffRuleKeys_AllRemovedNoDesired(t *testing.T) {
	active := map[string]DesiredRule{testKeyA: {Key: testKeyA}, testKeyB: {Key: testKeyB}}
	toApply, toRemove := diffRuleKeys(active, nil)
	if len(toApply) != 0 {
		t.Errorf("toApply = %v, want empty", toApply)
	}
	if want := []string{testKeyA, testKeyB}; !reflect.DeepEqual(toRemove, want) {
		t.Errorf("toRemove = %v, want %v", toRemove, want)
	}
}
