// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gateway

import (
	"net/netip"
	"reflect"
	"testing"
)

const (
	testKeyA       = "ns/a"
	testKeyB       = "ns/b"
	testKeyKeep    = "ns/keep"
	testKeyChanged = "ns/changed"
)

func TestDiffRuleKeys_ApplyAndRemove(t *testing.T) {
	active := map[string]DesiredRule{
		testKeyKeep:    {Key: testKeyKeep, Port: 80},
		testKeyChanged: {Key: testKeyChanged, Port: 80},
		testKeyA:       {Key: testKeyA},
	}
	desired := map[string]DesiredRule{
		testKeyKeep:    {Key: testKeyKeep, Port: 80},
		testKeyChanged: {Key: testKeyChanged, Port: 443},
		testKeyB:       {Key: testKeyB},
	}

	toApply, toRemove := diffRuleKeys(active, desired)

	if want := []string{testKeyB, testKeyChanged}; !reflect.DeepEqual(toApply, want) {
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

func TestRulesEqual(t *testing.T) {
	vip := netip.MustParseAddr("2001:db8::1")
	usidA := netip.MustParseAddr("fc00:0:1::")
	usidB := netip.MustParseAddr("fc00:0:2::")
	backend := func(usid netip.Addr) DesiredBackend {
		return DesiredBackend{Address: netip.MustParseAddr("2001:db8:1::10"), Port: 8080, USID: usid}
	}
	base := DesiredRule{
		Key: testKeyA, VPCRef: "vpc", VPCAttachmentRef: "att",
		VIPAddresses: []netip.Addr{vip}, Protocol: "udp", Port: 80,
		Backends: []DesiredBackend{backend(usidA)},
	}
	clone := func(mut func(*DesiredRule)) DesiredRule {
		r := base
		r.VIPAddresses = append([]netip.Addr(nil), base.VIPAddresses...)
		r.Backends = append([]DesiredBackend(nil), base.Backends...)
		mut(&r)
		return r
	}

	tests := []struct {
		name string
		b    DesiredRule
		want bool
	}{
		{"identical copy", clone(func(*DesiredRule) {}), true},
		{"backend uSID moved", clone(func(r *DesiredRule) { r.Backends[0] = backend(usidB) }), false},
		{"backend added", clone(func(r *DesiredRule) { r.Backends = append(r.Backends, backend(usidB)) }), false},
		{"VIP removed", clone(func(r *DesiredRule) { r.VIPAddresses = nil }), false},
		{"port changed", clone(func(r *DesiredRule) { r.Port = 443 }), false},
		{"protocol changed", clone(func(r *DesiredRule) { r.Protocol = "" }), false},
		{"VPC changed", clone(func(r *DesiredRule) { r.VPCRef = "other" }), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := rulesEqual(base, tt.b); got != tt.want {
				t.Errorf("rulesEqual = %v, want %v", got, tt.want)
			}
		})
	}
}
