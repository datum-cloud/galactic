// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package preflight

import (
	"errors"
	"strings"
	"testing"

	"github.com/cilium/ebpf/btf"
)

// stubProber is a mocked/stubbed [Prober] letting each of the four
// milestone-mandated scenarios (the pass case plus each individual failure
// case) be exercised without touching the real kernel (Milestone 2.3 exit
// criteria).
type stubProber struct {
	schedCLS      error
	hashMap       error
	btf           error
	fibLookupTBID error
}

func (s stubProber) SchedCLS() error      { return s.schedCLS }
func (s stubProber) HashMap() error       { return s.hashMap }
func (s stubProber) BTF() error           { return s.btf }
func (s stubProber) FIBLookupTBID() error { return s.fibLookupTBID }

var _ Prober = stubProber{}

// TestCheckWith_AllCapabilitiesPresent covers the pass case: every probe
// returns nil, CheckWith must return nil.
func TestCheckWith_AllCapabilitiesPresent(t *testing.T) {
	if err := CheckWith(stubProber{}); err != nil {
		t.Fatalf("CheckWith() = %v, want nil", err)
	}
}

// TestCheckWith_SchedCLSMissing covers BPF_PROG_TYPE_SCHED_CLS missing in
// isolation: every other probe passes, only this one fails, and the
// returned error must name the failing capability.
func TestCheckWith_SchedCLSMissing(t *testing.T) {
	want := errors.New("no SCHED_CLS on this kernel")
	err := CheckWith(stubProber{schedCLS: want})
	if err == nil {
		t.Fatal("CheckWith() = nil, want an error")
	}
	if !errors.Is(err, want) {
		t.Errorf("CheckWith() = %v, want it to wrap %v", err, want)
	}
	if !strings.Contains(err.Error(), "BPF_PROG_TYPE_SCHED_CLS") {
		t.Errorf("CheckWith() = %q, want it to name BPF_PROG_TYPE_SCHED_CLS", err.Error())
	}
}

// TestCheckWith_HashMapMissing covers BPF_MAP_TYPE_HASH missing in
// isolation.
func TestCheckWith_HashMapMissing(t *testing.T) {
	want := errors.New("no BPF_MAP_TYPE_HASH on this kernel")
	err := CheckWith(stubProber{hashMap: want})
	if err == nil {
		t.Fatal("CheckWith() = nil, want an error")
	}
	if !errors.Is(err, want) {
		t.Errorf("CheckWith() = %v, want it to wrap %v", err, want)
	}
	if !strings.Contains(err.Error(), "BPF_MAP_TYPE_HASH") {
		t.Errorf("CheckWith() = %q, want it to name BPF_MAP_TYPE_HASH", err.Error())
	}
}

// TestCheckWith_BTFMissing covers BTF presence missing in isolation.
func TestCheckWith_BTFMissing(t *testing.T) {
	want := errors.New("no BTF on this kernel")
	err := CheckWith(stubProber{btf: want})
	if err == nil {
		t.Fatal("CheckWith() = nil, want an error")
	}
	if !errors.Is(err, want) {
		t.Errorf("CheckWith() = %v, want it to wrap %v", err, want)
	}
	if !strings.Contains(err.Error(), "BTF") {
		t.Errorf("CheckWith() = %q, want it to mention BTF", err.Error())
	}
}

// TestCheckWith_FIBLookupTBIDMissing covers the VRF-tbid-specific
// bpf_fib_lookup variant missing in isolation -- this is the milestone's
// central case: the base helper existing is not enough, and this failure
// must be distinguishable from a generic "fib_lookup not supported" error.
func TestCheckWith_FIBLookupTBIDMissing(t *testing.T) {
	want := errors.New("struct bpf_fib_lookup has no tbid member")
	err := CheckWith(stubProber{fibLookupTBID: want})
	if err == nil {
		t.Fatal("CheckWith() = nil, want an error")
	}
	if !errors.Is(err, want) {
		t.Errorf("CheckWith() = %v, want it to wrap %v", err, want)
	}
	if !strings.Contains(err.Error(), "tbid") {
		t.Errorf("CheckWith() = %q, want it to mention tbid", err.Error())
	}
}

// TestCheckWith_AllMissing covers every capability failing at once: the
// aggregate error must mention all four, not just the first (design plan
// §6: never a partial check -- a caller fixing only the first-reported
// problem and re-running should immediately learn about the rest, not
// discover them one at a time).
func TestCheckWith_AllMissing(t *testing.T) {
	err := CheckWith(stubProber{
		schedCLS:      errors.New("no sched_cls"),
		hashMap:       errors.New("no hash map"),
		btf:           errors.New("no btf"),
		fibLookupTBID: errors.New("no tbid"),
	})
	if err == nil {
		t.Fatal("CheckWith() = nil, want an error")
	}
	for _, want := range []string{
		"BPF_PROG_TYPE_SCHED_CLS", "BPF_MAP_TYPE_HASH", "BTF", "tbid",
		"4/4 required kernel capabilities missing",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("CheckWith() = %q, want it to contain %q", err.Error(), want)
		}
	}
}

// TestCheckWith_NeverPartialPass guards against a regression where a
// caller might mistake "some capabilities present" for a pass: as long as
// even one probe fails, CheckWith must return non-nil, regardless of how
// many others succeeded.
func TestCheckWith_NeverPartialPass(t *testing.T) {
	cases := []struct {
		name string
		stub stubProber
	}{
		{"only fib lookup tbid missing", stubProber{fibLookupTBID: errors.New("x")}},
		{"only btf missing", stubProber{btf: errors.New("x")}},
		{"only hash map missing", stubProber{hashMap: errors.New("x")}},
		{"only sched cls missing", stubProber{schedCLS: errors.New("x")}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := CheckWith(tc.stub); err == nil {
				t.Fatal("CheckWith() = nil, want a non-nil error (no partial pass allowed)")
			}
		})
	}
}

// TestHasMemberNamed_TopLevel covers a member found directly on the
// struct, with no nesting involved.
func TestHasMemberNamed_TopLevel(t *testing.T) {
	s := fakeStruct("outer", fakeMember("family", fakeInt()), fakeMember("tbid", fakeInt()))
	if !hasMemberNamed(s, "tbid", 0) {
		t.Error("hasMemberNamed() = false, want true for a top-level member")
	}
}

// TestHasMemberNamed_NestedInAnonymousUnion mirrors the real kernel's
// struct bpf_fib_lookup layout: `tbid` lives inside an anonymous union
// nested inside the outer struct, not as a top-level member. This is the
// exact shape [KernelProber.FIBLookupTBID] must handle correctly.
func TestHasMemberNamed_NestedInAnonymousUnion(t *testing.T) {
	innerUnion := fakeUnion("",
		fakeMember("h_vlan_proto", fakeInt()),
		fakeMember("h_vlan_TCI", fakeInt()),
		fakeMember("tbid", fakeInt()),
	)
	outer := fakeStruct("bpf_fib_lookup",
		fakeMember("family", fakeInt()),
		fakeMember("ifindex", fakeInt()),
		fakeMember("", innerUnion),
	)
	if !hasMemberNamed(outer, "tbid", 0) {
		t.Error("hasMemberNamed() = false, want true for a member nested in an anonymous union")
	}
}

// TestHasMemberNamed_AbsentField covers the negative case: a struct that
// resembles bpf_fib_lookup's older shape (no tbid anywhere, e.g. an
// anonymous union holding only VLAN fields) must report false, not
// panic or false-positive.
func TestHasMemberNamed_AbsentField(t *testing.T) {
	innerUnion := fakeUnion("",
		fakeMember("h_vlan_proto", fakeInt()),
		fakeMember("h_vlan_TCI", fakeInt()),
	)
	outer := fakeStruct("bpf_fib_lookup",
		fakeMember("family", fakeInt()),
		fakeMember("ifindex", fakeInt()),
		fakeMember("", innerUnion),
	)
	if hasMemberNamed(outer, "tbid", 0) {
		t.Error("hasMemberNamed() = true, want false when tbid is genuinely absent")
	}
}

// TestHasMemberNamed_NonCompositeType covers a leaf type (not a struct or
// union) being passed in -- must return false, not panic.
func TestHasMemberNamed_NonCompositeType(t *testing.T) {
	if hasMemberNamed(fakeInt(), "tbid", 0) {
		t.Error("hasMemberNamed() = true for a non-composite type, want false")
	}
}

// TestHasMemberNamed_DepthLimitTerminates guards against unbounded
// recursion: a chain of nested anonymous structs deeper than
// maxMemberSearchDepth must terminate (returning false), not recurse
// forever or overflow the stack, even though this shape never occurs in a
// real bpf_fib_lookup.
func TestHasMemberNamed_DepthLimitTerminates(t *testing.T) {
	// Build a chain of anonymous structs nested well past the depth
	// limit, with the target field only at the very bottom.
	var chain btf.Type = fakeStruct("bottom", fakeMember("tbid", fakeInt()))
	for range maxMemberSearchDepth + 4 {
		chain = fakeStruct("", fakeMember("", chain))
	}
	if hasMemberNamed(chain, "tbid", 0) {
		t.Error("hasMemberNamed() = true past the depth limit, want false")
	}
}

// fakeInt returns a minimal *btf.Int usable as a leaf member type in test
// fixtures -- its own fields are irrelevant to hasMemberNamed, which never
// inspects a non-struct/union type's contents.
func fakeInt() *btf.Int {
	return &btf.Int{Name: "unsigned int", Size: 4}
}

// fakeMember builds a btf.Member with the given name and type, matching
// the shape hasMemberNamed walks.
func fakeMember(name string, typ btf.Type) btf.Member {
	return btf.Member{Name: name, Type: typ}
}

// fakeStruct builds a *btf.Struct with the given name and members.
func fakeStruct(name string, members ...btf.Member) *btf.Struct {
	return &btf.Struct{Name: name, Members: members}
}

// fakeUnion builds a *btf.Union with the given name and members.
func fakeUnion(name string, members ...btf.Member) *btf.Union {
	return &btf.Union{Name: name, Members: members}
}
