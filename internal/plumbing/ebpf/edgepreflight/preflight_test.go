// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package edgepreflight

import (
	"errors"
	"strings"
	"testing"
)

// stubProber is a mocked/stubbed [Prober] letting the pass case and each
// individual failure case be exercised without touching the real kernel.
type stubProber struct {
	xdp           error
	lruHashMap    error
	hashMap       error
	btf           error
	xdpAdjustHead error
	xdpCsumDiff   error
}

func (s stubProber) XDP() error           { return s.xdp }
func (s stubProber) LRUHashMap() error    { return s.lruHashMap }
func (s stubProber) HashMap() error       { return s.hashMap }
func (s stubProber) BTF() error           { return s.btf }
func (s stubProber) XDPAdjustHead() error { return s.xdpAdjustHead }
func (s stubProber) XDPCsumDiff() error   { return s.xdpCsumDiff }

var _ Prober = stubProber{}

// TestCheckWith_AllCapabilitiesPresent covers the pass case.
func TestCheckWith_AllCapabilitiesPresent(t *testing.T) {
	if err := CheckWith(stubProber{}); err != nil {
		t.Fatalf("CheckWith() = %v, want nil", err)
	}
}

// failureCase exercises one capability failing in isolation and asserts the
// aggregate error wraps the underlying cause and names the capability.
func failureCase(t *testing.T, name string, p Prober, want error) {
	t.Helper()
	err := CheckWith(p)
	if err == nil {
		t.Fatal("CheckWith() = nil, want an error")
	}
	if !errors.Is(err, want) {
		t.Errorf("CheckWith() = %v, want it to wrap %v", err, want)
	}
	if !strings.Contains(err.Error(), name) {
		t.Errorf("CheckWith() = %q, want it to name %q", err.Error(), name)
	}
}

func TestCheckWith_XDPMissing(t *testing.T) {
	want := errors.New("no XDP on this kernel")
	failureCase(t, "BPF_PROG_TYPE_XDP", stubProber{xdp: want}, want)
}

func TestCheckWith_HashMapMissing(t *testing.T) {
	want := errors.New("no BPF_MAP_TYPE_HASH on this kernel")
	failureCase(t, "BPF_MAP_TYPE_HASH", stubProber{hashMap: want}, want)
}

func TestCheckWith_LRUHashMapMissing(t *testing.T) {
	want := errors.New("no BPF_MAP_TYPE_LRU_HASH on this kernel")
	failureCase(t, "BPF_MAP_TYPE_LRU_HASH", stubProber{lruHashMap: want}, want)
}

func TestCheckWith_BTFMissing(t *testing.T) {
	want := errors.New("no BTF on this kernel")
	failureCase(t, "kernel BTF", stubProber{btf: want}, want)
}

func TestCheckWith_XDPAdjustHeadMissing(t *testing.T) {
	want := errors.New("no bpf_xdp_adjust_head on this kernel")
	failureCase(t, "bpf_xdp_adjust_head", stubProber{xdpAdjustHead: want}, want)
}

func TestCheckWith_XDPCsumDiffMissing(t *testing.T) {
	want := errors.New("no bpf_csum_diff on this kernel")
	failureCase(t, "bpf_csum_diff", stubProber{xdpCsumDiff: want}, want)
}

// TestCheckWith_EveryCapabilityMissing covers every probe failing at once:
// the aggregate error must name all six, and no early return may skip any.
func TestCheckWith_EveryCapabilityMissing(t *testing.T) {
	err := CheckWith(stubProber{
		xdp:           errors.New("a"),
		hashMap:       errors.New("b"),
		lruHashMap:    errors.New("c"),
		btf:           errors.New("d"),
		xdpAdjustHead: errors.New("e"),
		xdpCsumDiff:   errors.New("f"),
	})
	if err == nil {
		t.Fatal("CheckWith() = nil, want an error")
	}
	for _, name := range []string{
		"BPF_PROG_TYPE_XDP", "BPF_MAP_TYPE_HASH", "BPF_MAP_TYPE_LRU_HASH",
		"kernel BTF", "bpf_xdp_adjust_head", "bpf_csum_diff",
	} {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("CheckWith() = %q, want it to name %q", err.Error(), name)
		}
	}
	if !strings.Contains(err.Error(), "6/6") {
		t.Errorf("CheckWith() = %q, want it to report 6/6 missing", err.Error())
	}
}
