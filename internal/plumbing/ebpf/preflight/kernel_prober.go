// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package preflight

import (
	"fmt"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/rlimit"
)

// fibLookupStructName and tbidMemberName identify the kernel BTF type and
// member the FIB lookup check looks for. Named so the lookup and its error
// messages stay in sync.
const (
	fibLookupStructName = "bpf_fib_lookup"
	tbidMemberName      = "tbid"
)

// KernelProber is the real Prober implementation. It probes the running kernel
// by attempting the create and load syscalls for the program and map types, the
// same technique any BPF loader uses, and by introspecting kernel BTF for BTF
// presence and the FIB lookup's table-id member.
//
// The zero value is not ready to use; construct with NewKernelProber. One may
// be reused across calls: its only internal state, the loaded BTF spec, is
// cached after the first probe that needs it, since re-parsing a multi-megabyte
// blob on every call would make a repeated check needlessly expensive.
type KernelProber struct {
	specOnce sync.Once
	spec     *btf.Spec
	specErr  error
}

// NewKernelProber returns a ready-to-use [KernelProber].
func NewKernelProber() *KernelProber {
	return &KernelProber{}
}

// SchedCLS reports whether the kernel accepts the TC-BPF program type, by
// attempting to create a minimal program of that type.
func (k *KernelProber) SchedCLS() error {
	if err := ensureMemlockRemoved(); err != nil {
		return err
	}
	if err := features.HaveProgramType(ebpf.SchedCLS); err != nil {
		return fmt.Errorf("kernel rejects BPF_PROG_TYPE_SCHED_CLS: %w", err)
	}
	return nil
}

// HashMap reports whether the kernel accepts the hash map type, by attempting
// to create a minimal map of that type.
func (k *KernelProber) HashMap() error {
	if err := ensureMemlockRemoved(); err != nil {
		return err
	}
	if err := features.HaveMapType(ebpf.Hash); err != nil {
		return fmt.Errorf("kernel rejects BPF_MAP_TYPE_HASH: %w", err)
	}
	return nil
}

// BTF implements [Prober] by attempting to load the running kernel's own
// BTF (typically /sys/kernel/btf/vmlinux).
func (k *KernelProber) BTF() error {
	if _, err := k.kernelSpec(); err != nil {
		return fmt.Errorf("kernel BTF unavailable: %w", err)
	}
	return nil
}

// FIBLookupTBID reports whether this kernel's bpf_fib_lookup understands the
// VRF-table-id parameter, by loading the kernel's BTF description of the lookup
// struct and searching it recursively for a member named tbid, which the real
// struct nests inside an anonymous union.
//
// Presence of that field is version-string-independent proof, the kernel's BTF
// being generated from the same struct definition the helper implementation
// reads.
func (k *KernelProber) FIBLookupTBID() error {
	spec, err := k.kernelSpec()
	if err != nil {
		return fmt.Errorf("cannot determine bpf_fib_lookup tbid support without kernel BTF: %w", err)
	}

	var fibLookup *btf.Struct
	if err := spec.TypeByName(fibLookupStructName, &fibLookup); err != nil {
		return fmt.Errorf("kernel BTF has no %q struct: %w", fibLookupStructName, err)
	}

	if !hasMemberNamed(fibLookup, tbidMemberName, 0) {
		return fmt.Errorf(
			"kernel's struct %s has no %q member: this kernel's bpf_fib_lookup() predates VRF-table-id "+
				"support; upgrade the kernel or exclude this node from the eBPF uSID datapath rollout",
			fibLookupStructName, tbidMemberName,
		)
	}
	return nil
}

// kernelSpec loads and caches the running kernel's BTF spec, parsing it at
// most once per *KernelProber.
func (k *KernelProber) kernelSpec() (*btf.Spec, error) {
	k.specOnce.Do(func() {
		k.spec, k.specErr = btf.LoadKernelSpec()
	})
	return k.spec, k.specErr
}

// maxMemberSearchDepth bounds the recursive member search. The real struct
// nests at most one level deep, so this is headroom against deeper nesting in a
// future kernel while still guaranteeing termination against malformed BTF.
const maxMemberSearchDepth = 8

// hasMemberNamed reports whether t, a struct or union, has a member named name,
// searching recursively into nested anonymous members. That is required because
// the kernel places the field this checks for inside an anonymous union rather
// than at the top level.
func hasMemberNamed(t btf.Type, name string, depth int) bool {
	if depth > maxMemberSearchDepth {
		return false
	}

	var members []btf.Member
	switch v := t.(type) {
	case *btf.Struct:
		members = v.Members
	case *btf.Union:
		members = v.Members
	default:
		return false
	}

	for _, m := range members {
		if m.Name == name {
			return true
		}
		if hasMemberNamed(m.Type, name, depth+1) {
			return true
		}
	}
	return false
}

// ensureMemlockRemoved lifts the memlock limit older kernels enforce against
// BPF map and program creation. Safe and cheap to call repeatedly, the
// underlying call being idempotent, and required here because these probes may
// be the first BPF syscalls a process makes.
func ensureMemlockRemoved() error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock rlimit: %w", err)
	}
	return nil
}

var _ Prober = (*KernelProber)(nil)
