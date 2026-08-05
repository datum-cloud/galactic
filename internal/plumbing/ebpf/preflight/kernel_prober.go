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
// member this package's FIBLookupTBID check looks for. Named constants so
// both the lookup and its error messages stay in sync if either ever needs
// to change.
const (
	fibLookupStructName = "bpf_fib_lookup"
	tbidMemberName      = "tbid"
)

// KernelProber is the real, kernel-backed [Prober] implementation used in
// production. It probes the actual running kernel via
// github.com/cilium/ebpf's features package (for BPF_PROG_TYPE_SCHED_CLS
// and BPF_MAP_TYPE_HASH -- both of which that package detects by actually
// attempting the create/load syscall, the same technique any BPF loader
// uses) and via kernel BTF introspection (for BTF presence and the
// bpf_fib_lookup tbid member specifically -- see this package's doc
// comment for why a struct-field check, not a version-string parse).
//
// The zero value is not ready to use; construct with [NewKernelProber].
// A *KernelProber may be reused across multiple Check/CheckWith calls --
// its one piece of internal state (the loaded kernel BTF spec) is cached
// after the first probe that needs it, since re-parsing the kernel's BTF
// blob (several megabytes) on every call would make repeated preflight
// checks (e.g. a health-check loop re-running this at Milestone 3.1/4)
// needlessly expensive.
type KernelProber struct {
	specOnce sync.Once
	spec     *btf.Spec
	specErr  error
}

// NewKernelProber returns a ready-to-use [KernelProber].
func NewKernelProber() *KernelProber {
	return &KernelProber{}
}

// SchedCLS implements [Prober] by attempting to create a minimal
// BPF_PROG_TYPE_SCHED_CLS program and reporting whether the kernel accepted
// the program type.
func (k *KernelProber) SchedCLS() error {
	if err := ensureMemlockRemoved(); err != nil {
		return err
	}
	if err := features.HaveProgramType(ebpf.SchedCLS); err != nil {
		return fmt.Errorf("kernel rejects BPF_PROG_TYPE_SCHED_CLS: %w", err)
	}
	return nil
}

// HashMap implements [Prober] by attempting to create a minimal
// BPF_MAP_TYPE_HASH map and reporting whether the kernel accepted the map
// type.
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

// FIBLookupTBID implements [Prober] by loading the running kernel's BTF
// description of `struct bpf_fib_lookup` and checking, recursively (the
// real struct nests `tbid` inside an anonymous union -- see
// hasMemberNamed), for a member literally named `tbid`. Presence of that
// field is a direct, version-string-independent proof that this kernel's
// bpf_fib_lookup() understands the BPF_FIB_LOOKUP_TBID flag and the
// VRF-table-id lookup R5 depends on, since the kernel's BTF is generated
// from the exact same struct definition its bpf_fib_lookup()
// implementation reads.
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

// maxMemberSearchDepth bounds hasMemberNamed's recursion. struct
// bpf_fib_lookup nests at most one level deep (a handful of anonymous
// unions directly inside the outer struct); this ceiling is generous
// headroom against any deeper nesting a future kernel might introduce,
// while still guaranteeing termination against unexpected/malformed BTF.
const maxMemberSearchDepth = 8

// hasMemberNamed reports whether t (expected to be a *btf.Struct or
// *btf.Union) has a member named name, searching recursively into any
// nested anonymous struct/union members -- required here because the real
// kernel's `struct bpf_fib_lookup` places `tbid` inside an anonymous
// `union { struct { ... vlan fields ... }; __u32 tbid; }`, not as a
// top-level member.
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

// ensureMemlockRemoved lifts the memlock rlimit that older kernels (pre-5.11
// cgroup-based BPF memory accounting) enforce against BPF map/program
// creation. It is safe and cheap to call repeatedly -- github.com/cilium/
// ebpf's rlimit package makes the underlying setrlimit call idempotent --
// and is required here because this package's probes may be the first BPF
// syscalls a process makes (Milestone 3.1's control daemon is expected to
// call [Check] before doing any other BPF setup of its own).
func ensureMemlockRemoved() error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock rlimit: %w", err)
	}
	return nil
}

var _ Prober = (*KernelProber)(nil)
