// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package edgepreflight

import (
	"fmt"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/rlimit"
)

// bpfFuncXDPAdjustHead and bpfFuncCsumDiff are the raw BPF_FUNC_* helper IDs
// from the kernel UAPI's enum bpf_func_id (include/uapi/linux/bpf.h). These
// numeric IDs are stable ABI once a helper is introduced -- unlike
// preflight's tbid check, no BTF struct-field probe is possible for "does
// this helper exist," so features.HaveProgramHelper (the same
// creation-attempt technique preflight's own SchedCLS/HashMap checks use,
// just applied to a specific helper rather than a program/map type) is the
// house convention here instead of a version-string heuristic.
//
// github.com/cilium/ebpf v0.22.0's asm package does not export named
// constants for every helper (BuiltinFunc constants are resolved per
// platform via BuiltinFuncForPlatform for helpers the library hasn't
// special-cased) -- these two are cited directly against the raw enum
// values confirmed empirically on this repo's target kernel
// (7.1.3-200.fc44.x86_64) during this design's Phase 0 spike.
const (
	bpfFuncXDPAdjustHead asm.BuiltinFunc = 44
	bpfFuncCsumDiff      asm.BuiltinFunc = 28
)

// KernelProber is the real, kernel-backed [Prober] implementation used in
// production. It probes the actual running kernel via
// github.com/cilium/ebpf's features package (which detects support by
// actually attempting the create/load syscall) and via kernel BTF
// introspection for BTF presence.
//
// The zero value is not ready to use; construct with [NewKernelProber]. A
// *KernelProber may be reused across multiple Check/CheckWith calls -- its
// one piece of internal state (the loaded kernel BTF spec) is cached after
// the first probe that needs it.
type KernelProber struct {
	specOnce sync.Once
	spec     *btf.Spec
	specErr  error
}

// NewKernelProber returns a ready-to-use [KernelProber].
func NewKernelProber() *KernelProber {
	return &KernelProber{}
}

// XDP implements [Prober] by attempting to create a minimal
// BPF_PROG_TYPE_XDP program and reporting whether the kernel accepted the
// program type.
func (k *KernelProber) XDP() error {
	if err := ensureMemlockRemoved(); err != nil {
		return err
	}
	if err := features.HaveProgramType(ebpf.XDP); err != nil {
		return fmt.Errorf("kernel rejects BPF_PROG_TYPE_XDP: %w", err)
	}
	return nil
}

// HashMap implements [Prober] by attempting to create a minimal
// BPF_MAP_TYPE_HASH map.
func (k *KernelProber) HashMap() error {
	if err := ensureMemlockRemoved(); err != nil {
		return err
	}
	if err := features.HaveMapType(ebpf.Hash); err != nil {
		return fmt.Errorf("kernel rejects BPF_MAP_TYPE_HASH: %w", err)
	}
	return nil
}

// LRUHashMap implements [Prober] by attempting to create a minimal
// BPF_MAP_TYPE_LRU_HASH map.
func (k *KernelProber) LRUHashMap() error {
	if err := ensureMemlockRemoved(); err != nil {
		return err
	}
	if err := features.HaveMapType(ebpf.LRUHash); err != nil {
		return fmt.Errorf("kernel rejects BPF_MAP_TYPE_LRU_HASH: %w", err)
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

// XDPAdjustHead implements [Prober] by attempting to load a minimal XDP
// program that calls bpf_xdp_adjust_head.
func (k *KernelProber) XDPAdjustHead() error {
	if err := ensureMemlockRemoved(); err != nil {
		return err
	}
	if err := features.HaveProgramHelper(ebpf.XDP, bpfFuncXDPAdjustHead); err != nil {
		return fmt.Errorf("kernel's XDP programs reject bpf_xdp_adjust_head: %w", err)
	}
	return nil
}

// XDPCsumDiff implements [Prober] by attempting to load a minimal XDP
// program that calls bpf_csum_diff.
func (k *KernelProber) XDPCsumDiff() error {
	if err := ensureMemlockRemoved(); err != nil {
		return err
	}
	if err := features.HaveProgramHelper(ebpf.XDP, bpfFuncCsumDiff); err != nil {
		return fmt.Errorf("kernel's XDP programs reject bpf_csum_diff: %w", err)
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

// ensureMemlockRemoved lifts the memlock rlimit that older kernels enforce
// against BPF map/program creation. Safe and cheap to call repeatedly.
func ensureMemlockRemoved() error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock rlimit: %w", err)
	}
	return nil
}

var _ Prober = (*KernelProber)(nil)
