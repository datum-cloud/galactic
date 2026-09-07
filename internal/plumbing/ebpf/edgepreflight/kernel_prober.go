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

// bpfFuncXDPAdjustHead is the raw helper ID from the kernel's helper enum. That
// numeric ID is stable ABI once a helper is introduced.
//
// No BTF struct-field probe is possible for whether a helper exists, unlike the
// uSID datapath's table-id check, so support is detected by attempting to load a
// program using it, the same technique the program and map type checks use.
//
// The eBPF library exports no named constant for this helper, resolving such
// constants per platform for helpers it has not special-cased, so the raw enum
// value is cited directly.
const bpfFuncXDPAdjustHead asm.BuiltinFunc = 44

// KernelProber is the real Prober implementation. It probes the running kernel
// by attempting the create and load syscalls, and by BTF introspection for BTF
// presence.
//
// The zero value is not ready to use; construct with NewKernelProber. One may be
// reused across calls: its only internal state, the loaded BTF spec, is cached
// after the first probe that needs it.
type KernelProber struct {
	specOnce sync.Once
	spec     *btf.Spec
	specErr  error
}

// NewKernelProber returns a ready-to-use [KernelProber].
func NewKernelProber() *KernelProber {
	return &KernelProber{}
}

// XDP reports whether the kernel accepts the XDP program type, by attempting to
// create a minimal program of that type.
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
