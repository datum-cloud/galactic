// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package preflight

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/features"
	"golang.org/x/sys/unix"
)

// minTrafficPolicyKernel is the oldest kernel interface traffic policy
// enforces on: 6.8 defers freeing a replaced inner map until no program can
// still use it ("bpf: Defer the free of inner map when necessary"), which
// snapshot publication relies on and which cannot be probed.
var minTrafficPolicyKernel = [2]int{6, 8}

// CheckTrafficPolicy reports whether this kernel can enforce interface
// traffic policy: map-in-map hashes, bpf_for_each_map_elem from a tc program,
// and, unless kernelCheck is false, kernel 6.8 or later. galactic-cni records
// the answer, and CNI ADD refuses a managed interface while policy is on and
// the answer was no; nothing falls back to forwarding unenforced.
func CheckTrafficPolicy(kernelCheck bool) error {
	if err := ensureMemlockRemoved(); err != nil {
		return err
	}
	var errs []error
	if err := features.HaveMapType(ebpf.HashOfMaps); err != nil {
		errs = append(errs, fmt.Errorf("kernel rejects BPF_MAP_TYPE_HASH_OF_MAPS: %w", err))
	}
	if err := features.HaveProgramHelper(ebpf.SchedCLS, asm.FnForEachMapElem); err != nil {
		errs = append(errs, fmt.Errorf("kernel rejects bpf_for_each_map_elem for BPF_PROG_TYPE_SCHED_CLS: %w", err))
	}
	if kernelCheck {
		var uts unix.Utsname
		if err := unix.Uname(&uts); err != nil {
			errs = append(errs, fmt.Errorf("read kernel release: %w", err))
		} else if release := unix.ByteSliceToString(uts.Release[:]); !atLeast(release, minTrafficPolicyKernel) {
			errs = append(errs, fmt.Errorf("kernel %s is older than %d.%d; set GALACTIC_CNI_TRAFFIC_POLICY_KERNEL_CHECK=false "+
				"only if it carries the inner-map freeing fix", release, minTrafficPolicyKernel[0], minTrafficPolicyKernel[1]))
		}
	}
	return errors.Join(errs...)
}

// atLeast reports whether release ("6.18.2-custom") is at least want.
func atLeast(release string, want [2]int) bool {
	parts := strings.SplitN(release, ".", 3)
	if len(parts) < 2 {
		return false
	}
	major, err1 := strconv.Atoi(parts[0])
	digits := strings.IndexFunc(parts[1], func(r rune) bool { return r < '0' || r > '9' })
	if digits < 0 {
		digits = len(parts[1])
	}
	minor, err2 := strconv.Atoi(parts[1][:digits])
	if err1 != nil || err2 != nil {
		return false
	}
	return major > want[0] || (major == want[0] && minor >= want[1])
}
