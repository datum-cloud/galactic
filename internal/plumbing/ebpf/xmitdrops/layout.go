// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package xmitdrops

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf/btf"
)

const (
	// redirectErrParams counts the xdp_redirect_err arguments, including the
	// leading void * every tracepoint probe takes: dev, prog, tgt, err,
	// map_type, map_id, index.
	redirectErrParams = 8
	// redirectErrMapType is the index of the map_type argument. Kernels
	// before about 5.18 pass a struct bpf_map pointer there instead.
	redirectErrMapType = 5
	// devmapXmitParams counts the xdp_devmap_xmit arguments, including the
	// leading void *.
	devmapXmitParams = 6
)

// checkTracepointLayout reports whether the running kernel's tracepoint
// argument layouts are the ones xmitdrops.c reads.
func checkTracepointLayout() error {
	spec, err := btf.LoadKernelSpec()
	if err != nil {
		return fmt.Errorf("load kernel BTF: %w", err)
	}
	return checkLayout(func(name string) (btf.Type, error) {
		var td *btf.Typedef
		if err := spec.TypeByName(name, &td); err != nil {
			return nil, err
		}
		return td, nil
	})
}

// checkLayout checks the tracepoint prototypes that lookup returns by typedef
// name.
func checkLayout(lookup func(name string) (btf.Type, error)) error {
	redirect, err := tracepointParams(lookup, "btf_trace_xdp_redirect_err")
	if err != nil {
		return err
	}
	if len(redirect) != redirectErrParams {
		return fmt.Errorf("unsupported tracepoint layout: xdp_redirect_err has %d arguments, want %d",
			len(redirect), redirectErrParams)
	}
	if e, ok := btf.UnderlyingType(redirect[redirectErrMapType].Type).(*btf.Enum); !ok || e.Name != "bpf_map_type" {
		return errors.New("unsupported tracepoint layout: xdp_redirect_err has no map_type argument")
	}
	devmap, err := tracepointParams(lookup, "btf_trace_xdp_devmap_xmit")
	if err != nil {
		return err
	}
	if len(devmap) != devmapXmitParams {
		return fmt.Errorf("unsupported tracepoint layout: xdp_devmap_xmit has %d arguments, want %d",
			len(devmap), devmapXmitParams)
	}
	return nil
}

func tracepointParams(lookup func(string) (btf.Type, error), name string) ([]btf.FuncParam, error) {
	t, err := lookup(name)
	if err != nil {
		return nil, fmt.Errorf("unsupported tracepoint layout: find %s: %w", name, err)
	}
	t = btf.UnderlyingType(t)
	if p, ok := t.(*btf.Pointer); ok {
		t = btf.UnderlyingType(p.Target)
	}
	fp, ok := t.(*btf.FuncProto)
	if !ok {
		return nil, fmt.Errorf("unsupported tracepoint layout: %s is not a function prototype", name)
	}
	return fp.Params, nil
}
