// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package xmitdrops

import (
	"fmt"
	"strings"
	"testing"

	"github.com/cilium/ebpf/btf"
)

const (
	redirectName = "btf_trace_xdp_redirect_err"
	devmapName   = "btf_trace_xdp_devmap_xmit"
)

func both(r, d btf.Type) map[string]btf.Type {
	return map[string]btf.Type{redirectName: r, devmapName: d}
}

func tracepointTypedef(name string, params ...btf.Type) btf.Type {
	fp := &btf.FuncProto{Return: &btf.Void{}}
	for i, p := range params {
		fp.Params = append(fp.Params, btf.FuncParam{Name: fmt.Sprintf("p%d", i), Type: p})
	}
	return &btf.Typedef{Name: name, Type: &btf.Pointer{Target: fp}}
}

func TestCheckLayout(t *testing.T) {
	u32 := &btf.Int{Name: "u32", Size: 4}
	ptr := &btf.Pointer{Target: &btf.Void{}}
	mapType := &btf.Enum{Name: "bpf_map_type", Size: 4}
	// A qualifier and a typedef between the parameter and the enum must not
	// hide it.
	aliased := &btf.Const{Type: &btf.Typedef{Name: "map_type_t", Type: mapType}}
	oldMap := &btf.Pointer{Target: &btf.Struct{Name: "bpf_map", Size: 8}}

	devmap := tracepointTypedef(devmapName, ptr, ptr, u32, u32, u32, u32)
	redirect := func(mt btf.Type) btf.Type {
		return tracepointTypedef(redirectName, ptr, ptr, ptr, ptr, u32, mt, u32, u32)
	}

	tests := []struct {
		name    string
		types   map[string]btf.Type
		wantErr string
	}{
		{"current layout", both(redirect(mapType), devmap), ""},
		{"qualified map_type", both(redirect(aliased), devmap), ""},
		{"old layout", both(redirect(oldMap), devmap), "no map_type argument"},
		{"redirect missing", map[string]btf.Type{devmapName: devmap}, redirectName},
		{"devmap missing", map[string]btf.Type{redirectName: redirect(mapType)}, devmapName},
		{
			"devmap short",
			map[string]btf.Type{
				redirectName: redirect(mapType),
				devmapName:   tracepointTypedef(devmapName, ptr, ptr, u32),
			},
			"xdp_devmap_xmit has 3 arguments",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := checkLayout(func(name string) (btf.Type, error) {
				if ty, ok := tc.types[name]; ok {
					return ty, nil
				}
				return nil, fmt.Errorf("type %s not found", name)
			})
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
				t.Fatalf("error = %v, want containing %q", err, tc.wantErr)
			case err != nil && !strings.Contains(err.Error(), "unsupported tracepoint layout"):
				t.Fatalf("error %q does not name the unsupported layout", err)
			}
		})
	}
}
