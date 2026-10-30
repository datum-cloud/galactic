// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cnitap

import (
	"slices"
	"testing"
)

func TestHostOnlyPorts(t *testing.T) {
	for _, tc := range []struct {
		name    string
		config  string
		want    []uint16
		wantErr bool
	}{
		{name: "absent", config: `{"type":"galactic-tap"}`},
		{name: "one port", config: `{"type":"galactic-tap","hostOnlyPorts":[20000]}`, want: []uint16{20000}},
		{name: "zero", config: `{"hostOnlyPorts":[0]}`, wantErr: true},
		{name: "repeated", config: `{"hostOnlyPorts":[20000,20000]}`, wantErr: true},
		{name: "too many", config: `{"hostOnlyPorts":[1,2,3,4,5]}`, wantErr: true},
		{name: "out of range", config: `{"hostOnlyPorts":[70000]}`, wantErr: true},
		{name: "not a list", config: `{"hostOnlyPorts":"20000"}`, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := hostOnlyPorts([]byte(tc.config))
			if (err != nil) != tc.wantErr {
				t.Fatalf("hostOnlyPorts error = %v, wantErr %v", err, tc.wantErr)
			}
			if !slices.Equal(got, tc.want) {
				t.Errorf("hostOnlyPorts = %v, want %v", got, tc.want)
			}
		})
	}
}
