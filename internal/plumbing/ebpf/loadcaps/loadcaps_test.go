// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package loadcaps

import (
	"errors"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/rlimit"
)

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("test requires root to reduce capabilities from; re-run via sudo")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("rlimit.RemoveMemlock: %v", err)
	}
}

// TestRun_EnforcesUnprivilegedVerifierRules proves the restricted thread
// reaches the verifier's reduced ruleset. Without this control, a kernel or
// runner that ignored the capability drop would let every load test pass
// vacuously.
func TestRun_EnforcesUnprivilegedVerifierRules(t *testing.T) {
	requireRoot(t)

	// The two cases differ only by PERFMON, so a rejection can only come from
	// that capability.
	withoutPerfmon := []string{"BPF", "NET_ADMIN", "NET_RAW"}
	tests := []struct {
		name       string
		caps       []string
		wantReject bool
	}{
		{"WithoutPerfmon", withoutPerfmon, true},
		{"WithPerfmon", append(slices.Clone(withoutPerfmon), "PERFMON"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Run(tt.caps, loadVariablePacketOffsetProgram)
			var ve *ebpf.VerifierError
			switch {
			case tt.wantReject && !errors.As(err, &ve):
				t.Fatalf("load with %v: got %v, want a verifier rejection", tt.caps, err)
			case tt.wantReject && !strings.Contains(strings.Join(ve.Log, "\n"), "prohibited for !root"):
				t.Fatalf("load with %v: verifier rejected for another reason:\n%+v", tt.caps, ve)
			case !tt.wantReject && err != nil:
				t.Fatalf("load with %v: %+v", tt.caps, err)
			}
		})
	}
}

// loadVariablePacketOffsetProgram loads a tc program that advances a packet
// pointer by a bounded but variable offset, which only a loader with
// CAP_PERFMON may do.
func loadVariablePacketOffsetProgram() error {
	const skbLenOff, skbDataOff = 0, 76
	p, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type:    ebpf.SchedCLS,
		License: "GPL",
		Instructions: asm.Instructions{
			asm.LoadMem(asm.R2, asm.R1, skbDataOff, asm.Word),
			asm.LoadMem(asm.R3, asm.R1, skbLenOff, asm.Word),
			asm.And.Imm(asm.R3, 0x3c),
			asm.Add.Reg(asm.R2, asm.R3),
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
	})
	if err != nil {
		return err
	}
	return p.Close()
}
