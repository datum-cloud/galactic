// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package xdpdispatch

import (
	"errors"
	"os"
	"regexp"
	"strconv"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/rlimit"
)

// XDP verdicts, as the stub slot programs return them.
const (
	xdpAborted = 0
	xdpDrop    = 1
	xdpPass    = 2
	xdpTx      = 3
)

// testRunIfindex is the ingress ifindex BPF_PROG_TEST_RUN reports when the
// caller passes no context: the loopback device's.
const testRunIfindex = 1

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("test requires root (CAP_BPF/CAP_NET_ADMIN) to load BPF programs and maps; re-run via sudo")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("rlimit.RemoveMemlock: %v", err)
	}
}

// loadUnpinned loads the dispatch objects with no pinning, for tests that only
// run the root program.
func loadUnpinned(t *testing.T) *DispatchObjects {
	t.Helper()
	var objs DispatchObjects
	if err := LoadDispatchObjects(&objs, nil); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			t.Fatalf("load objects: verifier rejected program:\n%+v", ve)
		}
		t.Fatalf("load objects: %v", err)
	}
	t.Cleanup(func() { _ = objs.Close() })
	return &objs
}

// stubProgram loads a one-instruction XDP program returning verdict. Its
// attach type matches an ELF SEC("xdp") program's, as a prog array requires.
func stubProgram(t *testing.T, verdict int64) *ebpf.Program {
	t.Helper()
	p, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type:         ebpf.XDP,
		AttachType:   ebpf.AttachXDP,
		Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, int32(verdict)), asm.Return()},
		License:      "GPL",
	})
	if err != nil {
		t.Fatalf("load stub program: %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p
}

// ipv6Frame is any frame; the root never parses the packet.
func ipv6Frame() []byte {
	pkt := make([]byte, 14+40)
	pkt[12], pkt[13] = 0x86, 0xdd
	pkt[14] = 0x60
	return pkt
}

func TestXdpDispatch_RunsPermittedLiveSlotsInOrder(t *testing.T) {
	requireRoot(t)

	live := monotonicNow() + uint64(LeaseTTL)
	expired := monotonicNow() - 1

	type slotState struct {
		verdict int64 // -1: empty
		lease   uint64
	}
	filled := func(v int64) slotState { return slotState{v, live} }
	empty := slotState{-1, live}

	tests := []struct {
		name  string
		roles *uint32 // nil: no row
		slots [3]slotState
		want  uint32
	}{
		{"no role row passes", nil,
			[3]slotState{filled(xdpTx), filled(xdpAborted), filled(xdpDrop)}, xdpPass},
		{"public uplink runs the load balancer first",
			new(uint32(RolePublicLB | RoleEgress)),
			[3]slotState{filled(xdpTx), filled(xdpAborted), filled(xdpDrop)}, xdpTx},
		{"empty slot is skipped",
			new(uint32(RolePublicLB | RoleEgress)),
			[3]slotState{empty, filled(xdpAborted), filled(xdpDrop)}, xdpDrop},
		{"expired lease is skipped",
			new(uint32(RolePublicLB | RoleEgress)),
			[3]slotState{{xdpTx, expired}, filled(xdpAborted), filled(xdpDrop)}, xdpDrop},
		{"internal link runs the return program",
			new(uint32(RoleInternalReturn | RoleEgress)),
			[3]slotState{filled(xdpTx), filled(xdpAborted), filled(xdpDrop)}, xdpAborted},
		{"slot without its role bit is skipped",
			new(uint32(RoleEgress)),
			[3]slotState{filled(xdpTx), filled(xdpAborted), filled(xdpDrop)}, xdpDrop},
		{"return program never runs on a public interface",
			new(uint32(RolePublicLB | RoleInternalReturn)),
			[3]slotState{empty, filled(xdpAborted), empty}, xdpPass},
		{"nothing live passes",
			new(uint32(RolePublicLB | RoleEgress)),
			[3]slotState{empty, empty, {xdpDrop, expired}}, xdpPass},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			objs := loadUnpinned(t)
			if tt.roles != nil {
				if err := objs.IfaceRoles.Put(uint32(testRunIfindex), *tt.roles); err != nil {
					t.Fatalf("write roles: %v", err)
				}
			}
			for i, s := range tt.slots {
				if err := objs.SlotLease.Put(uint32(i), s.lease); err != nil {
					t.Fatalf("write lease %d: %v", i, err)
				}
				if s.verdict < 0 {
					continue
				}
				if err := objs.DispatchProgs.Put(uint32(i), stubProgram(t, s.verdict)); err != nil {
					t.Fatalf("fill slot %d: %v", i, err)
				}
			}
			ret, _, err := objs.XdpDispatch.Test(ipv6Frame())
			if err != nil {
				t.Fatalf("program test-run: %v", err)
			}
			if ret != tt.want {
				t.Errorf("verdict = %d, want %d", ret, tt.want)
			}
		})
	}
}

// TestConstantsMatchDispatchH holds the Go slot and role numbering to the C
// header's, since both sides read the same pinned maps.
func TestConstantsMatchDispatchH(t *testing.T) {
	src, err := os.ReadFile("dispatch.h")
	if err != nil {
		t.Fatalf("read dispatch.h: %v", err)
	}
	define := func(name string) int {
		t.Helper()
		m := regexp.MustCompile(`(?m)^#define ` + name + ` (\d+)$`).FindSubmatch(src)
		if m == nil {
			t.Fatalf("dispatch.h defines no numeric %s", name)
		}
		v, _ := strconv.Atoi(string(m[1]))
		return v
	}
	for name, want := range map[string]int{
		"XDPD_MAX_SLOTS":           NumSlots,
		"XDPD_SLOT_GATEWAY_LB":     int(SlotGatewayLB),
		"XDPD_SLOT_GATEWAY_RETURN": int(SlotGatewayReturn),
		"XDPD_SLOT_NAT":            int(SlotNAT),
	} {
		if got := define(name); got != want {
			t.Errorf("%s = %d in dispatch.h, %d in Go", name, got, want)
		}
	}
	for role, slot := range map[Role]Slot{
		RolePublicLB:       SlotGatewayLB,
		RoleInternalReturn: SlotGatewayReturn,
		RoleEgress:         SlotNAT,
	} {
		if role != 1<<slot {
			t.Errorf("role %#x is not bit %d", role, slot)
		}
	}
}
