// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package local

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"

	workerv1alpha1 "go.datum.net/galactic/api/galactic/worker/v1alpha1"
	"go.datum.net/galactic/internal/plumbing/ebpf/xdpmode"
)

// attachClusterCNI attaches, through tcx, an ingress program on ifname that
// ends every packet's ingress with TC_ACT_OK, as a cluster CNI such as
// Cilium does on the bond master it is pinned to. The kernel runs tcx
// programs before every clsact filter, so no clsact filter on ifname sees a
// packet after it.
func (r *rig) attachClusterCNI(ifname string) {
	r.t.Helper()
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type: ebpf.SchedCLS, License: "GPL",
		Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 0), asm.Return()},
	})
	if err != nil {
		r.t.Fatalf("load the cluster CNI stand-in: %v", err)
	}
	r.t.Cleanup(func() { _ = prog.Close() })
	r.in(r.node, func() error {
		l, err := netlink.LinkByName(ifname)
		if err != nil {
			return err
		}
		tl, err := link.AttachTCX(link.TCXOptions{Interface: l.Attrs().Index, Program: prog,
			Attach: ebpf.AttachTCXIngress})
		if err != nil {
			return err
		}
		r.t.Cleanup(func() { _ = tl.Close() })
		return nil
	})
}

// TestTapHandoffBehindClusterCNIOnBondRoot is #1438's lab failure on a bond:
// a cluster CNI's tcx program on the bond master ends ingress before every
// clsact filter. local_rx runs on the bond's members, ahead of the master,
// so a public client's request still reaches the TAP guest and its reply the
// client. With local_rx on the master, as before, it never ran, and the
// packet went to the node's own stack. A foreign tcx program on a member,
// ahead of local_rx itself, is reported as HandoffHookMissing.
func TestTapHandoffBehindClusterCNIOnBondRoot(t *testing.T) {
	for _, mode := range []xdpmode.Mode{xdpmode.Native, xdpmode.Generic} {
		t.Run(mode.String(), func(t *testing.T) {
			r := newRig(t, cellBond, mode)
			r.attachClusterCNI(bondName)
			v := r.vpcs[0]
			claims := r.claims(v)[:1]
			wantReady(t, r.reconcile(v.vpc, claims), claims)

			sock := r.clientSocket(40000)
			req := "behind-cni-" + v.vpc
			sock.send(t, v.vip, 7, req)
			got := v.guest.expect(t, req)
			if got.dst != v.vip || got.src != client {
				t.Fatalf("the guest received %s -> %s, want %s -> %s", got.src, got.dst, client, v.vip)
			}
			v.guest.send(t, v.vip, client, 7, 40000, "behind-cni-reply", false)
			sock.expect(t, v.vip, "behind-cni-reply")
			if s := r.stats(); s["rx_deliver"] == 0 {
				t.Fatalf("counters %v: local_rx delivered nothing", s)
			}

			// A program ahead of local_rx on a member hides it.
			r.attachClusterCNI(r.hooks[0])
			wantState(t, r.read(v.vpc), claims[0], true, false, true, workerv1alpha1.ReasonHandoffHookMissing)
		})
	}
}
