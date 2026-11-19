// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package local

import (
	"fmt"
	"testing"

	workerv1alpha1 "go.datum.net/galactic/api/galactic/worker/v1alpha1"
	"go.datum.net/galactic/internal/plumbing/ebpf/xdpmode"
	"go.datum.net/galactic/internal/worker/module"
)

// wantReady fails unless every destination of claims is Ready in st.
func wantReady(t *testing.T, st module.State, claims []module.Claim) {
	t.Helper()
	for _, c := range claims {
		for _, d := range c.Destinations {
			got, ok := st[c.Key][d.ID]
			if !ok || !got.Programmed || !got.Ready || !got.ForwardReady || !got.ReturnReady {
				t.Fatalf("%s %s = %+v (present %t), want ready", c.Key, d.ID, got, ok)
			}
		}
	}
}

// wantState fails unless claim c's only destination reports reason with
// the given programmed, forward and return readiness.
func wantState(t *testing.T, st module.State, c module.Claim, programmed, fwd, ret bool, reason string) {
	t.Helper()
	got := st[c.Key][c.Destinations[0].ID]
	if got.Programmed != programmed || got.ForwardReady != fwd || got.ReturnReady != ret || got.Reason != reason {
		t.Fatalf("%s = %+v, want programmed %t forward %t return %t reason %q", c.Key, got, programmed, fwd, ret,
			reason)
	}
}

// cells are the receiving devices and XDP modes local.tap and
// local.veth_pair are qualified on (docs/worker/qualification.md). The NAT
// end of a pair always runs native.
var cells = []struct {
	name string
	mode xdpmode.Mode
}{
	{"plain", xdpmode.Native},
	{"plain", xdpmode.Generic},
	{cellVLAN, xdpmode.Native},
	{cellVLAN, xdpmode.Generic},
	{cellBond, xdpmode.Native},
	{cellBond, xdpmode.Generic},
}

// TestEntryPathsRoot injects frames on every supported entry path and checks
// guest delivery, or a policy denial, at both VPCs' TAPs, whose guests use the
// same address: a public client through the dispatcher into local.tap and
// the guest's reply back, a guest's flow through local.veth_pair and the NAT
// stand-in to the client, and the client's reply back through the pair.
func TestEntryPathsRoot(t *testing.T) {
	for _, cell := range cells {
		t.Run(fmt.Sprintf("%s-%s", cell.name, cell.mode), func(t *testing.T) {
			r := newRig(t, cell.name+"-"+cell.mode.String(), cell.mode)
			for _, v := range r.vpcs {
				claims := r.claims(v)
				st := r.reconcile(v.vpc, claims)
				wantReady(t, st, claims[:1])
				// The pair is programmed, but its return needs the NAT
				// program on the NAT end.
				wantState(t, st, claims[1], true, true, false, workerv1alpha1.ReasonHandoffHookMissing)
				r.natStandIn(v)
				wantReady(t, r.reconcile(v.vpc, claims), claims)
				if !r.planEmpty(v.vpc, claims) {
					t.Fatalf("VPC %s: a second plan would write again", v.vpc)
				}
			}
			sock := r.clientSocket(40000)
			for _, v := range r.vpcs {
				other := r.vpcs[0]
				if other == v {
					other = r.vpcs[1]
				}
				// local.tap: the VIP's request reaches only this VPC's
				// guest, and the guest's reply from the VIP reaches the
				// client.
				req := "tap-request-" + v.vpc
				sock.send(t, v.vip, 7, req)
				got := v.guest.expect(t, req)
				if got.dst != v.vip || got.src != client {
					t.Fatalf("the guest received %s -> %s, want %s -> %s", got.src, got.dst, client, v.vip)
				}
				other.guest.absent(t, req)
				reply := "tap-reply-" + v.vpc
				v.guest.send(t, v.vip, client, 7, 40000, reply, false)
				sock.expect(t, v.vip, reply)

				// Policy on the PublicService path: port 9 is denied toward
				// the guest; port 8 is delivered, and the guest's reply from
				// it denied.
				sock.send(t, v.vip, 9, "tap-denied-in-"+v.vpc)
				v.guest.absent(t, "tap-denied-in-"+v.vpc)
				sock.send(t, v.vip, 8, "tap-open-"+v.vpc)
				v.guest.expect(t, "tap-open-"+v.vpc)
				v.guest.send(t, v.vip, client, 8, 40000, "tap-denied-out-"+v.vpc, false)
				sock.absent(t, "tap-denied-out-"+v.vpc)

				// local.veth_pair: the guest's flow leaves as the shard
				// address, and the client's reply returns to this guest
				// only.
				flow := "nat-flow-" + v.vpc
				v.guest.send(t, guestAddr, client, 5555, 40000, flow, false)
				sock.expect(t, v.shard, flow)
				back := "nat-return-" + v.vpc
				sock.send(t, v.shard, 5555, back)
				got = v.guest.expect(t, back)
				if got.dst != guestAddr || got.dport != 5555 {
					t.Fatalf("the NAT return reached the guest as %s:%d", got.dst, got.dport)
				}
				other.guest.absent(t, back)

				// Policy on the PublicNAT path: port 9 is denied both ways.
				v.guest.send(t, guestAddr, client, 5555, 9, "nat-denied-out-"+v.vpc, false)
				sock.absent(t, "nat-denied-out-"+v.vpc)
				nine := r.clientSocket(9)
				nine.send(t, v.shard, 5555, "nat-denied-in-"+v.vpc)
				v.guest.absent(t, "nat-denied-in-"+v.vpc)
				_ = nine.conn.Close()
			}
			s := r.stats()
			if s["rx_deliver"] == 0 || s["rx_deny"] == 0 || s["pair_deliver"] == 0 || s["pair_deny"] == 0 ||
				s["link_reply"] == 0 || s["link_reply_deny"] == 0 || s["link_nat"] == 0 || s["link_nat_deny"] == 0 {
				t.Fatalf("counters %v: a path was never taken", s)
			}
		})
	}
}
