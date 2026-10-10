// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package egressroutemap

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cilium/ebpf"

	"go.datum.net/galactic/internal/plumbing/ebpf/prog"
	"go.datum.net/galactic/internal/plumbing/ebpf/uformat"
)

// These run usid_egress under BPF_PROG_RUN against snapshots published through
// the real egress_shard_groups ARRAY_OF_MAPS.

var errBoundary = errors.New("injected failure at a publication boundary")

// failAt makes dp's store fail one publication at boundary ("create", "write"
// or "swap"), then behave normally again.
func (dp *datapath) failAt(boundary string) {
	real := NewKernelGroupStore(dp.objs.EgressShardGroups)
	once := true
	pass := func() bool {
		if once {
			once = false
			return false
		}
		return true
	}
	switch boundary {
	case "create":
		dp.store.newMap = func(spec *ebpf.MapSpec) (*ebpf.Map, error) {
			if !pass() {
				return nil, errBoundary
			}
			return real.newMap(spec)
		}
	case "write":
		dp.store.writeInner = func(inner *ebpf.Map, v *prog.UsidEgressShardGroupValue) error {
			if !pass() {
				return errBoundary
			}
			return real.writeInner(inner, v)
		}
	case "swap":
		dp.store.swap = func(outer *ebpf.Map, id uint32, inner *ebpf.Map) error {
			if !pass() {
				return errBoundary
			}
			return real.swap(outer, id, inner)
		}
	}
}

// TestGroupPublication_FailedPublicationIsInvisible reproduces the review's
// F05 sequence against the kernel at every publication boundary. A occupies
// slot 0 and a tenant is pinned to it. Replacing A with B fails, so packets
// keep seeing A and the pin keeps holding. C then replaces B and is published:
// the pin must be refused, since C's generation is neither A's nor the one B
// was allocated, and the tenant is placed on C afresh.
func TestGroupPublication_FailedPublicationIsInvisible(t *testing.T) {
	for _, boundary := range []string{"create", "write", "swap"} {
		t.Run(boundary, func(t *testing.T) {
			dp := loadDatapath(t)
			a, b, c := shardSID(0x10), shardSID(0x11), shardSID(0x12)
			reachable(t, a, b, c)
			policy := GroupPolicy{PinIdle: time.Hour}
			pkt := udp6(tenant(1), internet, 1, 1)

			dp.apply(t, policy, candidates(nil, a))
			if _, got, _ := dp.send(t, pkt); got != a {
				t.Fatalf("pinned to %s, want %s", got, a)
			}

			dp.failAt(boundary)
			rb, err := dp.groups.Apply(NAT66ShardGroup, policy, candidates(nil, b))
			if !errors.Is(err, errBoundary) {
				t.Fatalf("Apply(B) = %v, want the injected %s failure", err, boundary)
			}
			if _, got, _ := dp.send(t, pkt); got != a {
				t.Errorf("after the failed publication the tenant went to %s, want A, still published", got)
			}
			if got := stat(t, dp.objs.EgressShardStats, prog.EgressShardStatPinHit); got != 1 {
				t.Errorf("pin_hit = %d, want 1: the pin to A holds while A stays published", got)
			}

			rc := dp.apply(t, policy, candidates(nil, c))
			if slotOf(t, rc, c).Generation == slotOf(t, rb, b).Generation {
				t.Fatalf("C reused B's allocated generation %d", slotOf(t, rc, c).Generation)
			}
			if _, got, _ := dp.send(t, pkt); got != c {
				t.Errorf("after C was published the tenant went to %s, want C", got)
			}
			if got := stat(t, dp.objs.EgressShardStats, prog.EgressShardStatPinStale); got != 1 {
				t.Errorf("pin_stale = %d, want 1: A's pin must be refused for C", got)
			}
		})
	}
}

// TestGroupPublication_RestartKeepsPins checks that a galactic-cni restart,
// which rebuilds the group from the published snapshot, keeps every member's
// generation and so every pin.
func TestGroupPublication_RestartKeepsPins(t *testing.T) {
	dp := loadDatapath(t)
	a, b := shardSID(0x10), shardSID(0x11)
	reachable(t, a, b)
	policy := GroupPolicy{PinIdle: time.Hour}
	dp.apply(t, policy, candidates(nil, a, b))
	pkt := udp6(tenant(3), internet, 1, 1)
	_, first, _ := dp.send(t, pkt)

	restarted := NewShardGroupTable(NewKernelGroupStore(dp.objs.EgressShardGroups))
	result, err := restarted.Apply(NAT66ShardGroup, policy, candidates(nil, a, b))
	if err != nil {
		t.Fatal(err)
	}
	if result.Changed {
		t.Errorf("rebuild after restart published a new snapshot: %+v", result.Shards)
	}
	if _, again, _ := dp.send(t, pkt); again != first {
		t.Errorf("after restart the tenant went to %s, want %s", again, first)
	}
	if got := stat(t, dp.objs.EgressShardStats, prog.EgressShardStatPinHit); got != 1 {
		t.Errorf("pin_hit = %d, want 1", got)
	}
}

// TestGroupPublication_ClassesIsolateTranslation checks that a route's group
// decides which shards can be chosen: NAT64 traffic is placed only on the
// NAT64 group's members, never on a shard that serves only NAT66.
func TestGroupPublication_ClassesIsolateTranslation(t *testing.T) {
	dp := loadDatapath(t)
	nat66Only, dual := shardSID(0x10), shardSID(0x11)
	reachable(t, nat66Only, dual)
	if _, err := dp.groups.Apply(NAT66ShardGroup, GroupPolicy{}, candidates(nil, nat66Only, dual)); err != nil {
		t.Fatal(err)
	}
	if _, err := dp.groups.Apply(1, GroupPolicy{Class: NAT64Class(nsp), Ineligible: 1},
		candidates(nil, dual)); err != nil {
		t.Fatal(err)
	}
	if err := dp.routes.RegisterGroup(dpTableID, nspNet(), 1, dpArgument); err != nil {
		t.Fatal(err)
	}

	sawNAT66Only := false
	for i := range 200 {
		dst := netip.AddrFrom16(nsp.Addr().As16())
		b := dst.As16()
		b[15] = byte(i)
		_, got, _ := dp.send(t, udp6(tenant(i), netip.AddrFrom16(b), 1, 53))
		if got != dual {
			t.Fatalf("NAT64 traffic from %s went to %s, want only %s", tenant(i), got, dual)
		}
		if _, g66, _ := dp.send(t, udp6(tenant(i), internet, 1, 53)); g66 == nat66Only {
			sawNAT66Only = true
		}
	}
	if !sawNAT66Only {
		t.Error("NAT66 traffic never used the NAT66-only shard, want it in the NAT66 group")
	}
}

// TestGroupPublication_ConcurrentSwapsStayCoherent publishes two snapshots
// alternately, replacing the only member of slot 0 each time with a shard
// whose next hop differs, while packets run through usid_egress on other
// CPUs. Every packet must leave with one snapshot's SID and that same
// snapshot's MAC addresses. An in-place update of an ordinary array value can
// mix the two; a swapped immutable snapshot cannot.
func TestGroupPublication_ConcurrentSwapsStayCoherent(t *testing.T) {
	dp := loadDatapath(t)
	a, b := shardSID(0x21), shardSID(0x22)
	// Each shard's next hop names it: its MACs end in its Node-ID byte.
	prev := resolveLinkAndL2Fn
	resolveLinkAndL2Fn = func(sid net.IP) (int, net.HardwareAddr, net.HardwareAddr, error) {
		addr, _ := netip.AddrFromSlice(sid)
		id, _ := uformat.NodeID(addr.Unmap())
		return 1, net.HardwareAddr{0xAA, 0, 0, 0, 0, byte(id)}, net.HardwareAddr{0xBB, 0, 0, 0, 0, byte(id)}, nil
	}
	t.Cleanup(func() { resolveLinkAndL2Fn = prev })
	dp.apply(t, GroupPolicy{}, candidates(nil, a))

	const swaps = 400
	var (
		stop                     atomic.Bool
		wg                       sync.WaitGroup
		mixed, seenA, seenB, all atomic.Int64
	)
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			pkt := udp6(tenant(5), internet, 1, 1)
			for !stop.Load() {
				ret, out, err := dp.objs.UsidEgress.Test(pkt)
				if err != nil || ret != tcActRedirect || len(out) < ethLen+ip6Len {
					continue
				}
				all.Add(1)
				dst, _ := netip.AddrFromSlice(out[ethLen+24 : ethLen+40])
				id, _ := uformat.NodeID(dst)
				switch {
				case out[5] != byte(id) || out[11] != byte(id):
					mixed.Add(1)
				case id == 0x21:
					seenA.Add(1)
				case id == 0x22:
					seenB.Add(1)
				}
			}
		}()
	}
	for i := range swaps {
		next := a
		if i%2 == 0 {
			next = b
		}
		if _, err := dp.groups.Apply(NAT66ShardGroup, GroupPolicy{}, candidates(nil, next)); err != nil {
			stop.Store(true)
			wg.Wait()
			t.Fatal(err)
		}
	}
	stop.Store(true)
	wg.Wait()

	t.Logf("%d packets across %d swaps: %d on A, %d on B, %d mixed", all.Load(), swaps, seenA.Load(), seenB.Load(),
		mixed.Load())
	if mixed.Load() != 0 {
		t.Errorf("%d packets left with one shard's SID and another's MACs", mixed.Load())
	}
	if seenA.Load() == 0 || seenB.Load() == 0 {
		t.Errorf("packets saw A %d times and B %d times: the swaps did not interleave with packets, the test proved "+
			"nothing", seenA.Load(), seenB.Load())
	}
}
