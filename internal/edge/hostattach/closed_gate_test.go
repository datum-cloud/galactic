// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package hostattach

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/vishvananda/netlink"

	"go.datum.net/galactic/internal/plumbing/ebpf/attachreg"
	"go.datum.net/galactic/internal/plumbing/ebpf/egressroutemap"
	"go.datum.net/galactic/internal/plumbing/vrf"
)

// shardLink is node Y's stand-in for an egress shard: every packet X
// encapsulates toward the shard SID leaves Y through it, and is counted.
const shardLink = "shard0"

// TestClosedGateNeverReachesShard runs a same-node workload's traffic to an
// edge prefix through the real uSID datapath while VPC A sends unknown
// destinations to an egress shard. With the prefix held by the edge
// attachment, it reaches the site while the gate is open and, once the gate
// closes and its host route goes, is dropped on the node and never reaches
// the shard. Without the edge's local entry the same packets reach the
// shard, the public egress path.
func TestClosedGateNeverReachesShard(t *testing.T) {
	requireRoot(t)
	f := newDatapathFixture(t)
	att := f.atts[pod3A]
	link := f.results[pod3A].HostIndex
	own := netip.PrefixFrom(att.Address, 128)
	shardSID := sid(t, dpNodeY, 0x1ff)

	f.y.do(t, func() error {
		if err := netlink.LinkAdd(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: shardLink}}); err != nil {
			return err
		}
		dummy, err := netlink.LinkByName(shardLink)
		if err != nil {
			return err
		}
		if err := netlink.LinkSetUp(dummy); err != nil {
			return err
		}
		return netlink.RouteReplace(&netlink.Route{LinkIndex: dummy.Attrs().Index,
			Dst: prefixNet(netip.PrefixFrom(shardSID, 128))})
	})
	shardPackets := func() uint64 {
		t.Helper()
		var n uint64
		f.y.do(t, func() error {
			l, err := netlink.LinkByName(shardLink)
			if err != nil {
				return err
			}
			n = l.Attrs().Statistics.TxPackets
			return nil
		})
		return n
	}

	// VPC A's ::/0 goes to the shard, and the site prefix has only the
	// entry galactic-edge keeps for it, not the workload-style one the
	// fixture registered.
	var table uint32
	f.x.do(t, func() error {
		var err error
		if table, err = vrf.TableID(vpcA); err != nil {
			return err
		}
		routes, closer, err := egressroutemap.OpenPinnedEgressRouteTable(f.pinDir)
		if err != nil {
			return err
		}
		defer func() { _ = closer.Close() }()
		if err := routes.Unregister(table, prefixNet(sitePrefix)); err != nil {
			return err
		}
		if err := routes.Register(table, egressroutemap.DefaultPrefix, shardSID.AsSlice()); err != nil {
			return err
		}
		return attachreg.SyncHostLinkRoutes(f.pinDir, table, []netip.Prefix{own, sitePrefix})
	})

	before := shardPackets()
	if err := ping(f.wlXA, siteHost, 128); err != nil {
		t.Fatalf("same-node workload to the site while its host route is up: %v", err)
	}

	// The gate closes: the agent prunes the prefix's host route and keeps
	// the local entry while the route is accepted here.
	f.x.do(t, func() error {
		h, err := f.xH.netlink()
		if err != nil {
			return err
		}
		defer func() { _ = h.Close() }()
		return pruneRoutes(h, link, table, []installed{{dst: own}})
	})
	echoes := f.tunA.echoes.Load()
	for range 3 {
		if err := ping(f.wlXA, siteHost, 128); !errors.Is(err, errNoReply) && !errors.Is(err, errUnreachable) {
			t.Fatalf("same-node workload to the site through a closed gate: %v, want it dropped", err)
		}
	}
	if got := f.tunA.echoes.Load(); got != echoes {
		t.Fatalf("site answered %d requests through a closed gate", got-echoes)
	}
	if got := shardPackets(); got != before {
		t.Fatalf("%d packets for a closed edge prefix reached the egress shard", got-before)
	}

	// Without the local entry the closed prefix falls to ::/0: this is the
	// path the entry keeps it off.
	f.x.do(t, func() error {
		return attachreg.SyncHostLinkRoutes(f.pinDir, table, []netip.Prefix{own})
	})
	_ = ping(f.wlXA, siteHost, 128)
	if got := shardPackets(); got == before {
		t.Fatal("with no local entry, the closed prefix did not reach the shard: the check above proves nothing")
	}
}
