// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package installer

import (
	"context"
	"errors"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"

	"go.datum.net/galactic/internal/plumbing/ebpf/egressroutemap"
	"go.datum.net/galactic/internal/plumbing/ebpf/usidmap"
)

// uplinkTable is an in-memory public_uplink_table.
type uplinkTable map[any]any

func (m uplinkTable) Put(key, value any) error { m[key] = value; return nil }

func (m uplinkTable) Lookup(key, out any) error {
	v, ok := m[key]
	if !ok {
		return ebpf.ErrKeyNotExist
	}
	reflect.ValueOf(out).Elem().Set(reflect.ValueOf(v))
	return nil
}

func (m uplinkTable) Delete(key any) error { delete(m, key); return nil }

func (m uplinkTable) Iterate() usidmap.Iterator { panic("not used") }

// TestRefreshPublicUplink: a row never written stays unwritten, a row whose
// uplink lost its carrier moves to the uplink resolved now, and a pass that
// resolves nothing keeps the row it has.
func TestRefreshPublicUplink(t *testing.T) {
	uplink := egressroutemap.NewPublicUplink(uplinkTable{})
	smac := net.HardwareAddr{0xbb, 0, 0, 0, 0, 1}
	first := net.HardwareAddr{0xaa, 0, 0, 0, 0, 1}
	second := net.HardwareAddr{0xaa, 0, 0, 0, 0, 2}
	resolveTo := func(index int, dmac net.HardwareAddr, err error) func() (int, net.HardwareAddr,
		net.HardwareAddr, error,
	) {
		return func() (int, net.HardwareAddr, net.HardwareAddr, error) { return index, dmac, smac, err }
	}

	if changed, err := refreshPublicUplink(uplink, resolveTo(4, second, nil)); changed || err != nil {
		t.Fatalf("refresh of an unwritten row = %v, %v; want no write", changed, err)
	}
	if _, _, _, ok, _ := uplink.Get(); ok {
		t.Fatal("refresh wrote a row CNI ADD never wrote")
	}

	if err := uplink.Set(3, first, smac); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if changed, err := refreshPublicUplink(uplink, resolveTo(3, first, nil)); changed || err != nil {
		t.Errorf("refresh with the same uplink = %v, %v; want no write", changed, err)
	}
	if changed, err := refreshPublicUplink(uplink, resolveTo(4, second, nil)); !changed || err != nil {
		t.Errorf("refresh after the first uplink went = %v, %v; want a write", changed, err)
	}
	if changed, err := refreshPublicUplink(uplink, resolveTo(0, nil, errors.New("no carrier"))); changed ||
		err == nil {
		t.Errorf("refresh with nothing resolvable = %v, %v; want an error and no write", changed, err)
	}
	index, dmac, _, _, err := uplink.Get()
	if err != nil || index != 4 || dmac.String() != second.String() {
		t.Errorf("public_uplink_table = %d %s (err %v), want 4 %s", index, dmac, err, second)
	}
}

// TestWatchPublicUplinkOnce_SignalsOnLinkAndIPv6NeighborChanges: an uplink
// losing carrier shows as a link update and a lost neighbor as an IPv6
// neighbor update, and each must refresh the row; IPv4 neighbors cannot move
// it.
func TestWatchPublicUplinkOnce_SignalsOnLinkAndIPv6NeighborChanges(t *testing.T) {
	links := make(chan chan<- netlink.LinkUpdate, 1)
	neighs := make(chan chan<- netlink.NeighUpdate, 1)
	origLink, origNeigh := publicUplinkLinkSubscribe, publicUplinkNeighSubscribe
	t.Cleanup(func() { publicUplinkLinkSubscribe, publicUplinkNeighSubscribe = origLink, origNeigh })
	publicUplinkLinkSubscribe = func(ch chan<- netlink.LinkUpdate, _ <-chan struct{},
		_ netlink.LinkSubscribeOptions,
	) error {
		links <- ch
		return nil
	}
	publicUplinkNeighSubscribe = func(ch chan<- netlink.NeighUpdate, _ <-chan struct{},
		_ netlink.NeighSubscribeOptions,
	) error {
		neighs <- ch
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	trigger := make(chan struct{}, 1)
	done := make(chan error, 1)
	go func() { done <- watchPublicUplinkOnce(ctx, trigger) }()
	linkCh, neighCh := <-links, <-neighs

	expect := func(name string, want bool) {
		t.Helper()
		select {
		case <-trigger:
			if !want {
				t.Errorf("%s signalled a refresh, want none", name)
			}
		case <-time.After(100 * time.Millisecond):
			if want {
				t.Errorf("%s did not signal a refresh", name)
			}
		}
	}
	neighCh <- netlink.NeighUpdate{Neigh: netlink.Neigh{Family: netlink.FAMILY_V4}}
	expect("an IPv4 neighbor change", false)
	neighCh <- netlink.NeighUpdate{Neigh: netlink.Neigh{Family: netlink.FAMILY_V6}}
	expect("an IPv6 neighbor change", true)
	linkCh <- netlink.LinkUpdate{Link: &netlink.Bond{}}
	expect("a link change", true)

	cancel()
	if err := <-done; err != nil {
		t.Errorf("watchPublicUplinkOnce = %v, want nil once ctx ends", err)
	}
}
