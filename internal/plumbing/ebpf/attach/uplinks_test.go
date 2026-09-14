// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package attach

import (
	"errors"
	"testing"
	"time"

	"github.com/vishvananda/netlink"

	"go.datum.net/galactic/internal/config"
)

// testIfaceEth2 is a second fabric uplink, for the multi-homed cases here.
// testIfaceMissing is named but absent from the host.
const (
	testIfaceEth2    = "eth2"
	testIfaceMissing = "eth9"
)

// stubUplinkLinks makes ResolveInterfaces take its override path, naming the
// given interfaces, and resolves each to the ifindex the map says. An
// interface named but absent from the map fails to resolve, standing in for
// one that has gone away since.
func stubUplinkLinks(t *testing.T, names string, indexes map[string]int) {
	t.Helper()
	t.Setenv(config.EnvCNIEBPFInterfaces, names)

	prevByName := linkByNameFn
	linkByNameFn = func(name string) (netlink.Link, error) {
		idx, ok := indexes[name]
		if !ok {
			return nil, errors.New("no such device: " + name)
		}
		return &fakeLink{attrs: netlink.LinkAttrs{Name: name, Index: idx}}, nil
	}
	prevList := linkListFn
	linkListFn = func() ([]netlink.Link, error) { return nil, nil }

	t.Cleanup(func() {
		linkByNameFn = prevByName
		linkListFn = prevList
		InvalidateUplinkIndexes()
	})
	InvalidateUplinkIndexes()
}

func TestUplinkIndexesResolvesEveryNamedInterface(t *testing.T) {
	stubUplinkLinks(t, testIfaceEth1+","+testIfaceEth2, map[string]int{testIfaceEth1: 1060, testIfaceEth2: 1061})

	got, err := UplinkIndexes()
	if err != nil {
		t.Fatalf("UplinkIndexes() = %v, want success", err)
	}
	for _, want := range []int{1060, 1061} {
		if _, ok := got[want]; !ok {
			t.Errorf("UplinkIndexes() = %v, want it to contain ifindex %d", got, want)
		}
	}
	// The management interface is deliberately not in the resolved set: that
	// exclusion is the whole point of this lookup.
	if _, ok := got[2]; ok {
		t.Errorf("UplinkIndexes() = %v, want it not to contain the management ifindex 2", got)
	}
}

func TestUplinkIndexesSkipsAnInterfaceThatNoLongerExists(t *testing.T) {
	stubUplinkLinks(t, testIfaceEth1+","+testIfaceMissing, map[string]int{testIfaceEth1: 1060})

	got, err := UplinkIndexes()
	if err != nil {
		t.Fatalf("UplinkIndexes() = %v, want success when one named interface is gone", err)
	}
	if len(got) != 1 {
		t.Errorf("UplinkIndexes() = %v, want only the one interface that still exists", got)
	}
}

// TestUplinkIndexesFailsWhenNoneExist: an empty set would be indistinguishable
// from "accept every link", which is the behavior this whole lookup guards
// against.
func TestUplinkIndexesFailsWhenNoneExist(t *testing.T) {
	stubUplinkLinks(t, testIfaceMissing, map[string]int{})

	if _, err := UplinkIndexes(); err == nil {
		t.Fatal("UplinkIndexes() = nil error, want a failure when no resolved uplink exists")
	}
}

func TestUplinkIndexesServesTheCacheUntilItExpires(t *testing.T) {
	stubUplinkLinks(t, testIfaceEth1, map[string]int{testIfaceEth1: 1060})

	calls := 0
	prev := linkByNameFn
	linkByNameFn = func(name string) (netlink.Link, error) {
		calls++
		return prev(name)
	}
	t.Cleanup(func() { linkByNameFn = prev })

	if _, err := UplinkIndexes(); err != nil {
		t.Fatalf("first UplinkIndexes() = %v, want success", err)
	}
	// A resolve touches netlink more than once; what matters is whether it
	// happened at all, so compare against the count after the first call
	// rather than against a fixed number.
	afterFirst := calls
	if afterFirst == 0 {
		t.Fatal("first UplinkIndexes() touched netlink 0 times, want it to have resolved")
	}

	if _, err := UplinkIndexes(); err != nil {
		t.Fatalf("second UplinkIndexes() = %v, want success", err)
	}
	if calls != afterFirst {
		t.Errorf("second UplinkIndexes() resolved again (%d -> %d netlink calls), want it served from cache",
			afterFirst, calls)
	}

	// Past the TTL it resolves again, so an interface that appears is picked
	// up without waiting for a netlink event.
	prevNow := uplinkIndexNow
	uplinkIndexNow = func() time.Time { return time.Now().Add(2 * uplinkIndexCacheTTL) }
	t.Cleanup(func() { uplinkIndexNow = prevNow })

	if _, err := UplinkIndexes(); err != nil {
		t.Fatalf("third UplinkIndexes() = %v, want success", err)
	}
	if calls == afterFirst {
		t.Errorf("UplinkIndexes() still served the cache after the TTL expired (%d netlink calls)", calls)
	}
}

func TestInvalidateUplinkIndexesForcesAFreshResolve(t *testing.T) {
	stubUplinkLinks(t, testIfaceEth1, map[string]int{testIfaceEth1: 1060})

	calls := 0
	prev := linkByNameFn
	linkByNameFn = func(name string) (netlink.Link, error) {
		calls++
		return prev(name)
	}
	t.Cleanup(func() { linkByNameFn = prev })

	if _, err := UplinkIndexes(); err != nil {
		t.Fatalf("UplinkIndexes() = %v, want success", err)
	}
	afterFirst := calls
	InvalidateUplinkIndexes()
	if _, err := UplinkIndexes(); err != nil {
		t.Fatalf("UplinkIndexes() after invalidate = %v, want success", err)
	}
	if calls == afterFirst {
		t.Errorf("UplinkIndexes() served the cache after InvalidateUplinkIndexes (%d netlink calls)", calls)
	}
}
