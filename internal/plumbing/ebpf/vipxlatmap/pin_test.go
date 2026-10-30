// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package vipxlatmap

import (
	"errors"
	"io"
	"io/fs"
	"net"
	"sync"
	"sync/atomic"
	"testing"

	"go.datum.net/galactic/internal/plumbing/ebpf/usidmap"
)

type pinTestCloser struct{ closes atomic.Int32 }

func (c *pinTestCloser) Close() error { c.closes.Add(1); return nil }

func TestPinnedTableDiscoversLateRangeMap(t *testing.T) {
	exact, ranges := newFakeTable(), newFakeTable()
	exactHandle, rangeHandle := &pinTestCloser{}, &pinTestCloser{}
	exists, opens := false, 0
	table, closer := newPinnedTable(exact, exactHandle, func() (usidmap.Table, io.Closer, error) {
		opens++
		if !exists {
			return nil, nil, fs.ErrNotExist
		}
		return ranges, rangeHandle, nil
	})
	t.Cleanup(func() {
		if err := closer.Close(); err != nil {
			t.Error(err)
		}
	})
	vip, backend := net.ParseIP("2001:db8::1"), net.ParseIP("fd00::1")
	if err := table.RegisterIngress(testBlock, 10, 1, ProtoUDP, vip, 8080, backend, 8080); err != nil {
		t.Fatal(err)
	}
	before, ok, err := table.GetIngress(testBlock, 10, 1, ProtoUDP, vip, 8080)
	if err != nil || !ok {
		t.Fatalf("legacy registration: %v %v", ok, err)
	}
	if table.SupportsPortRanges() {
		t.Fatal("missing map reported supported")
	}
	if err := table.RegisterIngressRange(testBlock, 10, 1, ProtoUDP, vip, 10000, 10127, backend); err == nil {
		t.Fatal("missing range map accepted")
	}
	exists = true
	if err := table.RegisterIngressRange(testBlock, 10, 1, ProtoUDP, vip, 10000, 10127, backend); err != nil {
		t.Fatal(err)
	}
	if err := table.RegisterEgressRange(testBlock, 10, ProtoUDP, backend, 10000, 10127, vip); err != nil {
		t.Fatal(err)
	}
	present, err := table.RangeBindingPresent(testBlock, 10, 1, ProtoUDP, vip, 10000, 10127, backend)
	if err != nil || !present {
		t.Fatalf("range: %v %v", present, err)
	}
	opened := opens
	if !table.SupportsPortRanges() || opens != opened {
		t.Fatal("discovered map was not retained")
	}
	after, ok, err := table.GetIngress(testBlock, 10, 1, ProtoUDP, vip, 8080)
	if err != nil || !ok || after.Generation != before.Generation {
		t.Fatalf("exact ledger changed: %+v %v", after, err)
	}
	if err := table.RegisterIngress(testBlock, 10, 1, ProtoUDP, vip, 10001, backend, 10001); err == nil {
		t.Fatal("singleton did not consult newly discovered range")
	}
	if err := closer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := closer.Close(); err != nil {
		t.Fatal(err)
	}
	if exactHandle.closes.Load() != 1 || rangeHandle.closes.Load() != 1 {
		t.Fatal("handles were not closed exactly once")
	}
}

func TestPinnedRangeDiscoveryConcurrentAndClosed(t *testing.T) {
	for _, closeFirst := range []bool{false, true} {
		t.Run(map[bool]string{false: "concurrent", true: "already-closed"}[closeFirst], func(t *testing.T) {
			exactHandle, rangeHandle := &pinTestCloser{}, &pinTestCloser{}
			var opens atomic.Int32
			table, closer := newPinnedTable(newFakeTable(), exactHandle, func() (usidmap.Table, io.Closer, error) {
				opens.Add(1)
				return newFakeTable(), rangeHandle, nil
			})
			if closeFirst {
				if err := closer.Close(); err != nil {
					t.Fatal(err)
				}
			}
			var wg sync.WaitGroup
			for range 16 {
				wg.Go(func() {
					if got := table.SupportsPortRanges(); got == closeFirst {
						t.Errorf("support=%v closed=%v", got, closeFirst)
					}
				})
			}
			wg.Wait()
			if err := closer.Close(); err != nil {
				t.Fatal(err)
			}
			want := int32(1)
			if closeFirst {
				want = 0
			}
			if opens.Load() != want || rangeHandle.closes.Load() != want || exactHandle.closes.Load() != 1 {
				t.Fatalf("opens=%d range closes=%d exact closes=%d",
					opens.Load(), rangeHandle.closes.Load(), exactHandle.closes.Load())
			}
		})
	}
}

func TestPinnedRangeOpenFailureRetries(t *testing.T) {
	sentinel := errors.New("range pin denied")
	failure := true
	table, closer := newPinnedTable(newFakeTable(), &pinTestCloser{}, func() (usidmap.Table, io.Closer, error) {
		if failure {
			return nil, nil, sentinel
		}
		return newFakeTable(), &pinTestCloser{}, nil
	})
	defer func() {
		if err := closer.Close(); err != nil {
			t.Error(err)
		}
	}()
	if _, err := table.ListRanges(); !errors.Is(err, sentinel) {
		t.Fatalf("open error lost: %v", err)
	}
	failure = false
	if !table.SupportsPortRanges() {
		t.Fatal("open failure was cached")
	}
}

func TestPinnedRangeCloseDuringDiscovery(t *testing.T) {
	exactHandle, rangeHandle := &pinTestCloser{}, &pinTestCloser{}
	entered, release := make(chan struct{}), make(chan struct{})
	table, closer := newPinnedTable(newFakeTable(), exactHandle, func() (usidmap.Table, io.Closer, error) {
		close(entered)
		<-release
		return newFakeTable(), rangeHandle, nil
	})
	discovered, closed := make(chan struct{}), make(chan error, 1)
	go func() { table.SupportsPortRanges(); close(discovered) }()
	<-entered
	go func() { closed <- closer.Close() }()
	close(release)
	<-discovered
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	if exactHandle.closes.Load() != 1 || rangeHandle.closes.Load() != 1 {
		t.Fatal("in-flight discovery leaked a handle")
	}
}
