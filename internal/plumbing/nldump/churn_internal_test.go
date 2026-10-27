// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package nldump

import (
	"fmt"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("test requires root (CAP_NET_ADMIN) to create a network namespace; re-run via sudo")
	}
}

// churnCase is one listing kind exercised under churn: setup adds the stable
// entries the listing walks, change adds and removes one transient entry, and
// list makes one retrying listing.
type churnCase struct {
	kind   string
	setup  func() error
	change func(churner, i int)
	list   func() error
}

// TestListings_CountRealInterruptions lists each kind on a real kernel while
// other goroutines add and remove entries of that kind in the same namespace.
// Every listing succeeds, and the interrupted counter records the
// interruptions the kernel reported along the way.
func TestListings_CountRealInterruptions(t *testing.T) {
	requireRoot(t)
	var link netlink.Link
	cases := []churnCase{
		{
			kind: kindLink,
			setup: func() error {
				for i := range 300 {
					if err := netlink.LinkAdd(dummy(fmt.Sprintf("stab%d", i))); err != nil {
						return fmt.Errorf("add stable link %d: %w", i, err)
					}
				}
				return nil
			},
			change: func(c, i int) {
				d := dummy(fmt.Sprintf("churn%d_%d", c, i%4))
				if err := netlink.LinkAdd(d); err == nil {
					_ = netlink.LinkDel(d)
				}
			},
			list: func() error { _, err := LinkList(); return err },
		},
		{
			kind: kindAddress,
			setup: func() error {
				d := dummy("addr0")
				if err := netlink.LinkAdd(d); err != nil {
					return fmt.Errorf("add link: %w", err)
				}
				link = d
				for i := range 300 {
					if err := netlink.AddrAdd(link, addr(0, i)); err != nil {
						return fmt.Errorf("add stable address %d: %w", i, err)
					}
				}
				return nil
			},
			change: func(c, i int) {
				a := addr(c+1, i%4)
				if err := netlink.AddrAdd(link, a); err == nil {
					_ = netlink.AddrDel(link, a)
				}
			},
			list: func() error { _, err := AddrList(nil, netlink.FAMILY_V6); return err },
		},
	}
	for _, tc := range cases {
		t.Run(tc.kind, func(t *testing.T) { runChurn(t, tc) })
	}
}

func runChurn(t *testing.T, tc churnCase) {
	t.Helper()
	nsObj, err := ns.TempNetNS()
	if err != nil {
		t.Fatalf("create test netns: %v", err)
	}
	t.Cleanup(func() { _ = nsObj.Close() })

	if err := nsObj.Do(func(_ ns.NetNS) error { return tc.setup() }); err != nil {
		t.Fatal(err)
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup
	for c := range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = nsObj.Do(func(_ ns.NetNS) error {
				for i := 0; ; i++ {
					select {
					case <-stop:
						return nil
					default:
					}
					tc.change(c, i)
					// Bursts of changes, not a saturated loop that could
					// outlast any bounded retry.
					time.Sleep(2 * time.Millisecond)
				}
			})
		}()
	}
	t.Cleanup(func() {
		close(stop)
		wg.Wait()
	})

	before := testutil.ToFloat64(interrupted.WithLabelValues(tc.kind))
	beforeFailures := testutil.ToFloat64(failures.WithLabelValues(tc.kind))
	err = nsObj.Do(func(_ ns.NetNS) error {
		// Churn interrupts a listing within a few iterations; the deadline
		// only bounds a kernel that never reports one.
		deadline := time.Now().Add(10 * time.Second)
		for i := 0; testutil.ToFloat64(interrupted.WithLabelValues(tc.kind)) == before; i++ {
			if time.Now().After(deadline) {
				return fmt.Errorf("no interruption counted after %d listings under %s churn", i, tc.kind)
			}
			if err := tc.list(); err != nil {
				return fmt.Errorf("%s listing failed on iteration %d while entries were changing: %w", tc.kind, i, err)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if d := testutil.ToFloat64(failures.WithLabelValues(tc.kind)) - beforeFailures; d != 0 {
		t.Errorf("failure counter rose by %v, want 0", d)
	}
}

func dummy(name string) *netlink.Dummy {
	return &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name}}
}

// addr returns an IPv6 address unique per (group, i), with DAD off so it is
// usable at once.
func addr(group, i int) *netlink.Addr {
	return &netlink.Addr{
		IPNet: &net.IPNet{IP: net.ParseIP(fmt.Sprintf("fd00:%x::%x", group, i+1)), Mask: net.CIDRMask(128, 128)},
		Flags: unix.IFA_F_NODAD,
	}
}
