// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package nldump

import (
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/vishvananda/netlink"
)

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("test requires root (CAP_NET_ADMIN) to create a network namespace; re-run via sudo")
	}
}

// TestLinkList_CountsRealInterruptions lists links on a real kernel while
// other goroutines add and remove links in the same namespace. Every listing
// succeeds, and the interrupted counter records the interruptions the
// kernel reported along the way.
func TestLinkList_CountsRealInterruptions(t *testing.T) {
	requireRoot(t)
	nsObj, err := ns.TempNetNS()
	if err != nil {
		t.Fatalf("create test netns: %v", err)
	}
	t.Cleanup(func() { _ = nsObj.Close() })

	err = nsObj.Do(func(_ ns.NetNS) error {
		for i := range 300 {
			if err := netlink.LinkAdd(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: fmt.Sprintf("stab%d", i)}}); err != nil {
				return fmt.Errorf("add stable link %d: %w", i, err)
			}
		}
		return nil
	})
	if err != nil {
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
					dummy := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: fmt.Sprintf("churn%d_%d", c, i%4)}}
					if err := netlink.LinkAdd(dummy); err == nil {
						_ = netlink.LinkDel(dummy)
					}
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

	before := testutil.ToFloat64(interrupted.WithLabelValues(kindLink))
	beforeFailures := testutil.ToFloat64(failures.WithLabelValues(kindLink))
	err = nsObj.Do(func(_ ns.NetNS) error {
		// Churn interrupts a listing within a few iterations; the deadline
		// only bounds a kernel that never reports one.
		deadline := time.Now().Add(10 * time.Second)
		for i := 0; testutil.ToFloat64(interrupted.WithLabelValues(kindLink)) == before; i++ {
			if time.Now().After(deadline) {
				return fmt.Errorf("no interruption counted after %d listings under link churn", i)
			}
			if _, err := LinkList(); err != nil {
				return fmt.Errorf("LinkList failed on iteration %d while links were changing: %w", i, err)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if d := testutil.ToFloat64(failures.WithLabelValues(kindLink)) - beforeFailures; d != 0 {
		t.Errorf("failure counter rose by %v, want 0", d)
	}
}
