// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package nldumptest drives netlink listings through kernel interruptions in
// tests: it churns links and addresses in a network namespace and repeats a
// pass until the kernel has interrupted the listings it makes.
package nldumptest

import (
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"go.datum.net/galactic/internal/plumbing/nldump"
)

// Listing kinds, the kind label values of nldump's counters.
const (
	KindLink    = "link"
	KindAddress = "address"
)

// stableLinks is how many links, each with an address, Churn adds before it
// starts. The kernel only flags a dump interrupted when it spans several
// reads, which a handful of links or addresses never does.
const stableLinks = 300

// Churn adds stableLinks dummy links with an address each to netns, then adds and removes links
// carrying an address there until the test ends, so link and address
// listings in netns are interrupted. Link names start with "nlchurn", which
// no Galactic interface name matches.
func Churn(t testing.TB, netns ns.NetNS) {
	t.Helper()
	err := netns.Do(func(ns.NetNS) error {
		for i := range stableLinks {
			d := dummy(fmt.Sprintf("nlchurns%d", i))
			if err := netlink.LinkAdd(d); err != nil {
				return fmt.Errorf("add stable link %d: %w", i, err)
			}
			if err := netlink.AddrAdd(d, churnAddr(0xff, i)); err != nil {
				return fmt.Errorf("add stable address %d: %w", i, err)
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
			_ = netns.Do(func(ns.NetNS) error {
				for i := 0; ; i++ {
					select {
					case <-stop:
						return nil
					default:
					}
					d := dummy(fmt.Sprintf("nlchurn%d_%d", c, i%4))
					if err := netlink.LinkAdd(d); err == nil {
						_ = netlink.AddrAdd(d, churnAddr(c, i%4))
						_ = netlink.LinkDel(d)
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
}

// UntilInterrupted runs pass in netns at least minPasses times and until
// nldump has counted an interrupted listing of every kind in kinds since the
// call. It fails the test if any pass returns an error, if nldump counts a
// failed listing, if no interruption of some kind arrives within 10 seconds,
// or if the passes take longer than 2 minutes in all. A pass makes several
// listings and only some are interrupted, so minPasses keeps every listing it
// makes under churn long enough to meet an interruption. It returns how many
// passes ran.
func UntilInterrupted(t testing.TB, netns ns.NetNS, kinds []string, minPasses int, pass func() error) int {
	t.Helper()
	interruptedBefore := counts(t, "galactic_netlink_dump_interrupted_total")
	failuresBefore := counts(t, "galactic_netlink_dump_failures_total")
	pending := func() []string {
		now := counts(t, "galactic_netlink_dump_interrupted_total")
		var out []string
		for _, k := range kinds {
			if now[k] == interruptedBefore[k] {
				out = append(out, k)
			}
		}
		return out
	}

	passes := 0
	err := netns.Do(func(ns.NetNS) error {
		start := time.Now()
		for left := pending(); len(left) > 0 || passes < minPasses; left = pending() {
			if len(left) > 0 && time.Since(start) > 10*time.Second {
				return fmt.Errorf("no %v listing interrupted after %d passes", left, passes)
			}
			if time.Since(start) > 2*time.Minute {
				return fmt.Errorf("only %d of %d passes ran in 2 minutes", passes, minPasses)
			}
			if err := pass(); err != nil {
				return fmt.Errorf("pass %d failed while links and addresses were changing: %w", passes, err)
			}
			passes++
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	failuresAfter := counts(t, "galactic_netlink_dump_failures_total")
	for kind, n := range failuresAfter {
		if d := n - failuresBefore[kind]; d != 0 {
			t.Errorf("%s listing failures rose by %v, want 0", kind, d)
		}
	}
	return passes
}

// counts returns metric's value per kind label.
func counts(t testing.TB, metric string) map[string]float64 {
	t.Helper()
	reg := prometheus.NewRegistry()
	nldump.MustRegister(reg)
	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather netlink dump metrics: %v", err)
	}
	out := map[string]float64{}
	for _, f := range families {
		if f.GetName() != metric {
			continue
		}
		for _, m := range f.GetMetric() {
			for _, l := range m.GetLabel() {
				if l.GetName() == "kind" {
					out[l.GetValue()] = m.GetCounter().GetValue()
				}
			}
		}
	}
	return out
}

// churnAddr returns an address unique per (group, i), with DAD off so adding
// it changes nothing else.
func churnAddr(group, i int) *netlink.Addr {
	return &netlink.Addr{
		IPNet: &net.IPNet{IP: net.ParseIP(fmt.Sprintf("fd00:c%x::%x", group, i+1)), Mask: net.CIDRMask(128, 128)},
		Flags: unix.IFA_F_NODAD,
	}
}

func dummy(name string) *netlink.Dummy {
	return &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name}}
}
