// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"go.datum.net/galactic/internal/plumbing/ebpf/forwardgatemap"
)

// statGates is the fake gate table with the datapath's drop counters.
type statGates struct {
	*gates
	stats forwardgatemap.Stats
}

func (g statGates) Stats() (forwardgatemap.Stats, error) { return g.stats, nil }

// TestCollector exports the node's links, its gates by state, the gate drop
// counters and lost scopes, with no label naming a link, prefix or address
// however many there are.
func TestCollector(t *testing.T) {
	g := newGates()
	now := time.Hour
	const links = 50
	for i := range links {
		ifindex := uint32(100 + i) //nolint:gosec // small
		g.setLink(ifindex, netip.MustParseAddr(fmt.Sprintf("fd00:aa::%x", i+1)))
		prefix := netip.MustParsePrefix(fmt.Sprintf("fd00:bb:%x::/64", i))
		deadline := map[int]time.Duration{0: now + time.Second, 1: now - time.Second, 2: 0}[i%3]
		if err := g.Set(ifindex, prefix, forwardgatemap.Gate{Deadline: deadline, Epoch: 1}); err != nil {
			t.Fatal(err)
		}
	}
	a := &Agent{Gates: statGates{gates: g, stats: forwardgatemap.Stats{Ingress: 3, Egress: 2, Deliver: 1}},
		BootClock: func() time.Duration { return now }}
	a.markLost("vpc/a")

	reg := prometheus.NewRegistry()
	reg.MustRegister(Collector{Agent: a})
	if err := testutil.GatherAndCompare(reg, openTestdata(t, "collector.prom")); err != nil {
		t.Fatal(err)
	}

	// Without a gate table only the lost scopes are known.
	if n := testutil.CollectAndCount(Collector{Agent: &Agent{}}); n != 1 {
		t.Fatalf("collector without gates exported %d series, want 1", n)
	}
}

// openTestdata opens testdata/name, closed with the test.
func openTestdata(t *testing.T, name string) *os.File {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}
