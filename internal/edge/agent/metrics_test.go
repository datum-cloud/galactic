// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"errors"
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
// counters, lost scopes, and its MTU with the encapsulation limit, with no
// label naming a link, prefix or address however many there are.
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
		BootClock: func() time.Duration { return now },
		MTU:       1500, EncapMTU: func() (int, error) { return 1460, nil }}
	a.markLost("vpc/a")

	reg := prometheus.NewRegistry()
	reg.MustRegister(Collector{Agent: a})
	if err := testutil.GatherAndCompare(reg, openTestdata(t, "collector.prom")); err != nil {
		t.Fatal(err)
	}

	// Without a gate table or a limit only the lost scopes and the MTU are known.
	if n := testutil.CollectAndCount(Collector{Agent: &Agent{MTU: 1500}}); n != 2 {
		t.Fatalf("collector without gates exported %d series, want 2", n)
	}
}

// TestCollectorEncapLimit exports the limit on a node with no attachments, and
// counts a limit it cannot read as a collect error rather than reporting zero,
// which would read as the check being off.
func TestCollectorEncapLimit(t *testing.T) {
	for _, tc := range []struct {
		name  string
		limit int
		err   error
	}{
		{name: "set", limit: 1460},
		{name: "unset", limit: 0},
		{name: "unreadable", err: errors.New("map not pinned")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := Collector{Agent: &Agent{MTU: 1500, EncapMTU: func() (int, error) { return tc.limit, tc.err }}}
			if err := testutil.CollectAndCompare(c, openTestdata(t, "encap_limit_"+tc.name+".prom"),
				"galactic_edge_foundation_encap_limit_bytes", "galactic_edge_foundation_mtu_bytes",
				"galactic_edge_foundation_node_collect_errors"); err != nil {
				t.Fatal(err)
			}
		})
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
