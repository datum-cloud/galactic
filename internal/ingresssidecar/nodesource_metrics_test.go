// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package ingresssidecar

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"go.datum.net/galactic/internal/plumbing/ebpf/egressroutemap"
	"go.datum.net/galactic/internal/plumbing/ebpf/usidmap"
)

// nodeSrcTable is an in-memory node_src_addr_table. dropWrites makes Put
// succeed without storing, standing in for a write that does not read back.
type nodeSrcTable struct {
	value      *[16]byte
	puts       int
	dropWrites bool
	failLookup error
}

func (t *nodeSrcTable) Put(_, value any) error {
	t.puts++
	if t.dropWrites {
		return nil
	}
	v := value.([16]byte)
	t.value = &v
	return nil
}

func (t *nodeSrcTable) Lookup(_, valueOut any) error {
	if t.failLookup != nil {
		return t.failLookup
	}
	if t.value == nil {
		return ebpf.ErrKeyNotExist
	}
	*valueOut.(*[16]byte) = *t.value
	return nil
}

func (t *nodeSrcTable) Delete(any) error          { return nil }
func (t *nodeSrcTable) Iterate() usidmap.Iterator { return nil }

type staticNodeSource struct {
	addr net.IP
	err  error
}

func (r staticNodeSource) ResolveNodeSourceAddress() (net.IP, error) { return r.addr, r.err }

func TestSyncNodeSourceAddress(t *testing.T) {
	node := net.ParseIP("fd00:10::")
	other := net.ParseIP("fd00:20::")
	var raw [16]byte
	copy(raw[:], other.To16())

	for _, tc := range []struct {
		name      string
		resolver  NodeSourceAddressResolver
		table     *nodeSrcTable
		wantWrote bool
		wantPuts  int
		want      string
	}{
		{name: "unset is written", resolver: staticNodeSource{addr: node}, table: &nodeSrcTable{},
			wantWrote: true, wantPuts: 1, want: NodeSourceOK},
		{name: "the right address is left alone", resolver: staticNodeSource{addr: other},
			table: &nodeSrcTable{value: &raw}, want: NodeSourceOK},
		{name: "a wrong address is rewritten", resolver: staticNodeSource{addr: node},
			table: &nodeSrcTable{value: &raw}, wantWrote: true, wantPuts: 1, want: NodeSourceOK},
		{name: "no resolver", table: &nodeSrcTable{}, want: NodeSourceUnconfigured},
		{name: "unresolved leaves the table", resolver: staticNodeSource{err: errTest},
			table: &nodeSrcTable{value: &raw}, want: NodeSourceUnresolved},
		{name: "read failure", resolver: staticNodeSource{addr: node},
			table: &nodeSrcTable{failLookup: errTest}, want: NodeSourceError},
		{name: "write that does not read back", resolver: staticNodeSource{addr: node},
			table: &nodeSrcTable{dropWrites: true}, wantWrote: true, wantPuts: 1, want: NodeSourceError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wrote, err := syncNodeSourceAddress(tc.resolver, egressroutemap.NewNodeSourceAddress(tc.table))
			if got := nodeSourceStatus(err); got != tc.want {
				t.Errorf("status %q (err %v), want %q", got, err, tc.want)
			}
			if wrote != tc.wantWrote || tc.table.puts != tc.wantPuts {
				t.Errorf("wrote %v with %d puts, want %v with %d", wrote, tc.table.puts, tc.wantWrote, tc.wantPuts)
			}
		})
	}
}

// readNodeSourceCheck scrapes m's status and last-checked time, and
// reports an error unless exactly one status is 1 and the rest 0.
func readNodeSourceCheck(m *NodeSourceMetrics) (status string, at float64, err error) {
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(m.check)
	families, err := reg.Gather()
	if err != nil {
		return "", 0, err
	}
	for _, f := range families {
		switch f.GetName() {
		case "galactic_ingress_sidecar_node_source_address_last_checked_timestamp_seconds":
			at = f.GetMetric()[0].GetGauge().GetValue()
		case "galactic_ingress_sidecar_node_source_address_status":
			for _, mt := range f.GetMetric() {
				switch v := mt.GetGauge().GetValue(); v {
				case 0:
				case 1:
					if status != "" {
						return "", 0, fmt.Errorf("statuses %q and %q are both set", status, mt.GetLabel()[0].GetValue())
					}
					status = mt.GetLabel()[0].GetValue()
				default:
					return "", 0, fmt.Errorf("status %q is %v", mt.GetLabel()[0].GetValue(), v)
				}
			}
		}
	}
	if status == "" {
		return "", 0, errors.New("no status is set")
	}
	return status, at, nil
}

// nodeSourceStatusIs returns m's one status that is 1.
func nodeSourceStatusIs(t *testing.T, m *NodeSourceMetrics) string {
	t.Helper()
	status, _, err := readNodeSourceCheck(m)
	if err != nil {
		t.Fatal(err)
	}
	return status
}

// TestSweepRestoresNodeSourceAddress: while a VRF is installed, every sweep
// checks node_src_addr_table and writes it when it is unset or wrong, so an
// address that was cleared, or could not be set when the VRF was created,
// recovers with no new VPC.
func TestSweepRestoresNodeSourceAddress(t *testing.T) {
	backend := newFakeBackend()
	const want = "node"
	backend.nodeSourceWant = want
	store := NewStore(backend, time.Minute, nil)
	metrics := NewNodeSourceMetrics()
	store.SetNodeSourceMetrics(metrics)
	ctx := context.Background()
	start := time.Unix(1_700_000_000, 0)

	store.Sweep(ctx, start)
	if backend.nodeSourceChecks != 0 || nodeSourceStatusIs(t, metrics) != NodeSourceUnknown {
		t.Fatalf("checked %d times with no VRF installed, status %q", backend.nodeSourceChecks,
			nodeSourceStatusIs(t, metrics))
	}

	backend.failNodeSource = errors.Join(errNodeSourceUnresolved, errTest)
	if err := store.SetDesired(ctx, "ns/a", &DesiredRoute{
		VPC: testVPC1, Prefix: mustPrefix(t, "fd00::1"), SID: net.ParseIP("fd00:99::1"),
	}); err != nil {
		t.Fatal(err)
	}
	store.Sweep(ctx, start.Add(time.Second))
	if got := nodeSourceStatusIs(t, metrics); got != NodeSourceUnresolved {
		t.Errorf("status %q while the BGPRouter yields no address, want %q", got, NodeSourceUnresolved)
	}

	backend.failNodeSource = nil
	store.Sweep(ctx, start.Add(2*time.Second))
	if backend.nodeSource != want || nodeSourceStatusIs(t, metrics) != NodeSourceOK {
		t.Fatalf("table %q, status %q after the address resolved", backend.nodeSource, nodeSourceStatusIs(t, metrics))
	}
	store.Sweep(ctx, start.Add(3*time.Second))
	backend.nodeSource = "" // another writer, or a reload, empties the table
	store.Sweep(ctx, start.Add(4*time.Second))
	if backend.nodeSource != want {
		t.Error("an emptied table was not restored")
	}
	if got := testutil.ToFloat64(metrics.repairs); got != 2 {
		t.Errorf("repairs %v, want 2: the first write and the restore", got)
	}
	if _, got, _ := readNodeSourceCheck(metrics); got != float64(start.Add(4*time.Second).Unix()) {
		t.Errorf("last checked %v, want the last sweep's time", got)
	}
	if backend.nodeSourceChecks != 4 {
		t.Errorf("%d checks over four sweeps with a VRF installed", backend.nodeSourceChecks)
	}
}

func TestNodeSourceMetricsSeries(t *testing.T) {
	reg := prometheus.NewPedanticRegistry()
	NewNodeSourceMetrics().MustRegister(reg)
	n, err := testutil.GatherAndCount(reg)
	if err != nil {
		t.Fatal(err)
	}
	if want := len(nodeSourceStatuses) + 2; n != want {
		t.Errorf("%d series, want %d", n, want)
	}
	var m *NodeSourceMetrics
	m.observe(time.Now(), true, nil) // nil-safe
}

// TestNodeSourceStatusThroughSweep: each status the check can end in reaches
// the metric, a failed write counts no repair, and the check stops once no
// VRF is installed.
func TestNodeSourceStatusThroughSweep(t *testing.T) {
	backend := newFakeBackend()
	backend.nodeSourceWant = "node"
	store := NewStore(backend, time.Minute, nil)
	metrics := NewNodeSourceMetrics()
	store.SetNodeSourceMetrics(metrics)
	ctx := context.Background()
	now := time.Now() // teardown grace runs from SetDesired's wall-clock time
	if err := store.SetDesired(ctx, "ns/a", &DesiredRoute{
		VPC: testVPC1, Prefix: mustPrefix(t, "fd00::1"), SID: net.ParseIP("fd00:99::1"),
	}); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		err  error
		want string
	}{
		{errNodeSourceUnconfigured, NodeSourceUnconfigured},
		{&nodeSourceMismatchError{want: net.ParseIP("fd00::1"), got: net.ParseIP("fd00::2")}, NodeSourceError},
		{errTest, NodeSourceError},
	} {
		backend.failNodeSource = tc.err
		now = now.Add(time.Second)
		store.Sweep(ctx, now)
		if got := nodeSourceStatusIs(t, metrics); got != tc.want {
			t.Errorf("status %q after %v, want %q", got, tc.err, tc.want)
		}
	}
	if got := testutil.ToFloat64(metrics.repairs); got != 0 {
		t.Errorf("repairs %v with every check failing, want 0", got)
	}

	backend.failNodeSource = nil
	if err := store.SetDesired(ctx, "ns/a", nil); err != nil {
		t.Fatal(err)
	}
	store.Sweep(ctx, now.Add(2*time.Minute)) // route removed; VRF grace starts
	store.Sweep(ctx, now.Add(4*time.Minute)) // VRF removed
	checks := backend.nodeSourceChecks
	store.Sweep(ctx, now.Add(5*time.Minute))
	if backend.nodeSourceChecks != checks {
		t.Error("a sweep checked the table with no VRF installed")
	}
}

// TestNodeSourceScrapeSeesOneStatus: a scrape during a run of checks that
// change the status always sees exactly one status set.
func TestNodeSourceScrapeSeesOneStatus(t *testing.T) {
	m := NewNodeSourceMetrics()
	done := make(chan struct{})
	go func() {
		defer close(done)
		errs := []error{nil, errNodeSourceUnconfigured, errTest, fmt.Errorf("%w: x", errNodeSourceUnresolved)}
		for i := range 20000 {
			m.observe(time.Unix(int64(i), 0), false, errs[i%len(errs)])
		}
	}()
	for {
		select {
		case <-done:
			return
		default:
		}
		if _, _, err := readNodeSourceCheck(m); err != nil {
			t.Fatal(err)
		}
	}
}
