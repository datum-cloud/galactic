// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"go.datum.net/galactic/internal/plumbing/ebpf/natmap"
	"go.datum.net/galactic/internal/plumbing/ebpf/natprog"
)

const (
	connTableMaxEntriesName = "galactic_nat_conn_table_max_entries"
	connsName               = "galactic_nat_conns"
	sessionsName            = "galactic_nat_sessions"
	oldestRowAgeName        = "galactic_nat_conn_table_oldest_row_age_seconds"
)

// connRows is a read-only natmap.Table over a fixed list of wire rows, enough
// for the collector's walk.
type connRows struct {
	keys   []natprog.NatConnKey
	values []natprog.NatConnValue
}

func (r *connRows) add(key natprog.NatConnKey, value natprog.NatConnValue) {
	r.keys = append(r.keys, key)
	r.values = append(r.values, value)
}

func (*connRows) Put(_, _ any) error    { return errors.New("read-only") }
func (*connRows) Lookup(_, _ any) error { return ebpf.ErrKeyNotExist }
func (*connRows) Delete(_ any) error    { return ebpf.ErrKeyNotExist }
func (r *connRows) Iterate() natmap.Iterator {
	return &connRowsIterator{rows: r, idx: -1}
}

type connRowsIterator struct {
	rows *connRows
	idx  int
}

func (it *connRowsIterator) Next(keyOut, valueOut any) bool {
	it.idx++
	if it.idx >= len(it.rows.keys) {
		return false
	}
	reflect.ValueOf(keyOut).Elem().Set(reflect.ValueOf(it.rows.keys[it.idx]))
	reflect.ValueOf(valueOut).Elem().Set(reflect.ValueOf(it.rows.values[it.idx]))
	return true
}

func (*connRowsIterator) Err() error { return nil }

// reverseRow is a reverse row's wire key and value: no encapsulation source.
// proto is the tenant's protocol, which the value carries; a NAT64 Echo
// session's key holds ICMP instead, as the datapath writes it. destPort is in
// host order.
func reverseRow(
	family, proto uint8, shardPort, destPort uint16, lastSeen uint32,
) (natprog.NatConnKey, natprog.NatConnValue) {
	keyProto := proto
	if family == natprog.FamilyIPv4 && proto == 58 {
		keyProto = 1
	}
	return natprog.NatConnKey{Family: family, Proto: keyProto, Dport: shardPort},
		natprog.NatConnValue{Proto: proto, DestPort: destPort<<8 | destPort>>8, LastSeen: lastSeen}
}

func fixedClock(now uint32) func() (uint32, error) {
	return func() (uint32, error) { return now, nil }
}

// gatherGauges registers c and returns every gauge by metric name, each keyed
// by its label values joined with "/".
func gatherGauges(t *testing.T, c prometheus.Collector) (map[string]map[string]float64, map[string]string) {
	t.Helper()
	reg := prometheus.NewPedanticRegistry()
	if err := reg.Register(c); err != nil {
		t.Fatalf("register: %v", err)
	}
	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	gauges := map[string]map[string]float64{}
	help := map[string]string{}
	for _, mf := range families {
		if mf.GetType() != dto.MetricType_GAUGE {
			continue
		}
		help[mf.GetName()] = mf.GetHelp()
		series := map[string]float64{}
		for _, m := range mf.GetMetric() {
			labels := make([]string, 0, len(m.GetLabel()))
			for _, lp := range m.GetLabel() {
				labels = append(labels, lp.GetValue())
			}
			series[strings.Join(labels, "/")] = m.GetGauge().GetValue()
		}
		gauges[mf.GetName()] = series
	}
	return gauges, help
}

func TestNatCollectorCountsLiveSessions(t *testing.T) {
	const now uint32 = 50_000
	rows := &connRows{}
	// nat66: one live DNS session and two expired ones.
	rows.add(reverseRow(natprog.FamilyIPv6, 17, 35000, 53, now-10))
	rows.add(reverseRow(natprog.FamilyIPv6, 17, 35001, 53, now-31))
	rows.add(reverseRow(natprog.FamilyIPv6, 17, 35002, 53, now-900))
	// nat64: one live ICMP Echo session, tenant protocol ICMPv6.
	rows.add(reverseRow(natprog.FamilyIPv4, 58, 35003, 0, now-20))
	// A forward row: counted as a row, never as a session.
	rows.add(natprog.NatConnKey{Family: natprog.FamilyIPv6, Proto: 17, EncapSrc: [16]byte{0xfc}},
		natprog.NatConnValue{Proto: 17, LastSeen: 1})

	c := &natCollector{connTable: natmap.NewConnTable(rows), now: fixedClock(now)}
	gauges, help := gatherGauges(t, c)

	wantConns := map[string]float64{familyNAT66: 4, familyNAT64: 1}
	if !reflect.DeepEqual(gauges[connsName], wantConns) {
		t.Errorf("%s = %v, want %v", connsName, gauges[connsName], wantConns)
	}
	wantSessions := map[string]float64{
		"nat66/tcp": 0, "nat66/udp": 1, "nat66/icmp": 0,
		"nat64/tcp": 0, "nat64/udp": 0, "nat64/icmp": 1,
	}
	if !reflect.DeepEqual(gauges[sessionsName], wantSessions) {
		t.Errorf("%s = %v, want %v", sessionsName, gauges[sessionsName], wantSessions)
	}
	if got := gauges[oldestRowAgeName][""]; got != 900 {
		t.Errorf("%s = %v, want 900", oldestRowAgeName, got)
	}

	if !strings.Contains(help[connsName], "expired sessions included") {
		t.Errorf("%s help does not say it counts expired rows: %q", connsName, help[connsName])
	}
	if !strings.Contains(help[sessionsName], "Expired sessions are not counted") {
		t.Errorf("%s help does not say it counts live sessions only: %q", sessionsName, help[sessionsName])
	}
}

func TestNatCollectorEmptyConnTable(t *testing.T) {
	c := &natCollector{connTable: natmap.NewConnTable(&connRows{}), now: fixedClock(1)}
	gauges, _ := gatherGauges(t, c)

	if len(gauges[connsName]) != 2 || len(gauges[sessionsName]) != 6 {
		t.Errorf("empty table: %s = %v, %s = %v; want every series at zero",
			connsName, gauges[connsName], sessionsName, gauges[sessionsName])
	}
	if _, ok := gauges[oldestRowAgeName]; ok {
		t.Errorf("%s reported for a table with no reverse rows", oldestRowAgeName)
	}
}

func TestNatCollectorDescribesConnTableMaxEntries(t *testing.T) {
	ch := make(chan *prometheus.Desc, 16)
	(&natCollector{}).Describe(ch)
	close(ch)

	var descs []string
	for d := range ch {
		descs = append(descs, d.String())
	}
	found := false
	for _, d := range descs {
		if strings.Contains(d, `fqName: "`+connTableMaxEntriesName+`"`) {
			found = true
		}
	}
	if !found {
		t.Errorf("Describe does not emit %s; got %v", connTableMaxEntriesName, descs)
	}
}

func TestNatCollectorOmitsMaxEntriesWithoutMap(t *testing.T) {
	ch := make(chan prometheus.Metric, 4)
	(&natCollector{}).collectConnTableMaxEntries(ch)
	close(ch)
	for m := range ch {
		t.Errorf("unexpected metric without a loaded map: %s", m.Desc())
	}
}

func TestNatCollectorReportsMaxEntriesAsGauge(t *testing.T) {
	ch := make(chan prometheus.Metric, 1)
	(&natCollector{connMaxEntries: 1024}).collectConnTableMaxEntries(ch)
	close(ch)

	m, ok := <-ch
	if !ok {
		t.Fatal("no metric emitted")
	}
	var out dto.Metric
	if err := m.Write(&out); err != nil {
		t.Fatalf("write: %v", err)
	}
	if out.GetGauge() == nil || out.GetGauge().GetValue() != 1024 {
		t.Errorf("metric = %v, want gauge 1024", &out)
	}
}

func TestNatCollectorSessionRefreshedMidWalk(t *testing.T) {
	// The datapath refreshed this session after the scrape read its clock.
	const now uint32 = 50_000
	rows := &connRows{}
	rows.add(reverseRow(natprog.FamilyIPv6, 6, 35000, 443, now+1))

	c := &natCollector{connTable: natmap.NewConnTable(rows), now: fixedClock(now)}
	gauges, _ := gatherGauges(t, c)

	if got := gauges[sessionsName]["nat66/tcp"]; got != 1 {
		t.Errorf("session refreshed mid-walk: %s{nat66,tcp} = %v, want 1", sessionsName, got)
	}
	if got := gauges[oldestRowAgeName][""]; got != 0 {
		t.Errorf("session refreshed mid-walk: %s = %v, want 0", oldestRowAgeName, got)
	}
}

func TestNatCollectorSkipsSessionsWithoutClock(t *testing.T) {
	rows := &connRows{}
	rows.add(reverseRow(natprog.FamilyIPv6, 17, 35000, 53, 1))
	c := &natCollector{
		connTable: natmap.NewConnTable(rows),
		now:       func() (uint32, error) { return 0, errors.New("no clock") },
	}
	gauges, _ := gatherGauges(t, c)

	for _, name := range []string{connsName, sessionsName, oldestRowAgeName} {
		if _, ok := gauges[name]; ok {
			t.Errorf("%s reported without the session clock", name)
		}
	}
}

func TestNatCollectorOmitsSessionsWithoutTable(t *testing.T) {
	ch := make(chan prometheus.Metric, 16)
	(&natCollector{}).collectConns(ch)
	close(ch)
	for m := range ch {
		t.Errorf("unexpected metric without a session table: %s", m.Desc())
	}
}

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("test requires root (CAP_BPF/CAP_NET_ADMIN) to load BPF programs and maps; re-run via sudo")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("rlimit.RemoveMemlock: %v", err)
	}
}

func TestNatCollectorConnTableMaxEntries(t *testing.T) {
	requireRoot(t)

	var objs natprog.NatObjects
	if err := natprog.LoadNatObjects(&objs, nil); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			t.Fatalf("load objects: verifier rejected program:\n%+v", ve)
		}
		t.Fatalf("load objects: %v", err)
	}
	t.Cleanup(func() { _ = objs.Close() })

	reg := prometheus.NewPedanticRegistry()
	if err := reg.Register(newNatCollector(&objs)); err != nil {
		t.Fatalf("register: %v", err)
	}
	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}

	want := float64(objs.NatConnTable.MaxEntries())
	for _, mf := range families {
		if mf.GetName() != connTableMaxEntriesName {
			continue
		}
		if mf.GetType() != dto.MetricType_GAUGE {
			t.Errorf("type = %s, want GAUGE", mf.GetType())
		}
		if got := mf.GetMetric()[0].GetGauge().GetValue(); got != want || got == 0 {
			t.Errorf("value = %v, want %v", got, want)
		}
		return
	}
	t.Errorf("%s not gathered", connTableMaxEntriesName)
}
