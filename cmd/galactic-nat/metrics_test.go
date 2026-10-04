// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"go.datum.net/galactic/internal/plumbing/ebpf/natprog"
)

const connTableMaxEntriesName = "galactic_nat_conn_table_max_entries"

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
