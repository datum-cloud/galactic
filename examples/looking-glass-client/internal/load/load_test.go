// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package load

import (
	"testing"

	"github.com/datum-cloud/galactic/examples/looking-glass-client/internal/rpcerr"
	"github.com/datum-cloud/galactic/examples/looking-glass-client/internal/run"
	"github.com/datum-cloud/galactic/examples/looking-glass-client/internal/stream"
)

func TestPercentiles(t *testing.T) {
	v := make([]float64, 0, 100)
	for i := 100; i >= 1; i-- {
		v = append(v, float64(i))
	}
	if p := Of(v); p != (Percentiles{N: 100, P50: 50, P95: 95, Max: 100}) {
		t.Errorf("percentiles = %+v", p)
	}
	if p := Of(nil); p != (Percentiles{}) {
		t.Errorf("empty sample = %+v", p)
	}
}

func TestSummarize(t *testing.T) {
	line := func(group, code, reason, complete string, ms float64) Line {
		r := run.Record{Status: rpcerr.Error{Code: code, Reason: reason}, Timing: run.Timing{CompleteMS: -1}}
		if complete != "" {
			r.Stream = stream.Result{Delivered: true, Reason: complete}
			r.Timing.CompleteMS, r.Timing.OutcomeMS = ms, []float64{ms / 2}
		}
		return Line{Group: group, Record: r}
	}
	got := Summarize([]Line{
		line("a", "OK", "", "Succeeded", 10),
		line("b", "ResourceExhausted", "Throttled", "", 0),
		line("a", "OK", "", "PartialResults", 30),
	})
	if len(got) != 2 || got[0].Group != "a" || got[0].Attempts != 2 || got[0].Delivered != 2 ||
		got[0].CompleteMS.Max != 30 || got[0].FirstOutcomeMS.P50 != 5 ||
		got[1].Statuses["ResourceExhausted/Throttled"] != 1 || got[1].CompleteMS.N != 0 {
		t.Errorf("summary = %+v", got)
	}
}
