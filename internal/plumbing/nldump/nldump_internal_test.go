// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package nldump

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
)

// errInterrupted is how netlink reports a dump the kernel flagged interrupted.
var errInterrupted = fmt.Errorf("execute netlink request after 1 attempts: %w", netlink.ErrDumpInterrupted)

// fakeDump fails its first n calls as interrupted, each with a partial
// result, then returns the complete result. It counts its calls.
func fakeDump(n int) (func() ([]string, error), *int) {
	calls := 0
	return func() ([]string, error) {
		calls++
		if calls <= n {
			return []string{"partial"}, errInterrupted
		}
		return []string{"a", "b"}, nil
	}, &calls
}

func withNoSleep(t *testing.T) *[]time.Duration {
	t.Helper()
	var slept []time.Duration
	prev := sleep
	sleep = func(d time.Duration) { slept = append(slept, d) }
	t.Cleanup(func() { sleep = prev })
	return &slept
}

// counts returns the interrupted and failure counts for kind.
func counts(kind string) (float64, float64) {
	return testutil.ToFloat64(interrupted.WithLabelValues(kind)), testutil.ToFloat64(failures.WithLabelValues(kind))
}

func TestRetry_RetriesInterruptedDumpAndDropsPartialResult(t *testing.T) {
	slept := withNoSleep(t)
	beforeInterrupted, beforeFailures := counts(kindLink)
	list, calls := fakeDump(triesPerRound + 2)

	got, err := retry(kindLink, list)
	if err != nil {
		t.Fatalf("retry: %v", err)
	}
	if !slices.Equal(got, []string{"a", "b"}) {
		t.Errorf("got %v, want the complete dump [a b]", got)
	}
	if *calls != triesPerRound+3 {
		t.Errorf("dumped %d times, want %d", *calls, triesPerRound+3)
	}
	if want := []time.Duration{roundBackoff}; !slices.Equal(*slept, want) {
		t.Errorf("slept %v, want one pause of %v after the first round", *slept, want)
	}
	afterInterrupted, afterFailures := counts(kindLink)
	if d := afterInterrupted - beforeInterrupted; d != triesPerRound+2 {
		t.Errorf("interrupted counter rose by %v, want %d", d, triesPerRound+2)
	}
	if afterFailures != beforeFailures {
		t.Errorf("failure counter rose by %v, want 0", afterFailures-beforeFailures)
	}
}

func TestRetry_GivesUpAfterBound(t *testing.T) {
	slept := withNoSleep(t)
	beforeInterrupted, beforeFailures := counts(kindRoute)
	const bound = dumpRounds * triesPerRound
	list, calls := fakeDump(bound)

	got, err := retry(kindRoute, list)
	if !errors.Is(err, netlink.ErrDumpInterrupted) {
		t.Fatalf("err = %v, want ErrDumpInterrupted", err)
	}
	if want := fmt.Sprintf("after %d attempts", bound); !strings.Contains(err.Error(), want) {
		t.Errorf("err = %q, want it to report %q", err, want)
	}
	if got != nil {
		t.Errorf("got %v, want no partial result", got)
	}
	if *calls != bound {
		t.Errorf("dumped %d times, want %d", *calls, bound)
	}
	want := []time.Duration{roundBackoff, 2 * roundBackoff, 3 * roundBackoff, 4 * roundBackoff}
	if !slices.Equal(*slept, want) {
		t.Errorf("slept %v, want %v", *slept, want)
	}
	afterInterrupted, afterFailures := counts(kindRoute)
	if d := afterInterrupted - beforeInterrupted; d != bound {
		t.Errorf("interrupted counter rose by %v, want %d", d, bound)
	}
	if d := afterFailures - beforeFailures; d != 1 {
		t.Errorf("failure counter rose by %v, want 1", d)
	}
}

func TestRetry_ReturnsOtherErrorsAtOnce(t *testing.T) {
	slept := withNoSleep(t)
	beforeInterrupted, beforeFailures := counts(kindAddress)
	calls := 0
	list := func() ([]string, error) {
		calls++
		return nil, unix.ENODEV
	}

	_, err := retry(kindAddress, list)
	if !errors.Is(err, unix.ENODEV) {
		t.Fatalf("err = %v, want ENODEV", err)
	}
	if calls != 1 || len(*slept) != 0 {
		t.Errorf("dumped %d times and slept %d times, want 1 and 0", calls, len(*slept))
	}
	afterInterrupted, afterFailures := counts(kindAddress)
	if afterInterrupted != beforeInterrupted || afterFailures != beforeFailures {
		t.Errorf("counters moved on a non-interrupt error")
	}
}

// TestMetrics_ExposeEveryKind pins that a scrape shows both counters
// for every listing kind from startup, before any listing is interrupted, so
// a rate over them is defined from the first scrape.
func TestMetrics_ExposeEveryKind(t *testing.T) {
	families, err := ctrlmetrics.Registry.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	got := map[string][]string{}
	for _, f := range families {
		for _, m := range f.GetMetric() {
			for _, l := range m.GetLabel() {
				if l.GetName() == labelKind {
					got[f.GetName()] = append(got[f.GetName()], l.GetValue())
				}
			}
		}
	}
	want := []string{kindAddress, kindLink, kindNeighbor, kindRoute, kindRule}
	for _, name := range []string{"galactic_netlink_dump_interrupted_total", "galactic_netlink_dump_failures_total"} {
		slices.Sort(got[name])
		if !slices.Equal(got[name], want) {
			t.Errorf("%s kinds = %v, want %v", name, got[name], want)
		}
	}
}
