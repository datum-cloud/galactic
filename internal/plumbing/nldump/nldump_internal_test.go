// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package nldump

import (
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// errInterrupted is how netlink reports a dump the kernel flagged interrupted.
var errInterrupted = fmt.Errorf("execute netlink request after 10 attempts: %w", netlink.ErrDumpInterrupted)

// fakeDump returns each of results in turn, counting its calls.
func fakeDump(results ...func() ([]string, error)) (func() ([]string, error), *int) {
	calls := 0
	return func() ([]string, error) {
		r := results[calls]
		calls++
		return r()
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

func TestRetry_RetriesInterruptedDumpAndDropsPartialResult(t *testing.T) {
	slept := withNoSleep(t)
	partial := func() ([]string, error) { return []string{"partial"}, errInterrupted }
	complete := func() ([]string, error) { return []string{"a", "b"}, nil }
	list, calls := fakeDump(partial, partial, complete)

	got, err := retry(list)
	if err != nil {
		t.Fatalf("retry: %v", err)
	}
	if !slices.Equal(got, []string{"a", "b"}) {
		t.Errorf("got %v, want the complete dump [a b]", got)
	}
	if *calls != 3 {
		t.Errorf("dumped %d times, want 3", *calls)
	}
	if want := []time.Duration{dumpBackoff, 2 * dumpBackoff}; !slices.Equal(*slept, want) {
		t.Errorf("slept %v, want %v", *slept, want)
	}
}

func TestRetry_GivesUpAfterBound(t *testing.T) {
	withNoSleep(t)
	results := make([]func() ([]string, error), dumpAttempts)
	for i := range results {
		results[i] = func() ([]string, error) { return []string{"partial"}, errInterrupted }
	}
	list, calls := fakeDump(results...)

	got, err := retry(list)
	if !errors.Is(err, netlink.ErrDumpInterrupted) {
		t.Fatalf("err = %v, want ErrDumpInterrupted", err)
	}
	if got != nil {
		t.Errorf("got %v, want no partial result", got)
	}
	if *calls != dumpAttempts {
		t.Errorf("dumped %d times, want %d", *calls, dumpAttempts)
	}
}

func TestRetry_ReturnsOtherErrorsAtOnce(t *testing.T) {
	slept := withNoSleep(t)
	list, calls := fakeDump(func() ([]string, error) { return nil, unix.ENODEV })

	_, err := retry(list)
	if !errors.Is(err, unix.ENODEV) {
		t.Fatalf("err = %v, want ENODEV", err)
	}
	if *calls != 1 || len(*slept) != 0 {
		t.Errorf("dumped %d times and slept %d times, want 1 and 0", *calls, len(*slept))
	}
}
