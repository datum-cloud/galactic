// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package healthprobe

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"syscall"
	"testing"
	"testing/synctest"
	"time"
)

// TestDialUnavailable: a probe over an interface that does not exist, or that
// has no IPv6 link-local address, cannot be sent, which Dial reports as
// ErrUnavailable rather than as a failed probe.
func TestDialUnavailable(t *testing.T) {
	addr := netip.MustParseAddr("fd20::100")
	for _, iface := range []string{"galactic-nonexistent0", "lo"} {
		err := Dial(context.Background(), iface, addr, 80, time.Second)
		if !errors.Is(err, ErrUnavailable) {
			t.Errorf("Dial over %s: err = %v, want ErrUnavailable", iface, err)
		}
	}
}

func TestRetryRefused(t *testing.T) {
	for _, tc := range []struct {
		name      string
		failures  int
		err       error
		wantCalls int
		wantTime  time.Duration
	}{
		{"healthy", 0, nil, 1, 0},
		{"waking", 1, fmt.Errorf("dial: %w", syscall.ECONNREFUSED), 2, 250 * time.Millisecond},
		{"slowWake", 2, syscall.ECONNREFUSED, 3, 500 * time.Millisecond},
		{"closedPort", 9, syscall.ECONNREFUSED, 3, 500 * time.Millisecond},
		{"unreachable", 9, syscall.ENETUNREACH, 1, 0},
		{"unavailable", 9, ErrUnavailable, 1, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				calls := 0
				start := time.Now()
				err := retryRefused(context.Background(), func() error {
					calls++
					if calls <= tc.failures {
						return tc.err
					}
					return nil
				})
				if calls != tc.wantCalls || time.Since(start) != tc.wantTime {
					t.Fatalf("calls=%d elapsed=%s", calls, time.Since(start))
				}
				if tc.failures >= tc.wantCalls {
					if !errors.Is(err, tc.err) {
						t.Fatalf("error=%v want %v", err, tc.err)
					}
				} else if err != nil {
					t.Fatal(err)
				}
			})
		})
	}
}

func TestRetryRefusedDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		calls := 0
		start := time.Now()
		err := retryRefused(ctx, func() error { calls++; return syscall.ECONNREFUSED })
		if !errors.Is(err, context.DeadlineExceeded) || calls != 1 || time.Since(start) != 100*time.Millisecond {
			t.Fatalf("err=%v calls=%d elapsed=%s", err, calls, time.Since(start))
		}
	})
}

func TestRetryRefusedCancellation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		calls := 0
		err := retryRefused(ctx, func() error { calls++; cancel(); return syscall.ECONNREFUSED })
		if !errors.Is(err, context.Canceled) || calls != 1 {
			t.Fatalf("err=%v calls=%d", err, calls)
		}
	})
}
