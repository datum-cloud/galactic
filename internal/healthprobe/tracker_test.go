// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package healthprobe

import (
	"errors"
	"fmt"
	"testing"
	"time"
)

var (
	errRefused = errors.New("connection refused")
	errNoIface = fmt.Errorf("%w: interface gone", ErrUnavailable)
)

func TestTracker(t *testing.T) {
	cfg := Config{UnhealthyThreshold: 3, HealthyThreshold: 2}
	healthy := &Decision{State: StateHealthy, Reason: ReasonProbeSucceeded}

	tests := []struct {
		name    string
		seed    *Decision
		results []error
		want    Decision
		changes int
	}{
		{
			name: "starts Unknown and Pending",
			want: Decision{State: StateUnknown, Reason: ReasonPending},
		},
		{
			name:    "becomes Healthy at the healthy threshold",
			results: []error{nil, nil},
			want:    Decision{State: StateHealthy, Reason: ReasonProbeSucceeded},
			changes: 1,
		},
		{
			name:    "stays Pending below the healthy threshold",
			results: []error{nil},
			want:    Decision{State: StateUnknown, Reason: ReasonPending},
		},
		{
			name:    "becomes Unhealthy at the unhealthy threshold, with the last error",
			seed:    healthy,
			results: []error{errRefused, errRefused, errRefused},
			want:    Decision{State: StateUnhealthy, Reason: ReasonProbeFailed, Message: errRefused.Error()},
			changes: 1,
		},
		{
			name:    "a success resets the failure count",
			seed:    healthy,
			results: []error{errRefused, errRefused, nil, errRefused, errRefused},
			want:    *healthy,
		},
		{
			name:    "alternating results never change the decision",
			seed:    healthy,
			results: []error{errRefused, nil, errRefused, nil, errRefused, nil, errRefused},
			want:    *healthy,
		},
		{
			name:    "a probe that cannot run makes the decision Unknown, not Unhealthy",
			seed:    healthy,
			results: []error{errNoIface, errNoIface, errNoIface},
			want:    Decision{State: StateUnknown, Reason: ReasonProbeUnavailable, Message: errNoIface.Error()},
			changes: 1,
		},
		{
			name:    "mixed kinds of failure reach neither threshold",
			seed:    healthy,
			results: []error{errNoIface, errNoIface, errRefused, errRefused},
			want:    *healthy,
		},
		{
			name:    "recovers from Unhealthy at the healthy threshold",
			seed:    &Decision{State: StateUnhealthy, Reason: ReasonProbeFailed, Message: "x"},
			results: []error{nil, nil},
			want:    Decision{State: StateHealthy, Reason: ReasonProbeSucceeded},
			changes: 1,
		},
		{
			name:    "a probe that cannot run does not return an Unhealthy backend to Unknown",
			seed:    healthy,
			results: []error{errRefused, errRefused, errRefused, errNoIface, errNoIface, errRefused},
			want:    Decision{State: StateUnhealthy, Reason: ReasonProbeFailed, Message: errRefused.Error()},
			changes: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tr := NewTracker(cfg, tt.seed, time.Time{})
			changes := 0
			for _, err := range tt.results {
				if tr.Observe(err, time.Time{}) {
					changes++
				}
			}
			got := tr.Decision()
			got.Since = time.Time{}
			if got != tt.want {
				t.Errorf("decision = %+v, want %+v", got, tt.want)
			}
			if changes != tt.changes {
				t.Errorf("changes = %d, want %d", changes, tt.changes)
			}
		})
	}
}

// TestTrackerSince: Since moves only when the state does.
func TestTrackerSince(t *testing.T) {
	start := time.Unix(1000, 0)
	tr := NewTracker(Config{UnhealthyThreshold: 1, HealthyThreshold: 1},
		&Decision{State: StateUnhealthy, Reason: ReasonProbeFailed, Since: start}, start)

	// Unhealthy to Unknown/ProbeUnavailable is a state change.
	at := start.Add(time.Second)
	if !tr.Observe(errNoIface, at) || tr.Decision().Since != at {
		t.Fatalf("decision = %+v, want a change at %s", tr.Decision(), at)
	}
	// Unknown/ProbeUnavailable to Healthy is too.
	at = at.Add(time.Second)
	if !tr.Observe(nil, at) || tr.Decision().Since != at {
		t.Fatalf("decision = %+v, want a change at %s", tr.Decision(), at)
	}
}

// TestTrackerReasonChangeKeepsSince: Pending to ProbeUnavailable changes the
// reason, not the state, so Since stays.
func TestTrackerReasonChangeKeepsSince(t *testing.T) {
	start := time.Unix(1000, 0)
	tr := NewTracker(Config{UnhealthyThreshold: 1, HealthyThreshold: 1}, nil, start)
	if !tr.Observe(errNoIface, start.Add(time.Minute)) {
		t.Fatal("Pending to ProbeUnavailable reported no change")
	}
	if got := tr.Decision(); got.State != StateUnknown || got.Since != start {
		t.Errorf("decision = %+v, want Unknown since %s", got, start)
	}
}
