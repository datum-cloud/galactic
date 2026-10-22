// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package healthprobe

import (
	"errors"
	"time"
)

// State is a backend's health decision.
type State string

// The decisions a Tracker makes. Their values match the API's
// BackendHealthState.
const (
	StateHealthy   State = "Healthy"
	StateUnhealthy State = "Unhealthy"
	StateUnknown   State = "Unknown"
)

// Reasons a Decision carries.
const (
	// ReasonProbeSucceeded: HealthyThreshold consecutive probes succeeded.
	ReasonProbeSucceeded = "ProbeSucceeded"

	// ReasonProbeFailed: UnhealthyThreshold consecutive probes failed.
	ReasonProbeFailed = "ProbeFailed"

	// ReasonPending: too few probes have completed to decide.
	ReasonPending = "Pending"

	// ReasonProbeUnavailable: UnhealthyThreshold consecutive probes could not
	// be sent (ErrUnavailable).
	ReasonProbeUnavailable = "ProbeUnavailable"
)

// Decision is a backend's damped health decision.
type Decision struct {
	State  State
	Reason string

	// Message is the probe error that led to the decision, or "".
	Message string

	// Since is when State last changed.
	Since time.Time
}

// Config is how one backend is probed and how its results are damped.
type Config struct {
	Interval           time.Duration
	Timeout            time.Duration
	UnhealthyThreshold int
	HealthyThreshold   int
}

// Tracker damps probe results into a Decision. The decision moves to Healthy
// after HealthyThreshold consecutive successes, to Unhealthy after
// UnhealthyThreshold consecutive failed probes, and to Unknown after
// UnhealthyThreshold consecutive probes that could not be sent. A backend
// whose results alternate never reaches a threshold and keeps its decision.
type Tracker struct {
	cfg      Config
	decision Decision

	// successes counts consecutive successes, and failures consecutive errors
	// of one kind: unavailable says which.
	successes   int
	failures    int
	unavailable bool
}

// NewTracker returns a Tracker that starts from seed, or from Unknown/Pending
// at now when seed is nil. Seeding from a published decision lets a restarted
// prober carry on where it left off instead of starting every backend over.
func NewTracker(cfg Config, seed *Decision, now time.Time) *Tracker {
	t := &Tracker{cfg: cfg, decision: Decision{State: StateUnknown, Reason: ReasonPending, Since: now}}
	if seed != nil {
		t.decision = *seed
	}
	return t
}

// Decision returns the current decision.
func (t *Tracker) Decision() Decision {
	return t.decision
}

// Observe records one probe's result, err being nil for a success, and
// reports whether the decision's state or reason changed.
func (t *Tracker) Observe(err error, now time.Time) bool {
	next := t.decision
	if err == nil {
		t.successes++
		t.failures = 0
		if t.successes < t.cfg.HealthyThreshold {
			return false
		}
		next.State, next.Reason, next.Message = StateHealthy, ReasonProbeSucceeded, ""
	} else {
		unavailable := errors.Is(err, ErrUnavailable)
		if t.failures == 0 || unavailable != t.unavailable {
			t.failures = 0
			t.unavailable = unavailable
		}
		t.failures++
		t.successes = 0
		if t.failures < t.cfg.UnhealthyThreshold {
			return false
		}
		next.State, next.Reason = StateUnhealthy, ReasonProbeFailed
		if unavailable {
			next.State, next.Reason = StateUnknown, ReasonProbeUnavailable
		}
		next.Message = err.Error()
	}
	if next.State == t.decision.State && next.Reason == t.decision.Reason {
		return false
	}
	if next.State != t.decision.State {
		next.Since = now
	}
	t.decision = next
	return true
}
