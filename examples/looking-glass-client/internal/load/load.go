// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package load runs a workload of concurrent attempts over one connection
// and summarizes what each group of them observed.
package load

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/datum-cloud/galactic/examples/looking-glass-client/internal/run"
	"google.golang.org/grpc"
)

// Group is a set of attempts sharing one shape.
type Group struct {
	Name string `json:"name"`
	// Count attempts run, at most Concurrency at once.
	Count       int `json:"count"`
	Concurrency int `json:"concurrency"`
	// StartAfter delays the group's first attempt from the workload's
	// start; Interval spaces its attempts' starts.
	StartAfter run.Duration `json:"startAfter,omitempty"`
	Interval   run.Duration `json:"interval,omitempty"`
	// Projects, if set, attributes attempts to them in turn; otherwise
	// every attempt uses Options.Project.
	Projects []string `json:"projects,omitempty"`
	// Targets, if set, gives attempts their query target in turn.
	Targets []string    `json:"targets,omitempty"`
	Options run.Options `json:"options"`
}

// Spec is a workload against one cell.
type Spec struct {
	Cell   string  `json:"cell"`
	Groups []Group `json:"groups"`
}

// Line is one attempt's record, with its group and its start offset from
// the workload's start.
type Line struct {
	Group   string  `json:"group"`
	StartMS float64 `json:"startMs"`
	run.Record
}

// Run runs spec on cc, handing each record to emit as it finishes. emit is
// called from one goroutine at a time.
func Run(ctx context.Context, cc grpc.ClientConnInterface, spec Spec, emit func(Line)) error {
	for _, g := range spec.Groups {
		if g.Count < 1 || g.Concurrency < 1 {
			return fmt.Errorf("group %q: count and concurrency must be positive", g.Name)
		}
		if _, err := g.Options.Query.Proto(); err != nil {
			return fmt.Errorf("group %q: %w", g.Name, err)
		}
	}
	var mu sync.Mutex
	var wg sync.WaitGroup
	t0 := time.Now()
	for _, g := range spec.Groups {
		sem := make(chan struct{}, g.Concurrency)
		for i := range g.Count {
			o := g.Options
			o.Cell, o.RequestID = spec.Cell, ""
			o.Nodes = slices.Clone(o.Nodes)
			if len(g.Projects) > 0 {
				o.Project = g.Projects[i%len(g.Projects)]
			}
			if len(g.Targets) > 0 {
				o.Query.Target = g.Targets[i%len(g.Targets)]
			}
			at := t0.Add(time.Duration(g.StartAfter) + time.Duration(i)*time.Duration(g.Interval))
			wg.Go(func() {
				if !sleepUntil(ctx, at) {
					return
				}
				select {
				case sem <- struct{}{}:
				case <-ctx.Done():
					return
				}
				defer func() { <-sem }()
				start := time.Since(t0)
				rec, err := run.Do(ctx, cc, o, nil)
				if err != nil {
					return
				}
				mu.Lock()
				defer mu.Unlock()
				emit(Line{Group: g.Name, StartMS: float64(start.Microseconds()) / 1000, Record: rec})
			})
		}
	}
	wg.Wait()
	return ctx.Err()
}

func sleepUntil(ctx context.Context, at time.Time) bool {
	t := time.NewTimer(time.Until(at))
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}

// Stats summarize one group's attempts.
type Stats struct {
	Group    string `json:"group"`
	Attempts int    `json:"attempts"`
	// Statuses counts attempts by "<gRPC code>/<reason>", and Completes by
	// terminal reason.
	Statuses   map[string]int `json:"statuses"`
	Completes  map[string]int `json:"completes"`
	Delivered  int            `json:"delivered"`
	Violations int            `json:"violations"`
	// CompleteMS and FirstOutcomeMS are latency percentiles over the
	// attempts that reached each point, measured from each attempt's start.
	CompleteMS     Percentiles `json:"completeMs"`
	FirstOutcomeMS Percentiles `json:"firstOutcomeMs"`
}

// Percentiles of a sample, in its unit; N is its size.
type Percentiles struct {
	N   int     `json:"n"`
	P50 float64 `json:"p50"`
	P95 float64 `json:"p95"`
	Max float64 `json:"max"`
}

// Of returns the percentiles of v (nearest rank).
func Of(v []float64) Percentiles {
	if len(v) == 0 {
		return Percentiles{}
	}
	s := slices.Clone(v)
	sort.Float64s(s)
	rank := func(p float64) float64 {
		i := int(p*float64(len(s))+0.999999) - 1
		return s[max(0, min(i, len(s)-1))]
	}
	return Percentiles{N: len(s), P50: rank(0.5), P95: rank(0.95), Max: s[len(s)-1]}
}

// Summarize groups lines by group, in first-seen order.
func Summarize(lines []Line) []Stats {
	var order []string
	by := map[string]*Stats{}
	complete := map[string][]float64{}
	first := map[string][]float64{}
	for _, l := range lines {
		s, ok := by[l.Group]
		if !ok {
			s = &Stats{Group: l.Group, Statuses: map[string]int{}, Completes: map[string]int{}}
			by[l.Group] = s
			order = append(order, l.Group)
		}
		s.Attempts++
		s.Statuses[l.Status.Code+"/"+l.Status.Reason]++
		if l.Stream.Reason != "" {
			s.Completes[l.Stream.Reason]++
		}
		if l.Stream.Delivered {
			s.Delivered++
		}
		s.Violations += len(l.Stream.Violations)
		if l.Timing.CompleteMS >= 0 {
			complete[l.Group] = append(complete[l.Group], l.Timing.CompleteMS)
		}
		if len(l.Timing.OutcomeMS) > 0 {
			first[l.Group] = append(first[l.Group], l.Timing.OutcomeMS[0])
		}
	}
	out := make([]Stats, 0, len(order))
	for _, g := range order {
		s := by[g]
		s.CompleteMS, s.FirstOutcomeMS = Of(complete[g]), Of(first[g])
		out = append(out, *s)
	}
	return out
}
