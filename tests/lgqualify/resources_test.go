// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package lgqualify_test

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
)

// maxJobGoroutines is the contract's cap on service job goroutines.
const maxJobGoroutines = 512

// usage is one process's peak resident memory and goroutines over the
// run, with its first goroutine count as a baseline.
type usage struct {
	PeakRSS        float64 `json:"peakRssBytes"`
	PeakGoroutines float64 `json:"peakGoroutines"`
	BaseGoroutines float64 `json:"baseGoroutines"`
	LimitBytes     int64   `json:"memoryLimitBytes,omitempty"`
	Samples        int     `json:"samples"`
}

// sampler records every gateway's and sidecar's usage every 5 s.
type sampler struct {
	mu   sync.Mutex
	use  map[string]*usage
	stop chan struct{}
	done chan struct{}
}

func (s *sampler) observe(key, text string, limit int64) {
	rss, ok1 := metricValue(text, "process_resident_memory_bytes")
	gr, ok2 := metricValue(text, "go_goroutines")
	if !ok1 || !ok2 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.use[key]
	if !ok {
		u = &usage{BaseGoroutines: gr, LimitBytes: limit}
		s.use[key] = u
	}
	u.PeakRSS, u.PeakGoroutines = max(u.PeakRSS, rss), max(u.PeakGoroutines, gr)
	u.Samples++
}

func memoryLimit(p corev1.Pod, container string) int64 {
	for _, c := range p.Spec.Containers {
		if c.Name == container {
			return c.Resources.Limits.Memory().Value()
		}
	}
	return 0
}

// startSampler samples until the returned sampler is closed.
func (l *lab) startSampler(ctx context.Context) *sampler {
	s := &sampler{use: map[string]*usage{}, stop: make(chan struct{}), done: make(chan struct{})}
	go func() {
		defer close(s.done)
		t := time.NewTicker(5 * time.Second)
		defer t.Stop()
		for {
			if gws, err := l.gatewayPods(ctx); err == nil {
				for _, p := range gws {
					if text, err := l.gatewayMetrics(ctx, p); err == nil {
						s.observe("gateway/"+p.Name, text, memoryLimit(p, "gateway"))
					}
				}
			}
			if frs, err := l.frrPods(ctx); err == nil {
				if nm, err := l.nodeMetrics(ctx); err == nil {
					for node, text := range nm {
						s.observe("sidecar/"+node, text, memoryLimit(frs[node], "fabric-api"))
					}
				}
			}
			select {
			case <-s.stop:
				return
			case <-t.C:
			}
		}
	}()
	return s
}

func (s *sampler) close() map[string]usage {
	close(s.stop)
	<-s.done
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]usage{}
	for k, v := range s.use {
		out[k] = *v
	}
	return out
}

// resources judges the run's peak usage: under each container's memory
// limit, and goroutines within the service's job cap of their baseline.
func resources(t *testing.T, ev *evidence, use map[string]usage) {
	ev.Thresholds = map[string]any{
		"rss": "below the container memory limit", "goroutines": fmt.Sprintf("baseline + %d", maxJobGoroutines),
	}
	ev.Observed["usage"] = use
	if len(use) == 0 {
		t.Fatal("no usage sample was taken")
	}
	for k, u := range use {
		if u.LimitBytes > 0 && u.PeakRSS >= float64(u.LimitBytes) {
			t.Errorf("%s: peak RSS %.0f reached its limit %d", k, u.PeakRSS, u.LimitBytes)
		}
		if u.PeakGoroutines > u.BaseGoroutines+maxJobGoroutines {
			t.Errorf("%s: %0.f goroutines, over baseline %.0f + %d", k, u.PeakGoroutines, u.BaseGoroutines, maxJobGoroutines)
		}
	}
}
