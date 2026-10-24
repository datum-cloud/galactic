// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package diagtest captures the Galactic Edge foundation's diagnostic Events
// in tests.
package diagtest

import (
	"fmt"
	"strings"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"

	"go.datum.net/galactic/internal/edge/diag"
)

// Event is one recorded Event.
type Event struct {
	// Regarding is the object's type, as %T prints it, then its namespace
	// and name.
	Regarding                  string
	Namespace, Name            string
	Type, Reason, Action, Note string
}

// Correlation returns the key=value pairs after the note's " | ".
func (e Event) Correlation() map[string]string {
	out := map[string]string{}
	_, corr, ok := strings.Cut(e.Note, " | ")
	if !ok {
		return out
	}
	for kv := range strings.FieldsSeq(corr) {
		if k, v, ok := strings.Cut(kv, "="); ok {
			out[k] = v
		}
	}
	return out
}

// Recorder is an events.EventRecorder that keeps every Event.
type Recorder struct {
	mu     sync.Mutex
	events []Event
}

// Eventf implements events.EventRecorder.
func (r *Recorder) Eventf(regarding, _ runtime.Object, eventtype, reason, action, note string, args ...any) {
	e := Event{Regarding: fmt.Sprintf("%T", regarding), Type: eventtype, Reason: reason, Action: action,
		Note: fmt.Sprintf(note, args...)}
	if m, err := meta.Accessor(regarding); err == nil {
		e.Namespace, e.Name = m.GetNamespace(), m.GetName()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
}

// Events returns the recorded Events, oldest first.
func (r *Recorder) Events() []Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Event(nil), r.events...)
}

// Find returns the recorded Events with action and reason.
func (r *Recorder) Find(action diag.Stage, reason string) []Event {
	var out []Event
	for _, e := range r.Events() {
		if e.Action == string(action) && e.Reason == reason {
			out = append(out, e)
		}
	}
	return out
}

// New returns a diag.Recorder recording into a new Recorder and counting
// into a new registry.
func New(component string) (*diag.Recorder, *Recorder, *prometheus.Registry) {
	events := &Recorder{}
	reg := prometheus.NewRegistry()
	return &diag.Recorder{Events: events, Metrics: diag.NewMetrics(reg, component)}, events, reg
}
