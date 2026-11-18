// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package fake is a delivery module for tests. It programs rows in a Host
// that outlives the module, so a test can restart Worker over the same host
// state, and it can inject failures, partial writes and pauses at Apply.
package fake

import (
	"context"
	"errors"
	"maps"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	workerv1alpha1 "go.datum.net/galactic/api/galactic/worker/v1alpha1"
	"go.datum.net/galactic/internal/worker/module"
)

// Row is one programmed destination.
type Row struct {
	Key        module.ClaimKey
	ID         string
	Generation uint64
}

// Kernel optionally mirrors every row write into real host state, so a
// privileged test can snapshot it.
type Kernel interface {
	Add(scope module.Scope, r Row) error
	Remove(scope module.Scope, r Row) error
}

// Host is the state a fake module programs, shared across restarts.
type Host struct {
	mu   sync.Mutex
	rows map[string]map[module.ClaimKey]map[string]uint64 // module/VPC → claim → dest → generation
}

// NewHost returns an empty host.
func NewHost() *Host { return &Host{rows: map[string]map[module.ClaimKey]map[string]uint64{}} }

// Rows returns every row of a scope, from every module, sorted.
func (h *Host) Rows(vpc string) []Row {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []Row
	for part, claims := range h.rows {
		if !strings.HasSuffix(part, "/"+vpc) {
			continue
		}
		for k, dests := range claims {
			for id, gen := range dests {
				out = append(out, Row{Key: k, ID: id, Generation: gen})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Key != out[j].Key {
			return out[i].Key.String() < out[j].Key.String()
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// Module is a fake delivery module.
type Module struct {
	ModuleName string
	ModuleMode workerv1alpha1.Mode
	Host       *Host
	Kernel     Kernel

	mu   sync.Mutex
	caps []module.Capability
	// failApply makes the next Apply calls fail after writing at most
	// failAfter rows.
	failApply int
	failAfter int
	// gate, when set, is received from before Apply writes.
	gate        chan struct{}
	entered     chan struct{}
	planGate    chan struct{}
	planEntered chan struct{}
	ready       func(module.ClaimKey, string) (bool, string)

	PlanCalls  atomic.Int64
	ApplyCalls atomic.Int64
	ReadCalls  atomic.Int64
	Writes     atomic.Int64
}

// New returns a fake module for mode, serving every capability of that mode.
func New(name string, mode workerv1alpha1.Mode, host *Host) *Module {
	m := &Module{ModuleName: name, ModuleMode: mode, Host: host}
	if mode == workerv1alpha1.Mode_MODE_FABRIC {
		m.caps = []module.Capability{{Name: workerv1alpha1.CapabilityFabricSRv6, Available: true}}
	} else {
		for _, c := range workerv1alpha1.Capabilities {
			if c != workerv1alpha1.CapabilityFabricSRv6 {
				m.caps = append(m.caps, module.Capability{Name: c, Available: true})
			}
		}
	}
	return m
}

// SetCapability sets one capability's state.
func (m *Module) SetCapability(c module.Capability) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.caps {
		if m.caps[i].Name == c.Name {
			m.caps[i] = c
			return
		}
	}
	m.caps = append(m.caps, c)
}

// FailApply makes the next n Apply calls fail after writing at most after
// rows, leaving a partial commit behind.
func (m *Module) FailApply(n, after int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failApply, m.failAfter = n, after
}

// Pause makes Apply wait at entry until Resume. Entered receives once Apply
// is waiting.
func (m *Module) Pause() (entered <-chan struct{}) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.gate = make(chan struct{})
	m.entered = make(chan struct{}, 1)
	return m.entered
}

// Resume releases a paused Apply.
func (m *Module) Resume() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.gate != nil {
		close(m.gate)
		m.gate = nil
	}
}

// PausePlan makes Plan wait at entry until ResumePlan, holding whatever
// ticket the caller took. Entered receives once Plan is waiting.
func (m *Module) PausePlan() (entered <-chan struct{}) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.planGate = make(chan struct{})
	m.planEntered = make(chan struct{}, 1)
	return m.planEntered
}

// ResumePlan releases a paused Plan.
func (m *Module) ResumePlan() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.planGate != nil {
		close(m.planGate)
		m.planGate = nil
	}
}

// RepausePlan releases the Plan waiting now and makes the next Plan wait.
func (m *Module) RepausePlan() (entered <-chan struct{}) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.planGate != nil {
		close(m.planGate)
	}
	m.planGate = make(chan struct{})
	m.planEntered = make(chan struct{}, 1)
	return m.planEntered
}

// SetReady sets the observed readiness of programmed destinations.
func (m *Module) SetReady(fn func(module.ClaimKey, string) (bool, string)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ready = fn
}

// Name implements module.Module.
func (m *Module) Name() string { return m.ModuleName }

// Mode implements module.Module.
func (m *Module) Mode() workerv1alpha1.Mode { return m.ModuleMode }

// Capabilities implements module.Module.
func (m *Module) Capabilities() []module.Capability {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]module.Capability(nil), m.caps...)
}

// change is the complete desired row set of a scope.
type change struct {
	want  map[module.ClaimKey]map[string]uint64
	empty bool
}

func (c change) Empty() bool { return c.empty }

// Plan implements module.Module.
func (m *Module) Plan(ctx context.Context, scope module.Scope, desired []module.Claim) (module.Change, error) {
	m.PlanCalls.Add(1)
	m.mu.Lock()
	gate, entered := m.planGate, m.planEntered
	m.mu.Unlock()
	if gate != nil {
		select {
		case entered <- struct{}{}:
		default:
		}
		select {
		case <-gate:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	want := map[module.ClaimKey]map[string]uint64{}
	for _, c := range desired {
		for _, d := range c.Destinations {
			if want[c.Key] == nil {
				want[c.Key] = map[string]uint64{}
			}
			want[c.Key][d.ID] = c.Generation
		}
	}
	m.Host.mu.Lock()
	have := m.Host.rows[m.ModuleName+"/"+scope.VPC]
	equal := maps.EqualFunc(want, have, func(a, b map[string]uint64) bool { return maps.Equal(a, b) })
	m.Host.mu.Unlock()
	return change{want: want, empty: equal}, nil
}

var errInjected = errors.New("fake: injected apply failure")

// Apply implements module.Module. It writes the difference row by row, so an
// injected failure leaves a partial commit.
func (m *Module) Apply(ctx context.Context, scope module.Scope, c module.Change) error {
	m.ApplyCalls.Add(1)
	m.mu.Lock()
	gate, entered := m.gate, m.entered
	fail, after := m.failApply > 0, m.failAfter
	if fail {
		m.failApply--
	}
	m.mu.Unlock()
	if gate != nil {
		select {
		case entered <- struct{}{}:
		default:
		}
		select {
		case <-gate:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	want := c.(change).want
	m.Host.mu.Lock()
	defer m.Host.mu.Unlock()
	have := m.Host.rows[m.ModuleName+"/"+scope.VPC]
	if have == nil {
		have = map[module.ClaimKey]map[string]uint64{}
		m.Host.rows[m.ModuleName+"/"+scope.VPC] = have
	}
	written := 0
	step := func() error {
		if fail && written >= after {
			return errInjected
		}
		written++
		m.Writes.Add(1)
		return nil
	}
	// Removals first, in a stable order.
	for _, k := range sortedKeys(have) {
		for _, id := range sortedIDs(have[k]) {
			if g, ok := want[k][id]; ok && g == have[k][id] {
				continue
			}
			if _, keep := want[k][id]; keep {
				continue
			}
			if err := step(); err != nil {
				return err
			}
			if m.Kernel != nil {
				if err := m.Kernel.Remove(scope, Row{Key: k, ID: id, Generation: have[k][id]}); err != nil {
					return err
				}
			}
			delete(have[k], id)
			if len(have[k]) == 0 {
				delete(have, k)
			}
		}
	}
	for _, k := range sortedKeys(want) {
		for _, id := range sortedIDs(want[k]) {
			g := want[k][id]
			if cur, ok := have[k][id]; ok && cur == g {
				continue
			}
			if err := step(); err != nil {
				return err
			}
			if m.Kernel != nil {
				if err := m.Kernel.Add(scope, Row{Key: k, ID: id, Generation: g}); err != nil {
					return err
				}
			}
			if have[k] == nil {
				have[k] = map[string]uint64{}
			}
			have[k][id] = g
		}
	}
	return nil
}

// Read implements module.Module.
func (m *Module) Read(_ context.Context, scope module.Scope) (module.State, error) {
	m.ReadCalls.Add(1)
	m.mu.Lock()
	ready := m.ready
	m.mu.Unlock()
	m.Host.mu.Lock()
	defer m.Host.mu.Unlock()
	out := module.State{}
	for k, dests := range m.Host.rows[m.ModuleName+"/"+scope.VPC] {
		out[k] = map[string]module.DestinationState{}
		for id, g := range dests {
			st := module.DestinationState{Generation: g, Programmed: true, Ready: true}
			if ready != nil {
				ok, reason := ready(k, id)
				st.Ready, st.Reason = ok, reason
			}
			out[k][id] = st
		}
	}
	return out, nil
}

func sortedKeys[V any](m map[module.ClaimKey]V) []module.ClaimKey {
	out := make([]module.ClaimKey, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}

func sortedIDs(m map[string]uint64) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
