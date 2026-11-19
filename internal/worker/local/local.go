// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package local is Galactic Worker's Local delivery module (#1435). It
// delivers between a service's handoff point and tenant destinations on this
// node through the handoffs docs/worker/contract.md#local-handoffs
// specifies:
//
//   - local.tap: a public packet a dispatcher slot program marked for a
//     tenant TAP is delivered by local_rx on the receiving device, and the
//     guest's reply leaves through the device it arrived on;
//   - local.veth_pair: a service-internal veth pair per VPC and claim, whose
//     NAT end the client attaches its native XDP program to; tenant flows
//     enter the pair and the pair's return is delivered to the tenant;
//   - local.routed_link and local.socket: a veth from the VPC's VRF to the
//     owner's pod, whose pod end the pod configures.
//
// The module separates link lifecycle from program ownership. CNI creates
// and deletes tenant interfaces; the module only attaches its own tc
// programs and rows to them, keyed by their current ifindex, and reprograms
// on a replacement. The module creates and deletes the pairs and routed
// links itself. It is the only writer of its tc filters (internal
// /plumbing/ebpf/attach.AttachLocal) and its lt_* maps.
//
// Programmed state is what the module wrote, read back. Observed state, which
// Ready reports, is what it did not write: the tenant interface with carrier
// and galactic-cni's chain, a live dispatcher slot on a receiving device, the
// client's XDP program on the NAT end, the MTUs and the neighbor.
package local

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"

	workerv1alpha1 "go.datum.net/galactic/api/galactic/worker/v1alpha1"
	"go.datum.net/galactic/internal/worker/module"
)

// Name is the module's name.
const Name = "local"

// Config configures a Module.
type Config struct {
	// Kernel is the host access.
	Kernel *Kernel
	// Node is this node, the node of every claim key.
	Node string
	Log  *slog.Logger
}

// Module is the Local delivery module.
type Module struct {
	cfg Config

	mu sync.Mutex
	// desired is each scope's claims from its last Plan.
	desired map[string][]module.Claim
	// tapScopes are the scopes with a local.tap claim.
	tapScopes map[string]bool
	// errs are the per-link errors of each scope's last Apply.
	errs map[string]map[string]error
	// handoffs are each scope's handoff interfaces from its last Read.
	handoffs map[string]map[module.ClaimKey][]module.HandoffInterface
	// neighborWait are the scopes with a failed neighbor.
	neighborWait map[string]bool
}

var (
	_ module.Module          = (*Module)(nil)
	_ module.HandoffReporter = (*Module)(nil)
)

// New returns a Local module.
func New(cfg Config) (*Module, error) {
	if cfg.Kernel == nil || cfg.Node == "" {
		return nil, errors.New("local: kernel and node are required")
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	cfg.Log = cfg.Log.With("module", Name)
	return &Module{cfg: cfg, desired: map[string][]module.Claim{}, tapScopes: map[string]bool{},
		errs: map[string]map[string]error{}, handoffs: map[string]map[module.ClaimKey][]module.HandoffInterface{},
		neighborWait: map[string]bool{}}, nil
}

// Name implements module.Module.
func (m *Module) Name() string { return Name }

// Mode implements module.Module.
func (m *Module) Mode() workerv1alpha1.Mode { return workerv1alpha1.Mode_MODE_LOCAL }

// Capabilities implements module.Module. Every Local capability needs the
// Local programs loaded against the pinned uSID datapath.
func (m *Module) Capabilities() []module.Capability {
	caps := []module.Capability{
		{Name: workerv1alpha1.CapabilityLocalTap, Available: true},
		{Name: workerv1alpha1.CapabilityLocalVethPair, Available: true},
		{Name: workerv1alpha1.CapabilityLocalRoutedLink, Available: true},
		{Name: workerv1alpha1.CapabilityLocalSocket, Available: true},
	}
	if err := m.cfg.Kernel.Loaded(); err != nil {
		for i := range caps {
			caps[i].Available = false
			caps[i].Reason = workerv1alpha1.ReasonDatapathNotLoaded
			caps[i].Message = err.Error()
		}
	}
	return caps
}

// change is the Local module's change for one scope: the model to ensure,
// and the connector claims whose edge links to register.
type change struct {
	vpc   string
	m     *model
	edge  []module.Claim
	dirty bool
}

// Empty implements module.Change.
func (c *change) Empty() bool { return !c.dirty }

// Plan implements module.Module. It computes the scope's desired Local state
// and checks the host against it without writing.
func (m *Module) Plan(_ context.Context, scope module.Scope, desired []module.Claim) (module.Change, error) {
	vpc := scope.VPC
	want := desire(vpc, desired)
	m.mu.Lock()
	if len(desired) > 0 {
		m.desired[vpc] = desired
	} else {
		delete(m.desired, vpc)
	}
	if want.tap {
		m.tapScopes[vpc] = true
	} else {
		delete(m.tapScopes, vpc)
	}
	anyTap := len(m.tapScopes) > 0
	m.mu.Unlock()

	ch := &change{vpc: vpc, m: want, edge: edgeClaims(desired)}
	if err := m.cfg.Kernel.Loaded(); err != nil {
		// Worker programs no destination whose capability is unavailable,
		// and leaves whatever an earlier Worker wrote until it can read it.
		return ch, nil
	}
	ep, err := m.planEdge(vpc, ch.edge)
	if err != nil {
		return nil, fmt.Errorf("local: plan edge links of %s: %w", vpc, err)
	}
	ch.dirty = ep.dirty()
	_, err = m.cfg.Kernel.ensure(want, true)
	if err == nil {
		err = m.cfg.Kernel.ensureReceivers(anyTap, true)
	}
	switch {
	case errors.Is(err, errDirty):
		ch.dirty = true
	case err != nil:
		return nil, fmt.Errorf("local: plan %s: %w", vpc, err)
	}
	return ch, nil
}

// Apply implements module.Module.
func (m *Module) Apply(_ context.Context, scope module.Scope, c module.Change) error {
	ch, ok := c.(*change)
	if !ok || ch.vpc != scope.VPC {
		return fmt.Errorf("local: change for another scope than %s", scope.VPC)
	}
	res, err := m.cfg.Kernel.ensure(ch.m, false)
	if err != nil {
		return err
	}
	// The edge plan is made again under the commit's lock, from the host as
	// it stands now.
	ep, err := m.planEdge(ch.vpc, ch.edge)
	if err != nil {
		return fmt.Errorf("local: plan edge links of %s: %w", ch.vpc, err)
	}
	if err := applyEdge(m.cfg.Kernel.edgeHost(), ep); err != nil {
		return err
	}
	for name, e := range res.errs {
		m.cfg.Log.Info("a routed link could not be created; retrying on the next change", "vpc", ch.vpc,
			"link", name, "error", e)
	}
	m.mu.Lock()
	m.errs[ch.vpc] = res.errs
	anyTap := len(m.tapScopes) > 0
	m.mu.Unlock()
	if err := m.cfg.Kernel.ensureReceivers(anyTap, false); err != nil {
		return err
	}
	if err := m.cfg.Kernel.purgeFlows(); err != nil {
		m.cfg.Log.Warn("removing the flows of released TAPs failed", "error", err)
	}
	return nil
}

// Read implements module.Module.
func (m *Module) Read(_ context.Context, scope module.Scope) (module.State, error) {
	vpc := scope.VPC
	m.mu.Lock()
	claims := m.desired[vpc]
	errs := m.errs[vpc]
	m.mu.Unlock()
	plain := slices.DeleteFunc(slices.Clone(claims), func(c module.Claim) bool { return c.EdgeLink != nil })
	res, err := m.cfg.Kernel.read(vpc, m.cfg.Node, plain, desire(vpc, plain), errs)
	if err != nil {
		return nil, fmt.Errorf("local: read %s: %w", vpc, err)
	}
	if err := readEdge(m.cfg.Kernel.edgeHost(), m.cfg.Node, vpc, claims, res.state); err != nil {
		return nil, fmt.Errorf("local: read edge links of %s: %w", vpc, err)
	}
	m.mu.Lock()
	m.handoffs[vpc] = res.handoffs
	if res.failedNeighbors {
		m.neighborWait[vpc] = true
	} else {
		delete(m.neighborWait, vpc)
	}
	m.mu.Unlock()
	return res.state, nil
}

// HandoffInterfaces implements module.HandoffReporter.
func (m *Module) HandoffInterfaces(scope module.Scope) map[module.ClaimKey][]module.HandoffInterface {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[module.ClaimKey][]module.HandoffInterface{}
	for k, v := range m.handoffs[scope.VPC] {
		out[k] = append([]module.HandoffInterface(nil), v...)
	}
	return out
}

// planEdge plans the scope's edge links against the host as it stands.
func (m *Module) planEdge(vpc string, edge []module.Claim) (*edgePlan, error) {
	table, _, haveVRF, err := tableID(vpc)
	if err != nil {
		return nil, err
	}
	return planEdge(m.cfg.Kernel.edgeHost(), vpc, table, haveVRF, edge)
}

// tapVPCs returns the scopes with a local.tap claim.
func (m *Module) tapVPCs() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return sortedKeys(m.tapScopes)
}

// neighborVPCs returns the scopes waiting on a failed neighbor.
func (m *Module) neighborVPCs() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return sortedKeys(m.neighborWait)
}
