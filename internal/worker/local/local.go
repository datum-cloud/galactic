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
	// PodAccess is nil when Worker can open and enter a pod's network
	// namespace, which a routed link's pod end needs (PodAccess), and the
	// reason otherwise. local.routed_link and local.socket are then
	// unavailable with ReasonRoutedLinkUnavailable.
	PodAccess error
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
	// egressErrs are why each scope's routed links carry no egress
	// datapath, as its last Apply found.
	egressErrs map[string]map[string]error
	// blocked are each scope's claims whose routed link cannot carry their
	// Fabric destinations, from its last Read.
	blocked map[string]map[module.ClaimKey]module.Blocked
	// handoffs are each scope's handoff interfaces from its last Read.
	handoffs map[string]map[module.ClaimKey][]module.HandoffInterface
	// neighborWait are the scopes with a failed neighbor.
	neighborWait map[string]bool
}

var (
	_ module.Module          = (*Module)(nil)
	_ module.HandoffReporter = (*Module)(nil)
	_ module.HandoffGate     = (*Module)(nil)
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
		errs: map[string]map[string]error{}, egressErrs: map[string]map[string]error{},
		blocked:      map[string]map[module.ClaimKey]module.Blocked{},
		handoffs:     map[string]map[module.ClaimKey][]module.HandoffInterface{},
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
		return caps
	}
	if err := m.cfg.PodAccess; err != nil {
		for i := range caps {
			if caps[i].Name == workerv1alpha1.CapabilityLocalRoutedLink ||
				caps[i].Name == workerv1alpha1.CapabilityLocalSocket {
				caps[i].Available = false
				caps[i].Reason = workerv1alpha1.ReasonRoutedLinkUnavailable
				caps[i].Message = err.Error()
			}
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
	// detail names the first difference Plan found, when it knows it.
	detail string
	// retry is set when the scope's last Apply left a link it could not
	// create, which this change tries again.
	retry bool
	// planned is set when the difference follows from desired state, such
	// as another scope's TAP claim changing the receiving devices.
	planned bool
	// keepEdge leaves the scope's edge links as they are: a handback
	// returns them to galactic-edge, which registers them again with the
	// same rows (docs/worker/connector.md#rollback).
	keepEdge bool
}

// Empty implements module.Change.
func (c *change) Empty() bool { return !c.dirty }

// Drift implements module.DriftDescriber.
func (c *change) Drift() (string, bool) {
	if c.retry || c.planned {
		return "", false
	}
	if c.detail == "" {
		return "the host differs from desired", true
	}
	return c.detail, true
}

// Plan implements module.Module. It computes the scope's desired Local state
// and checks the host against it without writing.
func (m *Module) Plan(ctx context.Context, scope module.Scope, desired []module.Claim) (module.Change, error) {
	return m.plan(ctx, scope, desired, false)
}

// plan is Plan, leaving the scope's edge links alone when keepEdge is set.
func (m *Module) plan(_ context.Context, scope module.Scope, desired []module.Claim, keepEdge bool) (*change, error) {
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
	retry := len(m.errs[vpc]) > 0 || len(m.egressErrs[vpc]) > 0
	m.mu.Unlock()

	ch := &change{vpc: vpc, m: want, edge: edgeClaims(desired), retry: retry, keepEdge: keepEdge}
	if err := m.cfg.Kernel.Loaded(); err != nil {
		// Worker programs no destination whose capability is unavailable,
		// and leaves whatever an earlier Worker wrote until it can read it.
		return ch, nil
	}
	ep := &edgePlan{}
	if !keepEdge {
		var err error
		if ep, err = m.planEdge(vpc, ch.edge); err != nil {
			return nil, fmt.Errorf("local: plan edge links of %s: %w", vpc, err)
		}
	}
	if ep.dirty() {
		ch.dirty, ch.detail = true, "an edge link's registration or pass-through entries differ from its claim"
	}
	_, err := m.cfg.Kernel.ensure(want, true)
	if err == nil {
		err = m.cfg.Kernel.ensureReceivers(anyTap, true)
	}
	switch {
	case errors.Is(err, errDirty):
		ch.dirty = true
		ch.detail, ch.planned = dirtyDetail(err)
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
	if !ch.keepEdge {
		ep, err := m.planEdge(ch.vpc, ch.edge)
		if err != nil {
			return fmt.Errorf("local: plan edge links of %s: %w", ch.vpc, err)
		}
		if err := applyEdge(m.cfg.Kernel.edgeHost(), ep); err != nil {
			return err
		}
	}
	for name, e := range res.errs {
		m.cfg.Log.Info("a routed link could not be created; retrying on the next change", "vpc", ch.vpc,
			"link", name, "error", e)
	}
	for name, e := range res.egress {
		m.cfg.Log.Info("a routed link carries no egress datapath; its claim's Fabric destinations are unreachable",
			"vpc", ch.vpc, "link", name, "error", e)
	}
	m.mu.Lock()
	m.errs[ch.vpc] = res.errs
	m.egressErrs[ch.vpc] = res.egress
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
	egressErrs := m.egressErrs[vpc]
	m.mu.Unlock()
	plain := slices.DeleteFunc(slices.Clone(claims), func(c module.Claim) bool { return c.EdgeLink != nil })
	res, err := m.cfg.Kernel.read(vpc, m.cfg.Node, plain, desire(vpc, plain), errs, egressErrs)
	if err != nil {
		return nil, fmt.Errorf("local: read %s: %w", vpc, err)
	}
	if err := readEdge(m.cfg.Kernel.edgeHost(), m.cfg.Node, vpc, claims, res.state); err != nil {
		return nil, fmt.Errorf("local: read edge links of %s: %w", vpc, err)
	}
	m.mu.Lock()
	m.handoffs[vpc] = res.handoffs
	m.blocked[vpc] = res.blocked
	if res.failedNeighbors {
		m.neighborWait[vpc] = true
	} else {
		delete(m.neighborWait, vpc)
	}
	m.mu.Unlock()
	return res.state, nil
}

// Release removes everything Local programmed for scope: its handoff links,
// its filters and the pass-through entries it owns, as applying a scope with
// no claims does. galactic-worker handback calls it for each scope it hands
// back, after Worker has stopped. Unlike Plan, it fails when the Local
// programs cannot be loaded, since it then could not tell what is left.
func (m *Module) Release(ctx context.Context, scope module.Scope) error {
	if err := m.cfg.Kernel.Loaded(); err != nil {
		return fmt.Errorf("local: release %s: %w", scope.VPC, err)
	}
	// One scope can be named with or without the zero padding of a VRF
	// name, and Local names its links after the form its claims used.
	forms, err := m.cfg.Kernel.vpcForms(scope.VPC)
	if err != nil {
		return err
	}
	for _, vpc := range forms {
		s := module.Scope{VPC: vpc}
		// Edge links stay registered: galactic-edge takes them back.
		ch, err := m.plan(ctx, s, nil, true)
		if err != nil {
			return err
		}
		if ch.Empty() {
			continue
		}
		if err := m.Apply(ctx, s, ch); err != nil {
			return err
		}
	}
	return nil
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

// HandoffBlocked implements module.HandoffGate. A routed link carries its
// claim's Fabric destinations only while it carries the egress datapath; a
// claim whose link does not reports them not forward-ready. Its Local
// destinations, which the kernel reaches through the link either way, are
// judged on their own.
func (m *Module) HandoffBlocked(scope module.Scope, mode workerv1alpha1.Mode) map[module.ClaimKey]module.Blocked {
	if mode != workerv1alpha1.Mode_MODE_FABRIC {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[module.ClaimKey]module.Blocked, len(m.blocked[scope.VPC]))
	for k, b := range m.blocked[scope.VPC] {
		out[k] = b
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
