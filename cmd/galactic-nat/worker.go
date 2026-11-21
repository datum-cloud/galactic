// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"sort"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	workerv1alpha1 "go.datum.net/galactic/api/galactic/worker/v1alpha1"
	"go.datum.net/galactic/pkg/workerclient"
)

// Local shard delivery through Galactic Worker (docs/worker/contract.md).
//
// A tenant on this node reaches this shard through its VPC's
// service-internal veth pair rather than over the fabric. This shard asks
// Worker for one local.veth_pair claim per VPC with a tenant attachment on
// this node, naming its own EgressShard as both the claim's attachment and
// its one destination. Worker creates the pair and reports its NAT end and
// the SID naming the VPC on this node; this shard runs nat_ingress native on
// that end and writes the rows that key the VPC's sessions by that SID and
// return their replies into the pair.

// claimGeneration is the generation of every claim this shard makes. A
// claim's spec never changes for a given key (the key names the shard and
// the spec names the same shard), so it never needs another.
const claimGeneration = 1

// shardIdentity is this node's own EgressShard.
type shardIdentity struct {
	Name string
	UID  string
}

func (s shardIdentity) valid() bool { return s.Name != "" && s.UID != "" }

// localTarget is a pair Worker reported for a VPC: the NAT end this shard
// attaches to and the SID that names the VPC on this node.
type localTarget struct {
	VPC        string
	NATName    string
	NATIfindex int
	TenantName string
	TenantSID  netip.Addr
}

// localPlumbing attaches the datapath to a pair and writes its rows.
type localPlumbing interface {
	// Program attaches nat_ingress native to t's NAT end and writes its rows,
	// replacing what an earlier Program wrote for the same VPC.
	Program(t localTarget) error
	// Unprogram removes what Program wrote for t.
	Unprogram(t localTarget) error
	// Prune removes every row and link not among keep, such as those a
	// previous process wrote for a pair that has since gone.
	Prune(keep []localTarget) error
}

// claimAPI is the part of workerclient.Client the manager uses.
type claimAPI interface {
	Request(ctx context.Context, key *workerv1alpha1.ClaimKey, generation uint64,
		spec *workerv1alpha1.ClaimSpec) (*workerv1alpha1.ClaimStatus, error)
	Release(ctx context.Context, key *workerv1alpha1.ClaimKey, generation uint64) (*workerv1alpha1.ClaimStatus, error)
	Observe(ctx context.Context, key *workerv1alpha1.ClaimKey) (statusStream, error)
	Capabilities() *workerv1alpha1.GetCapabilitiesResponse
	Close() error
}

// statusStream is an open Observe stream.
type statusStream interface {
	Recv() (*workerv1alpha1.ClaimStatus, error)
}

// dialFunc opens a Worker session.
type dialFunc func(ctx context.Context) (claimAPI, error)

// vpcState is what the manager knows about one VPC's claim.
type vpcState struct {
	key *workerv1alpha1.ClaimKey
	// requested is set once Worker accepted the claim.
	requested bool
	// statusSeen is set once a status for the claim arrived on the stream.
	statusSeen bool
	// programmed is the pair Program last wrote, if any.
	programmed *localTarget
	ready      bool
	reason     string
}

// natWorker keeps this shard's Worker claims in line with the VPCs it serves.
type natWorker struct {
	node  string
	dial  dialFunc
	plumb localPlumbing
	// retry is how long to wait before dialing again or retrying a failed
	// claim.
	retry time.Duration

	kick chan struct{}

	mu         sync.Mutex
	client     claimAPI
	sessionUp  bool
	caps       []*workerv1alpha1.Capability
	shard      shardIdentity
	wantVPCs   map[string]bool
	vpcs       map[string]*vpcState
	pruned     bool
	lastErrors map[string]string
}

func newNATWorker(node string, dial dialFunc, plumb localPlumbing) *natWorker {
	return &natWorker{node: node, dial: dial, plumb: plumb, retry: 5 * time.Second,
		kick: make(chan struct{}, 1), wantVPCs: map[string]bool{}, vpcs: map[string]*vpcState{},
		lastErrors: map[string]string{}}
}

func (w *natWorker) nudge() {
	select {
	case w.kick <- struct{}{}:
	default:
	}
}

// SetShard records this node's EgressShard. A change releases every claim
// made for the previous one.
func (w *natWorker) SetShard(id shardIdentity) {
	w.mu.Lock()
	changed := w.shard != id
	w.shard = id
	w.mu.Unlock()
	if changed {
		w.nudge()
	}
}

// SetVPCs records the VPCs with a tenant attachment on this node.
func (w *natWorker) SetVPCs(vpcs []string) {
	want := map[string]bool{}
	for _, v := range vpcs {
		if v != "" {
			want[v] = true
		}
	}
	w.mu.Lock()
	changed := len(want) != len(w.wantVPCs)
	for v := range want {
		if !w.wantVPCs[v] {
			changed = true
		}
	}
	w.wantVPCs = want
	w.mu.Unlock()
	if changed {
		w.nudge()
	}
}

// Run keeps a Worker session open and the claims current until ctx ends.
func (w *natWorker) Run(ctx context.Context) {
	for ctx.Err() == nil {
		c, err := w.dial(ctx)
		if err != nil {
			slog.Warn("Cannot open a Galactic Worker session; local shard delivery waits", "err", err)
			w.setSession(nil, false)
			if !sleepCtx(ctx, w.retry) {
				return
			}
			continue
		}
		w.setSession(c, true)
		w.serve(ctx, c)
		w.setSession(nil, false)
		_ = c.Close()
		if !sleepCtx(ctx, w.retry) {
			return
		}
	}
}

// serve runs one session: it observes every claim of this shard and
// reconciles claims on every nudge, until the stream fails or ctx ends.
func (w *natWorker) serve(ctx context.Context, c claimAPI) {
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// A new session may be a restarted Worker: every claim is requested
	// again, which Worker answers as a duplicate when it kept it.
	w.mu.Lock()
	for _, s := range w.vpcs {
		s.requested = false
	}
	w.mu.Unlock()

	stream, err := c.Observe(sctx, nil)
	if err != nil {
		slog.Warn("Cannot observe Galactic Worker claims", "err", err)
		return
	}
	streamDone := make(chan error, 1)
	go func() {
		for {
			st, err := stream.Recv()
			if err != nil {
				streamDone <- err
				return
			}
			w.handleStatus(st)
		}
	}()

	ticker := time.NewTicker(w.retry)
	defer ticker.Stop()
	for {
		w.reconcile(sctx, c)
		select {
		case <-ctx.Done():
			return
		case err := <-streamDone:
			if ctx.Err() == nil {
				slog.Warn("Galactic Worker claim stream ended; reopening the session", "err", err)
			}
			return
		case <-w.kick:
		case <-ticker.C:
		}
	}
}

func (w *natWorker) setSession(c claimAPI, up bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.client = c
	w.sessionUp = up
	w.caps = nil
	if c != nil {
		w.caps = c.Capabilities().GetCapabilities()
	}
}

// claimKey is the key of this shard's claim in vpc.
func (w *natWorker) claimKey(vpc string, shard shardIdentity) *workerv1alpha1.ClaimKey {
	return &workerv1alpha1.ClaimKey{Node: w.node, Vpc: vpc, AttachmentUid: shard.UID}
}

func claimSpec(shard shardIdentity) *workerv1alpha1.ClaimSpec {
	return &workerv1alpha1.ClaimSpec{
		Handoff: workerv1alpha1.Handoff_HANDOFF_VETH_PAIR,
		Mode:    workerv1alpha1.Mode_MODE_AUTO,
		Destinations: []*workerv1alpha1.Destination{{
			Target: &workerv1alpha1.Destination_Shard{Shard: &workerv1alpha1.ShardRef{Name: shard.Name}},
		}},
	}
}

// reconcile requests a claim for every wanted VPC, releases every claim no
// longer wanted, or made for another shard, and prunes rows a previous
// process left once every claim has reported.
func (w *natWorker) reconcile(ctx context.Context, c claimAPI) {
	w.mu.Lock()
	shard := w.shard
	type op struct {
		vpc     string
		key     *workerv1alpha1.ClaimKey
		release bool
		target  *localTarget
	}
	var ops []op
	for vpc, s := range w.vpcs {
		wanted := w.wantVPCs[vpc] && shard.valid() && s.key.GetAttachmentUid() == shard.UID
		if !wanted {
			ops = append(ops, op{vpc: vpc, key: s.key, release: true, target: s.programmed})
		}
	}
	if shard.valid() {
		for vpc := range w.wantVPCs {
			s := w.vpcs[vpc]
			switch {
			case s == nil:
				w.vpcs[vpc] = &vpcState{key: w.claimKey(vpc, shard)}
				ops = append(ops, op{vpc: vpc, key: w.vpcs[vpc].key})
			case s.key.GetAttachmentUid() == shard.UID && !s.requested:
				ops = append(ops, op{vpc: vpc, key: s.key})
			}
			// A claim made for another shard is released above; this VPC's
			// claim for the current shard follows on the next pass.
		}
	}
	w.mu.Unlock()
	sort.Slice(ops, func(i, j int) bool { return ops[i].vpc < ops[j].vpc })

	for _, o := range ops {
		if o.release {
			if o.target != nil {
				if err := w.plumb.Unprogram(*o.target); err != nil {
					slog.Error("Failed to remove a local pair's datapath rows", "vpc", o.vpc, "err", err)
					continue
				}
			}
			if _, err := c.Release(ctx, o.key, claimGeneration); err != nil &&
				workerclient.Reason(err) != workerv1alpha1.ReasonClaimNotFound {
				w.noteError(o.vpc, err)
				continue
			}
			w.mu.Lock()
			if s := w.vpcs[o.vpc]; s != nil && s.key.GetAttachmentUid() == o.key.GetAttachmentUid() {
				delete(w.vpcs, o.vpc)
			}
			w.mu.Unlock()
			// A claim for the current shard in a VPC still wanted is made on
			// the next pass.
			w.nudge()
			continue
		}
		_, err := c.Request(ctx, o.key, claimGeneration, claimSpec(shard))
		if err != nil && !alreadyClaimed(err) {
			w.noteError(o.vpc, err)
			continue
		}
		w.mu.Lock()
		if s := w.vpcs[o.vpc]; s != nil && s.key.GetAttachmentUid() == o.key.GetAttachmentUid() {
			s.requested = true
		}
		delete(w.lastErrors, o.vpc)
		w.mu.Unlock()
	}
	w.pruneOnce()
}

// alreadyClaimed reports whether a Request refusal means the claim exists
// already, as after this process restarted with a claim made at a
// generation it no longer remembers.
func alreadyClaimed(err error) bool {
	return status.Code(err) == codes.FailedPrecondition &&
		workerclient.Reason(err) == workerv1alpha1.ReasonClaimExists
}

func (w *natWorker) noteError(vpc string, err error) {
	reason := workerclient.Reason(err)
	if reason == "" {
		reason = status.Code(err).String()
	}
	w.mu.Lock()
	first := w.lastErrors[vpc] != reason
	w.lastErrors[vpc] = reason
	if s := w.vpcs[vpc]; s != nil {
		s.ready, s.reason = false, reason
	}
	w.mu.Unlock()
	if first {
		slog.Warn("Galactic Worker refused this shard's claim", "vpc", vpc, "reason", reason, "err", err)
	}
}

// pruneOnce removes rows and links a previous process left, once every claim
// has reported a status in this process, so a pair still in use keeps its
// rows while Worker reports it again.
func (w *natWorker) pruneOnce() {
	w.mu.Lock()
	if w.pruned || !w.sessionUp {
		w.mu.Unlock()
		return
	}
	var keep []localTarget
	for vpc := range w.wantVPCs {
		s := w.vpcs[vpc]
		if s == nil || !s.statusSeen {
			w.mu.Unlock()
			return
		}
	}
	for _, s := range w.vpcs {
		if s.programmed != nil {
			keep = append(keep, *s.programmed)
		}
	}
	w.mu.Unlock()
	if err := w.plumb.Prune(keep); err != nil {
		slog.Error("Failed to remove stale local pair rows", "err", err)
		return
	}
	w.mu.Lock()
	w.pruned = true
	w.mu.Unlock()
}

// handleStatus programs or removes a VPC's pair from one claim status.
func (w *natWorker) handleStatus(st *workerv1alpha1.ClaimStatus) {
	key := st.GetKey()
	vpc := key.GetVpc()
	w.mu.Lock()
	s := w.vpcs[vpc]
	if s == nil || s.key.GetAttachmentUid() != key.GetAttachmentUid() {
		w.mu.Unlock()
		return
	}
	s.statusSeen = true
	prev := s.programmed
	w.mu.Unlock()

	ready, reason := claimReadiness(st)
	target, ok := natTarget(vpc, st)
	withdrawing := st.GetReleased() || condTrue(st, workerv1alpha1.ConditionWithdrawing)

	var next *localTarget
	switch {
	case withdrawing || !ok:
		if prev != nil {
			if err := w.plumb.Unprogram(*prev); err != nil {
				slog.Error("Failed to remove a local pair's datapath rows", "vpc", vpc, "err", err)
				next = prev
			}
		}
	case prev != nil && *prev == target:
		next = prev
	default:
		if prev != nil && (prev.NATIfindex != target.NATIfindex || prev.TenantSID != target.TenantSID) {
			if err := w.plumb.Unprogram(*prev); err != nil {
				slog.Error("Failed to remove a replaced local pair's datapath rows", "vpc", vpc, "err", err)
			}
		}
		if err := w.plumb.Program(target); err != nil {
			slog.Error("Failed to attach to a local pair", "vpc", vpc, "natEnd", target.NATName, "err", err)
			reason = "AttachFailed"
			ready = false
		} else {
			t := target
			next = &t
			slog.Info("Serving a VPC through its local pair", "vpc", vpc, "natEnd", target.NATName,
				"ifindex", target.NATIfindex, "tenantSID", target.TenantSID)
		}
	}

	w.mu.Lock()
	if s := w.vpcs[vpc]; s != nil && s.key.GetAttachmentUid() == key.GetAttachmentUid() {
		s.programmed = next
		s.ready, s.reason = ready, reason
	}
	w.mu.Unlock()
}

// natTarget reads the NAT end, tenant end and tenant SID a claim status
// reports.
func natTarget(vpc string, st *workerv1alpha1.ClaimStatus) (localTarget, bool) {
	t := localTarget{VPC: vpc}
	for _, h := range st.GetHandoffInterfaces() {
		switch h.GetRole() {
		case workerv1alpha1.HandoffRoleNAT:
			t.NATName, t.NATIfindex = h.GetName(), int(h.GetIfindex())
			if sid, err := netip.ParseAddr(h.GetTenantSid()); err == nil && sid.Is6() && !sid.Is4In6() {
				t.TenantSID = sid
			}
		case workerv1alpha1.HandoffRoleTenant:
			t.TenantName = h.GetName()
		}
	}
	return t, t.NATIfindex > 0 && t.NATName != "" && t.TenantSID.IsValid()
}

// claimReadiness reads a claim's Ready condition and its reason.
func claimReadiness(st *workerv1alpha1.ClaimStatus) (bool, string) {
	for _, c := range st.GetConditions() {
		if c.GetType() == workerv1alpha1.ConditionReady {
			return c.GetStatus() == workerv1alpha1.ConditionStatus_CONDITION_STATUS_TRUE, c.GetReason()
		}
	}
	return false, workerv1alpha1.ReasonPending
}

func condTrue(st *workerv1alpha1.ClaimStatus, t string) bool {
	for _, c := range st.GetConditions() {
		if c.GetType() == t {
			return c.GetStatus() == workerv1alpha1.ConditionStatus_CONDITION_STATUS_TRUE
		}
	}
	return false
}

// workerSnapshot is what the metrics read.
type workerSnapshot struct {
	SessionUp    bool
	Capabilities []*workerv1alpha1.Capability
	// VPCs maps each VPC this shard serves to its claim's readiness and
	// reason.
	VPCs map[string]vpcReadiness
}

type vpcReadiness struct {
	Ready  bool
	Reason string
}

func (w *natWorker) snapshot() workerSnapshot {
	w.mu.Lock()
	defer w.mu.Unlock()
	snap := workerSnapshot{SessionUp: w.sessionUp, Capabilities: slices.Clone(w.caps),
		VPCs: map[string]vpcReadiness{}}
	for vpc := range w.wantVPCs {
		r := vpcReadiness{Reason: workerv1alpha1.ReasonPending}
		if !w.shard.valid() {
			r.Reason = "ShardNotProgrammed"
		} else if !w.sessionUp {
			r.Reason = "NoSession"
		}
		if s := w.vpcs[vpc]; s != nil && w.sessionUp {
			r = vpcReadiness{Ready: s.ready, Reason: s.reason}
			if r.Reason == "" && !r.Ready {
				r.Reason = workerv1alpha1.ReasonPending
			}
		}
		snap.VPCs[vpc] = r
	}
	return snap
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// workerclientDial adapts workerclient.Dial to dialFunc.
func workerclientDial(socket, tokenFile string) dialFunc {
	return func(ctx context.Context) (claimAPI, error) {
		c, err := workerclient.Dial(ctx, workerclient.Options{SocketPath: socket, TokenFile: tokenFile})
		if err != nil {
			return nil, fmt.Errorf("dial galactic-worker at %s: %w", socket, err)
		}
		return clientAdapter{c}, nil
	}
}

// clientAdapter narrows workerclient.Client to claimAPI.
type clientAdapter struct{ *workerclient.Client }

func (a clientAdapter) Observe(ctx context.Context, key *workerv1alpha1.ClaimKey) (statusStream, error) {
	o, err := a.Client.Observe(ctx, key)
	if err != nil {
		return nil, err
	}
	return o, nil
}
