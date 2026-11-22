// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package localhandoff delivers a gateway's flows to backends on its own node
// through Galactic Worker's Local handoff (docs/worker/contract.md), rather
// than encapsulating them toward the node's own locator.
//
// Maglev selection is unchanged and shared by every gateway. Locality is
// applied after it: edge_lb looks the selected backend's uSID up in
// edge_local_table, and a row naming a TAP hands the packet to Worker's
// local_rx through the dispatcher's metadata, while a row with no TAP drops
// it. A backend with no row is encapsulated as before. A Local backend is
// never encapsulated: Worker never falls back from Local to Fabric.
//
// The Manager asks Worker for one local.tap claim per backend attachment on
// this node, naming each backend slot the gateway encapsulates toward on it
// as a backend destination, and writes edge_local_table from what Worker
// reports: the TAP's ifindex for a slot whose destination is ready, and no
// TAP otherwise.
package localhandoff

import (
	"context"
	"log/slog"
	"net/netip"
	"slices"
	"sort"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	workerv1alpha1 "go.datum.net/galactic/api/galactic/worker/v1alpha1"
	bgpv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	"go.datum.net/galactic/pkg/workerclient"
)

// Backend is one backend on this gateway's node.
type Backend struct {
	// AttachmentUID is the backend's VPCAttachment UID, the claim's
	// attachment.
	AttachmentUID string
	// VPC is the attachment's VPC identity (VPCAttachment.status.vpc).
	VPC string
	// Slot is the uSID slot the gateway encodes for the backend.
	Slot uint16
	// USID is the uSID the gateway encapsulates toward, edge_local_table's
	// key.
	USID netip.Addr
}

// Table is edge_local_table. The gateway owns every row.
type Table interface {
	// Set writes sid's row. tapIfindex 0 makes edge_lb drop the backend's
	// flows.
	Set(sid netip.Addr, tapIfindex uint32) error
	Delete(sid netip.Addr) error
	List() (map[netip.Addr]uint32, error)
}

// ClaimAPI is the part of workerclient.Client the Manager uses.
type ClaimAPI interface {
	Request(ctx context.Context, key *workerv1alpha1.ClaimKey, generation uint64,
		spec *workerv1alpha1.ClaimSpec) (*workerv1alpha1.ClaimStatus, error)
	Update(ctx context.Context, key *workerv1alpha1.ClaimKey, generation uint64,
		spec *workerv1alpha1.ClaimSpec) (*workerv1alpha1.ClaimStatus, error)
	Release(ctx context.Context, key *workerv1alpha1.ClaimKey, generation uint64) (*workerv1alpha1.ClaimStatus, error)
	Observe(ctx context.Context, key *workerv1alpha1.ClaimKey) (StatusStream, error)
	Close() error
}

// StatusStream is an open Observe stream.
type StatusStream interface {
	Recv() (*workerv1alpha1.ClaimStatus, error)
}

// DialFunc opens a Worker session.
type DialFunc func(ctx context.Context) (ClaimAPI, error)

// AttachmentState is the Local handoff state of one backend attachment.
type AttachmentState struct {
	AttachmentUID string
	Ready         bool
	// Reason is LocalBackendReasonReady, a Worker reason, or
	// LocalBackendReasonWorkerUnavailable.
	Reason string
}

// Snapshot is what diagnostics and metrics read.
type Snapshot struct {
	SessionUp bool
	// Attachments is sorted by AttachmentUID.
	Attachments []AttachmentState
	// TableErrors counts failed edge_local_table writes since start.
	TableErrors uint64
}

// wantClaim is the claim the gateway wants for one attachment.
type wantClaim struct {
	vpc   string
	slots []uint16 // sorted, unique
}

// claimState is a claim Worker holds, or that this process asked for.
type claimState struct {
	key   *workerv1alpha1.ClaimKey
	slots []uint16
	gen   uint64
	// requested is set once Worker accepted the claim in this session.
	requested bool
	// status is the last snapshot Worker reported.
	status *workerv1alpha1.ClaimStatus
}

// Manager keeps the gateway's local.tap claims and edge_local_table in line
// with the backends on this node.
type Manager struct {
	node  string
	dial  DialFunc
	table Table
	// Retry is how long to wait before dialing again or retrying a claim.
	Retry time.Duration

	kick     chan struct{}
	onChange func()

	mu          sync.Mutex
	sessionUp   bool
	everStatus  bool
	want        map[string]wantClaim
	sids        map[netip.Addr]sidRef
	claims      map[string]*claimState
	lastGen     uint64
	tableErrors uint64
	// uplinkMissing is set while this node's public_uplink_table has no
	// next hop (SetUplinkMissing).
	uplinkMissing bool
	lastSnap      []AttachmentState
	lastErr       map[string]string
}

type sidRef struct {
	uid  string
	slot uint16
}

// New returns a Manager for node. onChange, when not nil, is called whenever
// an attachment's readiness changes.
func New(node string, dial DialFunc, table Table, onChange func()) *Manager {
	return &Manager{node: node, dial: dial, table: table, Retry: 5 * time.Second,
		kick: make(chan struct{}, 1), onChange: onChange,
		want: map[string]wantClaim{}, sids: map[netip.Addr]sidRef{},
		claims: map[string]*claimState{}, lastErr: map[string]string{}}
}

func (m *Manager) nudge() {
	select {
	case m.kick <- struct{}{}:
	default:
	}
}

// SetBackends replaces the backends on this node the gateway serves. Every
// one of them gets an edge_local_table row at once, with no TAP until Worker
// reports its handoff ready, so none is ever encapsulated toward this node.
func (m *Manager) SetBackends(backends []Backend) {
	want := map[string]wantClaim{}
	sids := map[netip.Addr]sidRef{}
	for _, b := range backends {
		if b.AttachmentUID == "" || b.VPC == "" || b.Slot == 0 || !b.USID.IsValid() {
			continue
		}
		w := want[b.AttachmentUID]
		w.vpc = b.VPC
		if !slices.Contains(w.slots, b.Slot) {
			w.slots = append(w.slots, b.Slot)
		}
		want[b.AttachmentUID] = w
		sids[b.USID] = sidRef{uid: b.AttachmentUID, slot: b.Slot}
	}
	for uid, w := range want {
		slices.Sort(w.slots)
		want[uid] = w
	}
	m.mu.Lock()
	changed := !wantEqual(m.want, want) || !sidsEqual(m.sids, sids)
	m.want, m.sids = want, sids
	m.mu.Unlock()
	if changed {
		m.syncTable()
		m.notify()
		m.nudge()
	}
}

func wantEqual(a, b map[string]wantClaim) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		w, ok := b[k]
		if !ok || w.vpc != v.vpc || !slices.Equal(w.slots, v.slots) {
			return false
		}
	}
	return true
}

func sidsEqual(a, b map[netip.Addr]sidRef) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// ReasonPublicUplinkMissing is a backend whose replies cannot leave this
// node: usid_egress sends every VIP reply through public_uplink_table, which
// has no next hop. It holds whichever gateway selected the backend.
const ReasonPublicUplinkMissing = "PublicUplinkMissing"

// SetUplinkMissing records whether this node's public_uplink_table has no
// next hop. While it has none, every backend on this node is reported not
// ready and its flows through this gateway are dropped, since no reply of
// theirs can leave.
func (m *Manager) SetUplinkMissing(missing bool) {
	m.mu.Lock()
	changed := m.uplinkMissing != missing
	m.uplinkMissing = missing
	m.mu.Unlock()
	if changed {
		m.syncTable()
		m.notify()
	}
}

// Run keeps a Worker session open and the claims current until ctx ends.
func (m *Manager) Run(ctx context.Context) {
	m.syncTable()
	for ctx.Err() == nil {
		c, err := m.dial(ctx)
		if err != nil {
			slog.Warn("Cannot open a Galactic Worker session; local backends stay out of service", "err", err)
			m.setSession(false)
			if !sleepCtx(ctx, m.Retry) {
				return
			}
			continue
		}
		m.setSession(true)
		m.serve(ctx, c)
		m.setSession(false)
		_ = c.Close()
		if !sleepCtx(ctx, m.Retry) {
			return
		}
	}
}

func (m *Manager) setSession(up bool) {
	m.mu.Lock()
	m.sessionUp = up
	if up {
		for _, cl := range m.claims {
			cl.requested = false
		}
	}
	m.mu.Unlock()
	m.notify()
}

// serve runs one session: it observes every claim of the gateway and
// reconciles them on every nudge, until the stream fails or ctx ends.
func (m *Manager) serve(ctx context.Context, c ClaimAPI) {
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stream, err := c.Observe(sctx, nil)
	if err != nil {
		slog.Warn("Cannot observe Galactic Worker claims", "err", err)
		return
	}
	done := make(chan error, 1)
	go func() {
		for {
			st, err := stream.Recv()
			if err != nil {
				done <- err
				return
			}
			m.handleStatus(st)
		}
	}()
	ticker := time.NewTicker(m.Retry)
	defer ticker.Stop()
	for {
		m.reconcile(sctx, c)
		select {
		case <-ctx.Done():
			return
		case err := <-done:
			if ctx.Err() == nil {
				slog.Warn("Galactic Worker claim stream ended; reopening the session", "err", err)
			}
			return
		case <-m.kick:
		case <-ticker.C:
		}
	}
}

// nextGenLocked returns a generation larger than any this process used, from
// the clock, so a restarted gateway's Update moves past the generation its
// predecessor left.
func (m *Manager) nextGenLocked() uint64 {
	g := uint64(time.Now().UnixNano()) //nolint:gosec // the clock is positive
	if g <= m.lastGen {
		g = m.lastGen + 1
	}
	m.lastGen = g
	return g
}

func (m *Manager) claimKey(vpc, uid string) *workerv1alpha1.ClaimKey {
	return &workerv1alpha1.ClaimKey{Node: m.node, Vpc: vpc, AttachmentUid: uid}
}

func (m *Manager) claimSpec(slots []uint16) *workerv1alpha1.ClaimSpec {
	s := &workerv1alpha1.ClaimSpec{Handoff: workerv1alpha1.Handoff_HANDOFF_TAP, Mode: workerv1alpha1.Mode_MODE_LOCAL}
	for _, slot := range slots {
		s.Destinations = append(s.Destinations, &workerv1alpha1.Destination{
			Target: &workerv1alpha1.Destination_Backend{Backend: &workerv1alpha1.BackendRef{Node: m.node, Slot: uint32(slot)}},
		})
	}
	return s
}

type op struct {
	uid     string
	key     *workerv1alpha1.ClaimKey
	gen     uint64
	slots   []uint16
	release bool
	update  bool
}

// reconcile requests or updates a claim for every wanted attachment and
// releases every other claim the gateway holds, including those an earlier
// process left.
func (m *Manager) reconcile(ctx context.Context, c ClaimAPI) {
	m.mu.Lock()
	var ops []op
	for uid, cl := range m.claims {
		w, ok := m.want[uid]
		if !ok || w.vpc != cl.key.GetVpc() {
			ops = append(ops, op{uid: uid, key: cl.key, gen: cl.gen, release: true})
		}
	}
	for uid, w := range m.want {
		cl := m.claims[uid]
		switch {
		case cl == nil:
			gen := m.nextGenLocked()
			m.claims[uid] = &claimState{key: m.claimKey(w.vpc, uid), slots: w.slots, gen: gen}
			ops = append(ops, op{uid: uid, key: m.claims[uid].key, gen: gen, slots: w.slots})
		case cl.key.GetVpc() != w.vpc:
			// Released above; requested again once that release completes.
		case !slices.Equal(cl.slots, w.slots):
			ops = append(ops, op{uid: uid, key: cl.key, gen: m.nextGenLocked(), slots: w.slots, update: true})
		case !cl.requested:
			ops = append(ops, op{uid: uid, key: cl.key, gen: cl.gen, slots: w.slots})
		}
	}
	m.mu.Unlock()
	sort.Slice(ops, func(i, j int) bool { return ops[i].uid < ops[j].uid })

	for _, o := range ops {
		switch {
		case o.release:
			_, err := c.Release(ctx, o.key, o.gen)
			if err != nil && workerclient.Reason(err) != workerv1alpha1.ReasonClaimNotFound {
				m.noteError(o.uid, err)
				continue
			}
			m.mu.Lock()
			if cl := m.claims[o.uid]; cl != nil && cl.key.GetVpc() == o.key.GetVpc() {
				delete(m.claims, o.uid)
			}
			m.mu.Unlock()
			m.nudge()
		default:
			gen, err := m.requestOrUpdate(ctx, c, o)
			if err != nil {
				m.noteError(o.uid, err)
				continue
			}
			m.mu.Lock()
			if cl := m.claims[o.uid]; cl != nil && cl.key.GetVpc() == o.key.GetVpc() {
				cl.gen, cl.slots, cl.requested = gen, o.slots, true
			}
			delete(m.lastErr, o.uid)
			m.mu.Unlock()
		}
	}
	m.syncTable()
	m.notify()
}

// requestOrUpdate makes Worker hold o's spec and returns the generation it
// holds it at. A claim Worker already holds at another generation, such as
// one a restarted gateway made before, is updated to a newer one.
func (m *Manager) requestOrUpdate(ctx context.Context, c ClaimAPI, o op) (uint64, error) {
	spec := m.claimSpec(o.slots)
	if !o.update {
		_, err := c.Request(ctx, o.key, o.gen, spec)
		if err == nil {
			return o.gen, nil
		}
		reason := workerclient.Reason(err)
		if status.Code(err) != codes.FailedPrecondition ||
			(reason != workerv1alpha1.ReasonClaimExists && reason != workerv1alpha1.ReasonGenerationConflict) {
			return 0, err
		}
		m.mu.Lock()
		o.gen = m.nextGenLocked()
		m.mu.Unlock()
	}
	if _, err := c.Update(ctx, o.key, o.gen, spec); err != nil {
		return 0, err
	}
	return o.gen, nil
}

func (m *Manager) noteError(uid string, err error) {
	reason := workerclient.Reason(err)
	if reason == "" {
		reason = status.Code(err).String()
	}
	m.mu.Lock()
	first := m.lastErr[uid] != reason
	m.lastErr[uid] = reason
	m.mu.Unlock()
	if first {
		slog.Warn("Galactic Worker refused a gateway Local handoff claim", "attachment", uid, "reason", reason, "err", err)
	}
}

// handleStatus records one claim snapshot.
func (m *Manager) handleStatus(st *workerv1alpha1.ClaimStatus) {
	key := st.GetKey()
	uid := key.GetAttachmentUid()
	if uid == "" || key.GetNode() != m.node {
		return
	}
	m.mu.Lock()
	m.everStatus = true
	cl := m.claims[uid]
	switch {
	case st.GetReleased():
		if cl != nil && cl.key.GetVpc() == key.GetVpc() {
			if _, wanted := m.want[uid]; wanted {
				// Worker withdrew it, for example after the attachment's
				// authority was revoked: ask again, and keep reporting it
				// not ready meanwhile.
				cl.requested, cl.status = false, st
			} else {
				delete(m.claims, uid)
			}
		}
	case cl == nil:
		// A claim an earlier gateway process made: track it, at the
		// generation Worker holds, so reconcile releases or adopts it.
		m.claims[uid] = &claimState{key: key, gen: st.GetGeneration(), requested: true, status: st,
			slots: statusSlots(st)}
	case cl.key.GetVpc() == key.GetVpc():
		if cl.status == nil || st.GetRevision() >= cl.status.GetRevision() ||
			st.GetObservedGeneration() > cl.status.GetObservedGeneration() {
			cl.status = st
		}
	}
	m.mu.Unlock()
	m.syncTable()
	m.notify()
	m.nudge()
}

func statusSlots(st *workerv1alpha1.ClaimStatus) []uint16 {
	var out []uint16
	for _, d := range st.GetDestinations() {
		if b := d.GetDestination().GetBackend(); b != nil && b.GetSlot() > 0 && b.GetSlot() <= 0xFFFF {
			out = append(out, uint16(b.GetSlot()))
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// slotReady reports whether cl's current status says slot's destination is
// ready, and the TAP it is delivered to.
func slotReady(cl *claimState, slot uint16) (uint32, bool, string) {
	if cl == nil || cl.status == nil {
		return 0, false, workerv1alpha1.ReasonPending
	}
	st := cl.status
	if st.GetObservedGeneration() < cl.gen {
		return 0, false, workerv1alpha1.ReasonPending
	}
	var tap uint32
	for _, h := range st.GetHandoffInterfaces() {
		if h.GetRole() == workerv1alpha1.HandoffRoleTap && h.GetIfindex() > 0 {
			tap = uint32(h.GetIfindex())
			break
		}
	}
	for _, d := range st.GetDestinations() {
		if d.GetDestination().GetBackend().GetSlot() != uint32(slot) {
			continue
		}
		if !d.GetReady() {
			r := d.GetReason()
			if r == "" {
				r = workerv1alpha1.ReasonPending
			}
			return 0, false, r
		}
		if tap == 0 {
			return 0, false, workerv1alpha1.ReasonHandoffInterfaceMissing
		}
		return tap, true, bgpv1alpha1.LocalBackendReasonReady
	}
	return 0, false, workerv1alpha1.ReasonPending
}

// syncTable writes edge_local_table from the wanted backends and Worker's
// statuses, and deletes every other row.
func (m *Manager) syncTable() {
	m.mu.Lock()
	rows := make(map[netip.Addr]uint32, len(m.sids))
	for sid, ref := range m.sids {
		tap, ok, _ := slotReady(m.claims[ref.uid], ref.slot)
		if !ok || m.uplinkMissing {
			tap = 0
		}
		rows[sid] = tap
	}
	m.mu.Unlock()

	var failed uint64
	have, err := m.table.List()
	if err != nil {
		slog.Error("Cannot read edge_local_table", "err", err)
		failed++
	}
	for sid, tap := range rows {
		if cur, ok := have[sid]; ok && cur == tap {
			continue
		}
		if err := m.table.Set(sid, tap); err != nil {
			slog.Error("Cannot write an edge_local_table row", "sid", sid, "err", err)
			failed++
		}
	}
	for sid := range have {
		if _, ok := rows[sid]; ok {
			continue
		}
		if err := m.table.Delete(sid); err != nil {
			slog.Error("Cannot delete an edge_local_table row", "sid", sid, "err", err)
			failed++
		}
	}
	if failed > 0 {
		m.mu.Lock()
		m.tableErrors += failed
		m.mu.Unlock()
	}
}

// Snapshot returns the session state and each wanted attachment's readiness.
func (m *Manager) Snapshot() Snapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	return Snapshot{SessionUp: m.sessionUp, Attachments: m.attachmentsLocked(), TableErrors: m.tableErrors}
}

// attachmentsLocked reports an attachment ready when every slot the gateway
// serves on it is. A gateway that never had a Worker status reports
// WorkerUnavailable. One that lost its session keeps the last status Worker
// reported, since Worker keeps programming its claims while their lease
// lasts and reports their withdrawal when the session reopens.
func (m *Manager) attachmentsLocked() []AttachmentState {
	out := make([]AttachmentState, 0, len(m.want))
	for uid, w := range m.want {
		s := AttachmentState{AttachmentUID: uid, Ready: true, Reason: bgpv1alpha1.LocalBackendReasonReady}
		switch {
		case !m.everStatus && !m.sessionUp:
			s.Ready, s.Reason = false, bgpv1alpha1.LocalBackendReasonWorkerUnavailable
		case m.uplinkMissing:
			s.Ready, s.Reason = false, ReasonPublicUplinkMissing
		default:
			for _, slot := range w.slots {
				if _, ok, reason := slotReady(m.claims[uid], slot); !ok {
					s.Ready, s.Reason = false, reason
					if r := m.lastErr[uid]; r != "" {
						s.Reason = r
					}
					break
				}
			}
		}
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].AttachmentUID < out[j].AttachmentUID })
	return out
}

// notify calls onChange when an attachment's readiness changed.
func (m *Manager) notify() {
	m.mu.Lock()
	cur := m.attachmentsLocked()
	changed := !slices.Equal(cur, m.lastSnap)
	m.lastSnap = cur
	m.mu.Unlock()
	if changed && m.onChange != nil {
		m.onChange()
	}
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

// WorkerclientDial adapts workerclient.Dial to DialFunc.
func WorkerclientDial(socket, tokenFile string) DialFunc {
	return func(ctx context.Context) (ClaimAPI, error) {
		c, err := workerclient.Dial(ctx, workerclient.Options{SocketPath: socket, TokenFile: tokenFile})
		if err != nil {
			return nil, err
		}
		return clientAdapter{c}, nil
	}
}

type clientAdapter struct{ *workerclient.Client }

func (a clientAdapter) Observe(ctx context.Context, key *workerv1alpha1.ClaimKey) (StatusStream, error) {
	o, err := a.Client.Observe(ctx, key)
	if err != nil {
		return nil, err
	}
	return o, nil
}
