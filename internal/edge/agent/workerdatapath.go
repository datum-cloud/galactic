// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"time"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	workerv1alpha1 "go.datum.net/galactic/api/galactic/worker/v1alpha1"
	"go.datum.net/galactic/internal/plumbing/ebpf/forwardgatemap"
	"go.datum.net/galactic/pkg/workerclient"
)

// Condition reasons a Worker-backed datapath gives the agent.
const (
	// ReasonWorkerUnavailable: Worker could not be reached, or did not
	// program or release the link in time.
	ReasonWorkerUnavailable = "WorkerUnavailable"
	// ReasonWorkerRefused: Worker refused the link's claim; the message
	// carries Worker's reason.
	ReasonWorkerRefused = "WorkerRefused"
)

// WorkerError is a Worker-backed datapath's failure, with the agent reason
// it is reported under and Worker's own reason.
type WorkerError struct {
	// Reason is ReasonWorkerUnavailable or ReasonWorkerRefused.
	Reason string
	// WorkerReason is Worker's contract reason, when it gave one.
	WorkerReason string
	Err          error
}

func (e *WorkerError) Error() string {
	if e.WorkerReason != "" {
		return fmt.Sprintf("galactic-worker %s: %v", e.WorkerReason, e.Err)
	}
	return "galactic-worker: " + e.Err.Error()
}

func (e *WorkerError) Unwrap() error { return e.Err }

// WorkerClient is the part of workerclient.Client the datapath uses.
type WorkerClient interface {
	Request(ctx context.Context, key *workerv1alpha1.ClaimKey, generation uint64,
		spec *workerv1alpha1.ClaimSpec) (*workerv1alpha1.ClaimStatus, error)
	Update(ctx context.Context, key *workerv1alpha1.ClaimKey, generation uint64,
		spec *workerv1alpha1.ClaimSpec) (*workerv1alpha1.ClaimStatus, error)
	Release(ctx context.Context, key *workerv1alpha1.ClaimKey, generation uint64) (*workerv1alpha1.ClaimStatus, error)
	Observe(ctx context.Context, key *workerv1alpha1.ClaimKey) (*workerclient.Observer, error)
}

var _ WorkerClient = (*workerclient.Client)(nil)

// LinkGates writes the gate rows of edge links that galactic-edge keeps when
// Worker registers the links (forwardgatemap).
type LinkGates interface {
	SetLink(ifindex uint32, addr netip.Addr) error
	DeleteGates(ifindex uint32) error
	DeleteLink(ifindex uint32) error
}

// PinnedLinkGates is LinkGates on the pinned gate maps, opened for every
// call as PinnedGates opens them.
type PinnedLinkGates struct{ PinDir string }

// SetLink implements LinkGates.
func (g PinnedLinkGates) SetLink(ifindex uint32, addr netip.Addr) error {
	t, err := forwardgatemap.OpenPinned(g.PinDir)
	if err != nil {
		return err
	}
	defer func() { _ = t.Close() }()
	return t.SetLink(ifindex, addr)
}

// DeleteGates implements LinkGates.
func (g PinnedLinkGates) DeleteGates(ifindex uint32) error { return deleteGates(g.PinDir, ifindex) }

// DeleteLink implements LinkGates.
func (g PinnedLinkGates) DeleteLink(ifindex uint32) error {
	return PinnedDatapath(g).Forget(ifindex)
}

// Connector is a datapath that hands each VPC scope's edge links to Galactic
// Worker (docs/worker/connector.md). The agent claims each link before
// creating it, so Worker creates the VPC's node state, and hands a scope it
// owns over to Worker once every live link is claimed.
type Connector interface {
	Datapath
	// Prepare claims l from Worker without waiting for it to be programmed.
	// l.Index may be zero: Worker finds the link by name.
	Prepare(l Link) error
	// Nudge asks Worker to reconcile every live claim of vpc again, as after
	// galactic-edge handed vpc's scope over.
	Nudge(vpc string) error
}

// DefaultWorkerWait bounds how long Register waits for Worker to program a
// link and Unregister for Worker to release one.
const DefaultWorkerWait = 10 * time.Second

// WorkerDatapath is the Datapath that claims each edge link from Galactic
// Worker (D14, D37). galactic-edge still creates the link, opens and closes
// its gates and owns its gate link row; Worker registers the link with the
// uSID datapath and writes the VPC's pass-through entries for it.
type WorkerDatapath struct {
	// Client is the Worker client, whose session belongs to galactic-edge.
	Client WorkerClient
	// Node is this node.
	Node string
	// Gates writes the links' gate rows.
	Gates LinkGates
	// Wait bounds each wait for Worker; DefaultWorkerWait when zero.
	Wait time.Duration
	// Capabilities returns Worker's last GetCapabilities response, for the
	// metrics. Nil exports none.
	Capabilities func() *workerv1alpha1.GetCapabilitiesResponse

	mu sync.Mutex
	// claims are galactic-edge's claims, by attachment UID.
	claims map[string]*edgeClaim
	// prefixes are what SyncRoutes last found each link to carry.
	prefixes map[string][]netip.Prefix
	// changed is closed and replaced whenever a status arrives.
	changed chan struct{}
}

var _ Connector = (*WorkerDatapath)(nil)

// edgeClaim is what the datapath knows of one claim.
type edgeClaim struct {
	key *workerv1alpha1.ClaimKey
	// gen is the last generation Worker accepted or reported.
	gen uint64
	// spec is the spec accepted at gen, or nil when unknown, as after a
	// restart.
	spec *workerv1alpha1.ClaimSpec
	// released is set once the claim is gone.
	released bool
	status   *workerv1alpha1.ClaimStatus
}

func (d *WorkerDatapath) init() {
	if d.claims == nil {
		d.claims = map[string]*edgeClaim{}
		d.prefixes = map[string][]netip.Prefix{}
		d.changed = make(chan struct{})
	}
}

func (d *WorkerDatapath) wait() time.Duration {
	if d.Wait > 0 {
		return d.Wait
	}
	return DefaultWorkerWait
}

// Run keeps an Observe stream of every claim of galactic-edge open until
// ctx is done, recording each status. The stream also renews the session.
func (d *WorkerDatapath) Run(ctx context.Context) error {
	backoff := 200 * time.Millisecond
	for {
		obs, err := d.Client.Observe(ctx, nil)
		if err == nil {
			backoff = 200 * time.Millisecond
			for {
				st, rerr := obs.Recv()
				if rerr != nil {
					err = rerr
					break
				}
				d.record(st)
			}
		}
		if ctx.Err() != nil {
			return nil
		}
		slog.Warn("galactic-edge: Worker status stream ended; reopening", "err", err, "after", backoff)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff):
		}
		backoff = min(2*backoff, 30*time.Second)
	}
}

// record keeps st, the newest status of one claim.
func (d *WorkerDatapath) record(st *workerv1alpha1.ClaimStatus) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.init()
	uid := st.GetKey().GetAttachmentUid()
	c := d.claims[uid]
	if c == nil {
		c = &edgeClaim{key: st.GetKey()}
		d.claims[uid] = c
	}
	if st.GetGeneration() > c.gen {
		// A generation this process did not send, such as one before a
		// restart: its spec is unknown until the next change sends one.
		c.gen, c.spec = st.GetGeneration(), nil
	}
	if st.GetGeneration() == c.gen {
		c.status = st
		c.released = st.GetReleased()
	}
	close(d.changed)
	d.changed = make(chan struct{})
}

// edgeSpec is a connector claim's spec for the link name and prefixes.
func edgeSpec(name string, prefixes []netip.Prefix) *workerv1alpha1.ClaimSpec {
	sorted := slices.Clone(prefixes)
	slices.SortFunc(sorted, func(a, b netip.Prefix) int {
		if c := a.Addr().Compare(b.Addr()); c != 0 {
			return c
		}
		return a.Bits() - b.Bits()
	})
	sorted = slices.Compact(sorted)
	out := make([]string, 0, len(sorted))
	for _, p := range sorted {
		out = append(out, p.String())
	}
	return &workerv1alpha1.ClaimSpec{Handoff: workerv1alpha1.Handoff_HANDOFF_ROUTED_LINK,
		EdgeLink: &workerv1alpha1.EdgeLink{Name: name, Prefixes: out}}
}

// currentGeneration returns the generation a refusal says is current.
func currentGeneration(err error) (uint64, bool) {
	st, ok := status.FromError(err)
	if !ok {
		return 0, false
	}
	for _, det := range st.Details() {
		if info, ok := det.(*errdetails.ErrorInfo); ok && info.GetDomain() == workerv1alpha1.ErrorDomain {
			if v, ok := info.GetMetadata()[workerv1alpha1.MetadataCurrentGeneration]; ok {
				n, err := strconv.ParseUint(v, 10, 64)
				return n, err == nil
			}
		}
	}
	return 0, false
}

// workerError classifies a Worker call's error.
func workerError(err error) error {
	if err == nil {
		return nil
	}
	reason := workerclient.Reason(err)
	switch status.Code(err) {
	case codes.PermissionDenied, codes.InvalidArgument, codes.FailedPrecondition, codes.Aborted:
		return &WorkerError{Reason: ReasonWorkerRefused, WorkerReason: reason, Err: err}
	}
	return &WorkerError{Reason: ReasonWorkerUnavailable, WorkerReason: reason, Err: err}
}

// put makes l's claim carry spec, with Request for a claim Worker does not
// hold and Update otherwise, and returns the generation Worker accepted.
// Unless force is set, a claim already accepted with spec is left alone. A
// generation from before a restart, which a refusal reports, is taken up and
// the call made again.
func (d *WorkerDatapath) put(ctx context.Context, l Link, force bool) (uint64, error) {
	if l.AttachmentUID == "" {
		return 0, errors.New("galactic-worker: a link without an attachment cannot be claimed")
	}
	d.mu.Lock()
	d.init()
	spec := edgeSpec(l.Name, d.prefixes[l.AttachmentUID])
	c := d.claims[l.AttachmentUID]
	if c == nil {
		c = &edgeClaim{key: &workerv1alpha1.ClaimKey{Node: d.Node, Vpc: l.VPC, AttachmentUid: l.AttachmentUID}}
		d.claims[l.AttachmentUID] = c
	}
	if !force && !c.released && c.gen > 0 && c.spec != nil && proto.Equal(c.spec, spec) {
		gen := c.gen
		d.mu.Unlock()
		return gen, nil
	}
	key := proto.Clone(c.key).(*workerv1alpha1.ClaimKey)
	gen, update := c.gen+1, c.gen > 0 && !c.released
	d.mu.Unlock()

	var err error
	for range 4 {
		if update {
			_, err = d.Client.Update(ctx, key, gen, spec)
		} else {
			_, err = d.Client.Request(ctx, key, gen, spec)
		}
		reason := workerclient.Reason(err)
		switch {
		case err == nil:
			d.mu.Lock()
			if gen >= c.gen {
				c.gen, c.spec, c.released = gen, spec, false
			}
			d.mu.Unlock()
			return gen, nil
		case reason == workerv1alpha1.ReasonClaimExists || reason == workerv1alpha1.ReasonStaleGeneration ||
			reason == workerv1alpha1.ReasonGenerationConflict:
			cur, ok := currentGeneration(err)
			if !ok {
				return 0, workerError(err)
			}
			gen, update = cur+1, true
		case reason == workerv1alpha1.ReasonClaimNotFound:
			update = false
		default:
			return 0, workerError(err)
		}
	}
	return 0, workerError(err)
}

// waitFor waits until done reports l's claim settled, or the wait ends.
func (d *WorkerDatapath) waitFor(ctx context.Context, uid string,
	done func(c *edgeClaim) (bool, error)) error {
	ctx, cancel := context.WithTimeout(ctx, d.wait())
	defer cancel()
	for {
		d.mu.Lock()
		d.init()
		c := d.claims[uid]
		ch := d.changed
		var (
			ok  bool
			err error
		)
		if c != nil {
			ok, err = done(c)
		}
		d.mu.Unlock()
		if ok || err != nil {
			return err
		}
		select {
		case <-ch:
		case <-ctx.Done():
			msg := "no status yet"
			if c != nil && c.status != nil {
				if p := statusCondition(c.status, workerv1alpha1.ConditionProgrammed); p != nil {
					msg = p.GetReason() + ": " + p.GetMessage()
				}
			}
			return &WorkerError{Reason: ReasonWorkerUnavailable, Err: fmt.Errorf("%w waiting for Worker (%s)",
				ctx.Err(), msg)}
		}
	}
}

func statusCondition(st *workerv1alpha1.ClaimStatus, t string) *workerv1alpha1.Condition {
	for _, c := range st.GetConditions() {
		if c.GetType() == t {
			return c
		}
	}
	return nil
}

// programmedAt reports whether the claim is Programmed at gen, and refuses a
// claim Worker revoked or released.
func programmedAt(gen uint64) func(c *edgeClaim) (bool, error) {
	return func(c *edgeClaim) (bool, error) {
		st := c.status
		if st == nil || st.GetObservedGeneration() < gen {
			return false, nil
		}
		if a := statusCondition(st, workerv1alpha1.ConditionAdmitted); a != nil &&
			a.GetStatus() == workerv1alpha1.ConditionStatus_CONDITION_STATUS_FALSE {
			return false, &WorkerError{Reason: ReasonWorkerRefused, WorkerReason: a.GetReason(),
				Err: errors.New(a.GetMessage())}
		}
		if c.released {
			return false, &WorkerError{Reason: ReasonWorkerRefused, WorkerReason: workerv1alpha1.ReasonReleased,
				Err: errors.New("the claim was withdrawn")}
		}
		p := statusCondition(st, workerv1alpha1.ConditionProgrammed)
		if p != nil && p.GetStatus() == workerv1alpha1.ConditionStatus_CONDITION_STATUS_TRUE {
			return true, nil
		}
		if p != nil && p.GetReason() == workerv1alpha1.ReasonHandoffInterfaceNotOwned {
			return false, &WorkerError{Reason: ReasonWorkerRefused, WorkerReason: p.GetReason(),
				Err: errors.New(p.GetMessage())}
		}
		return false, nil
	}
}

// isProgrammed reports whether uid's claim is Programmed at its generation.
func (d *WorkerDatapath) isProgrammed(uid string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	c := d.claims[uid]
	if c == nil || c.released || c.status == nil || c.status.GetObservedGeneration() != c.gen {
		return false
	}
	p := statusCondition(c.status, workerv1alpha1.ConditionProgrammed)
	return p != nil && p.GetStatus() == workerv1alpha1.ConditionStatus_CONDITION_STATUS_TRUE
}

// Register implements Datapath: the link's gate row first, then the claim,
// which Worker programs once it finds the gated link. It returns once Worker
// reports the link Programmed. A claim not yet Programmed is sent again at a
// new generation, so Worker looks at a link it found ungated once more.
func (d *WorkerDatapath) Register(l Link) error {
	if err := d.Gates.SetLink(l.Index, l.Addr); err != nil {
		return err
	}
	ctx := context.Background()
	gen, err := d.put(ctx, l, !d.isProgrammed(l.AttachmentUID))
	if err != nil {
		return err
	}
	return d.waitFor(ctx, l.AttachmentUID, programmedAt(gen))
}

// Prepare implements Connector.
func (d *WorkerDatapath) Prepare(l Link) error {
	_, err := d.put(context.Background(), l, false)
	return err
}

// Unregister implements Datapath: the link's gates first, then the claim,
// once Worker reports it released. The gate link row stays until Forget.
// A link with no attachment has only its gates cleared: Worker removes the
// rows of a link no claim keeps.
func (d *WorkerDatapath) Unregister(l Link) error {
	if err := d.Gates.DeleteGates(l.Index); err != nil {
		return err
	}
	if l.AttachmentUID == "" {
		return nil
	}
	ctx := context.Background()
	d.mu.Lock()
	d.init()
	c := d.claims[l.AttachmentUID]
	if c == nil {
		// Not seen since this process started: release from its first
		// generation, and take up the current one from the refusal.
		c = &edgeClaim{key: &workerv1alpha1.ClaimKey{Node: d.Node, Vpc: l.VPC, AttachmentUid: l.AttachmentUID}}
		d.claims[l.AttachmentUID] = c
	}
	if c.released {
		d.mu.Unlock()
		return nil
	}
	key := proto.Clone(c.key).(*workerv1alpha1.ClaimKey)
	gen := max(c.gen, 1)
	d.mu.Unlock()

	var err error
	for range 4 {
		var st *workerv1alpha1.ClaimStatus
		st, err = d.Client.Release(ctx, key, gen)
		if err == nil {
			if st == nil || st.GetReleased() {
				d.markReleased(l.AttachmentUID)
				return nil
			}
			break
		}
		reason := workerclient.Reason(err)
		if reason != workerv1alpha1.ReasonStaleGeneration && reason != workerv1alpha1.ReasonGenerationConflict {
			return workerError(err)
		}
		cur, ok := currentGeneration(err)
		if !ok {
			return workerError(err)
		}
		gen = cur
		d.mu.Lock()
		if cur > c.gen {
			c.gen, c.spec = cur, nil
		}
		d.mu.Unlock()
	}
	if err != nil {
		return workerError(err)
	}
	return d.waitFor(ctx, l.AttachmentUID, func(c *edgeClaim) (bool, error) { return c.released, nil })
}

func (d *WorkerDatapath) markReleased(uid string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if c := d.claims[uid]; c != nil {
		c.released = true
	}
	delete(d.prefixes, uid)
}

// Forget implements Datapath.
func (d *WorkerDatapath) Forget(ifindex uint32) error { return d.Gates.DeleteLink(ifindex) }

// SyncRoutes implements Datapath: each claimed link whose prefixes changed
// is sent at a new generation. Worker writes the pass-through entries of the
// links' own addresses and prefixes, so vrfTable is not needed. A link with
// no live claim gets its prefixes with its next Register.
func (d *WorkerDatapath) SyncRoutes(_ uint32, links []LinkRoutes) error {
	var errs []error
	for _, lr := range links {
		uid := lr.Link.AttachmentUID
		if uid == "" {
			continue
		}
		d.mu.Lock()
		d.init()
		d.prefixes[uid] = slices.Clone(lr.Prefixes)
		c := d.claims[uid]
		live := c != nil && !c.released && c.gen > 0
		d.mu.Unlock()
		if !live {
			continue
		}
		if _, err := d.put(context.Background(), lr.Link, false); err != nil {
			errs = append(errs, fmt.Errorf("claim %s: %w", lr.Link.Name, err))
		}
	}
	return errors.Join(errs...)
}

// Nudge implements Connector.
func (d *WorkerDatapath) Nudge(vpc string) error {
	d.mu.Lock()
	var links []Link
	for uid, c := range d.claims {
		if c.key.GetVpc() == vpc && !c.released && c.gen > 0 && c.spec != nil {
			links = append(links, Link{VPC: vpc, AttachmentUID: uid, Name: c.spec.GetEdgeLink().GetName()})
		}
	}
	d.mu.Unlock()
	var errs []error
	for _, l := range links {
		if _, err := d.put(context.Background(), l, true); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// ClaimStates returns, for the metrics, how many claims are in each state:
// "ready", "programmed", "pending" and "refused".
func (d *WorkerDatapath) ClaimStates() map[string]int {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := map[string]int{"ready": 0, "programmed": 0, "pending": 0, "refused": 0}
	for _, c := range d.claims {
		if c.released || c.status == nil {
			continue
		}
		cond := func(t string) bool {
			x := statusCondition(c.status, t)
			return x != nil && x.GetStatus() == workerv1alpha1.ConditionStatus_CONDITION_STATUS_TRUE
		}
		switch {
		case !cond(workerv1alpha1.ConditionAdmitted):
			out["refused"]++
		case cond(workerv1alpha1.ConditionReady):
			out["ready"]++
		case cond(workerv1alpha1.ConditionProgrammed):
			out["programmed"]++
		default:
			out["pending"]++
		}
	}
	return out
}
