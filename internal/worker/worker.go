// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package worker is Galactic Worker's reconciliation core and gRPC service,
// implementing docs/worker/contract.md.
//
// A mutating call is validated, authenticated, authorized against trusted
// sources and recorded durably before it returns; nothing is programmed on
// the call path. Reconciliation runs per VPC scope from a deduplicating
// queue. It resolves every destination, takes the scope's ticket from the
// ownership fence (internal/ownership), commits the complete desired
// state of the scope through the delivery modules and reads the host back to
// report programmed and observed state. Desired state is durable;
// programmed and observed state are rebuilt from the host after a restart.
package worker

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"k8s.io/client-go/util/workqueue"

	workerv1alpha1 "go.datum.net/galactic/api/galactic/worker/v1alpha1"
	"go.datum.net/galactic/internal/ownership"
	"go.datum.net/galactic/internal/worker/auth"
	"go.datum.net/galactic/internal/worker/module"
	"go.datum.net/galactic/internal/worker/sources"
	"go.datum.net/galactic/internal/worker/store"
)

// Defaults from the contract.
const (
	// DefaultLease and DefaultRenewInterval are the XDP dispatcher's slot
	// lease values (D5).
	DefaultLease         = 120 * time.Second
	DefaultRenewInterval = 10 * time.Second
	// DefaultClaimLimit is the number of claims one caller may hold (D18).
	DefaultClaimLimit = 1024
	// DefaultRetryMin and DefaultRetryMax bound Worker's own programming
	// retries.
	DefaultRetryMin = time.Second
	DefaultRetryMax = 60 * time.Second
	// DefaultResyncInterval is how often every scope is reconciled again to
	// refresh observed state.
	DefaultResyncInterval = 30 * time.Second
)

// Authenticator authenticates the caller of a call.
type Authenticator interface {
	Authenticate(ctx context.Context) (auth.Caller, error)
}

// Config configures a Worker.
type Config struct {
	// Node is this node's name.
	Node           string
	Lease          time.Duration
	RenewInterval  time.Duration
	ClaimLimit     int
	RetryMin       time.Duration
	RetryMax       time.Duration
	ResyncInterval time.Duration
	// Reconcilers is the number of scopes reconciled at once.
	Reconcilers int
}

func (c *Config) defaults() {
	if c.Lease == 0 {
		c.Lease = DefaultLease
	}
	if c.RenewInterval == 0 {
		c.RenewInterval = DefaultRenewInterval
	}
	if c.ClaimLimit == 0 {
		c.ClaimLimit = DefaultClaimLimit
	}
	if c.RetryMin == 0 {
		c.RetryMin = DefaultRetryMin
	}
	if c.RetryMax == 0 {
		c.RetryMax = DefaultRetryMax
	}
	if c.ResyncInterval == 0 {
		c.ResyncInterval = DefaultResyncInterval
	}
	if c.Reconcilers == 0 {
		c.Reconcilers = 4
	}
}

// Deps are a Worker's collaborators.
type Deps struct {
	Store   store.Store
	Fence   *ownership.Authority
	Sources sources.Sources
	Modules *module.Registry
	Auth    Authenticator
	Log     *slog.Logger
	// Now is the clock, time.Now when nil.
	Now func() time.Time
}

// claim is one claim's desired state and last status.
type claim struct {
	rec    store.Record
	spec   *workerv1alpha1.ClaimSpec
	status *workerv1alpha1.ClaimStatus
}

func (c *claim) key() module.ClaimKey {
	return module.ClaimKey{Node: c.rec.Node, VPC: c.rec.VPC, AttachmentUID: c.rec.AttachmentUID}
}

// scopeState is Worker's view of one VPC scope.
type scopeState struct {
	// resyncing is set for a scope whose desired state was loaded at start,
	// until the first snapshot commit. Claim changes are refused meanwhile.
	resyncing bool
	// repair is set after a failed commit, until a commit succeeds.
	repair bool
}

// Worker is the reconciliation core and gRPC service.
type Worker struct {
	workerv1alpha1.UnimplementedWorkerServer

	cfg   Config
	d     Deps
	owner string
	log   *slog.Logger
	queue workqueue.TypedRateLimitingInterface[string]

	keyLocks [256]sync.Mutex

	mu       sync.Mutex
	claims   map[module.ClaimKey]*claim
	scopes   map[string]*scopeState
	sessions map[string]*session
	lastSeen map[string]time.Time
	subs     map[*subscriber]struct{}
	revision uint64

	shutting atomic.Bool
	started  atomic.Bool
}

// New returns a Worker. Start loads desired state and starts reconciling.
func New(cfg Config, d Deps) (*Worker, error) {
	cfg.defaults()
	if cfg.Node == "" {
		return nil, errors.New("worker: node name is required")
	}
	if d.Store == nil || d.Fence == nil || d.Sources == nil || d.Modules == nil || d.Auth == nil {
		return nil, errors.New("worker: store, fence, sources, modules and auth are required")
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.Log == nil {
		d.Log = slog.Default()
	}
	id := make([]byte, 8)
	if _, err := rand.Read(id); err != nil {
		return nil, fmt.Errorf("worker: owner ID: %w", err)
	}
	w := &Worker{
		cfg:      cfg,
		d:        d,
		owner:    ownership.WorkerOwnerPrefix + cfg.Node + ":" + hex.EncodeToString(id),
		log:      d.Log.With("component", "galactic-worker"),
		claims:   map[module.ClaimKey]*claim{},
		scopes:   map[string]*scopeState{},
		sessions: map[string]*session{},
		lastSeen: map[string]time.Time{},
		subs:     map[*subscriber]struct{}{},
		revision: uint64(d.Now().UnixNano()),
		queue: workqueue.NewTypedRateLimitingQueueWithConfig(
			workqueue.NewTypedItemExponentialFailureRateLimiter[string](cfg.RetryMin, cfg.RetryMax),
			workqueue.TypedRateLimitingQueueConfig[string]{}),
	}
	return w, nil
}

// Owner is this incarnation's fence owner ID.
func (w *Worker) Owner() string { return w.owner }

// Start loads desired state from the store, marks every scope that has
// claims as resyncing and starts the reconcilers, the lease checker and the
// periodic resync. They run until ctx is done.
func (w *Worker) Start(ctx context.Context) error {
	if !w.started.CompareAndSwap(false, true) {
		return errors.New("worker: already started")
	}
	recs, err := w.d.Store.List()
	if err != nil {
		return err
	}
	now := w.d.Now()
	w.mu.Lock()
	for _, r := range recs {
		spec := &workerv1alpha1.ClaimSpec{}
		if err := protojson.Unmarshal(r.Spec, spec); err != nil {
			w.mu.Unlock()
			return fmt.Errorf("worker: decode stored spec of %s/%s/%s: %w", r.Node, r.VPC, r.AttachmentUID, err)
		}
		c := &claim{rec: r, spec: spec}
		c.status = w.initialStatus(c, 0)
		w.claims[c.key()] = c
		w.scope(r.VPC).resyncing = true
		w.lastSeen[r.Owner] = now
	}
	scopes := w.scopeNames()
	w.mu.Unlock()
	updateClaimGauge(w)
	for _, s := range scopes {
		w.queue.Add(s)
	}

	for range w.cfg.Reconcilers {
		go w.runReconciler(ctx)
	}
	go func() {
		<-ctx.Done()
		w.queue.ShutDown()
	}()
	go w.every(ctx, w.cfg.RenewInterval, w.ExpireLeases)
	go w.every(ctx, w.cfg.ResyncInterval, func() { w.Changed("") })
	return nil
}

// Shutdown makes every later mutating call fail with UNAVAILABLE and
// ShuttingDown. Forwarding continues: the datapath does not call Worker.
func (w *Worker) Shutdown() { w.shutting.Store(true) }

// Changed requeues the scope of vpc, or every scope when vpc is "". Trusted
// source watches call it; duplicate calls coalesce in the queue.
func (w *Worker) Changed(vpc string) {
	w.mu.Lock()
	var names []string
	if vpc == "" {
		names = w.scopeNames()
	} else if _, ok := w.scopes[vpc]; ok {
		names = []string{vpc}
	}
	w.mu.Unlock()
	for _, n := range names {
		w.queue.Add(n)
	}
}

func (w *Worker) every(ctx context.Context, d time.Duration, fn func()) {
	t := time.NewTicker(d)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			fn()
		}
	}
}

// scope returns the state of a VPC scope, creating it. w.mu must be held.
func (w *Worker) scope(vpc string) *scopeState {
	s, ok := w.scopes[vpc]
	if !ok {
		s = &scopeState{}
		w.scopes[vpc] = s
	}
	return s
}

// scopeNames lists scopes that have claims. w.mu must be held.
func (w *Worker) scopeNames() []string {
	out := make([]string, 0, len(w.scopes))
	for n := range w.scopes {
		out = append(out, n)
	}
	return out
}

// keyLock serializes calls on one claim key.
func (w *Worker) keyLock(k module.ClaimKey) *sync.Mutex {
	h := uint32(2166136261)
	for _, b := range []byte(k.String()) {
		h = (h ^ uint32(b)) * 16777619
	}
	return &w.keyLocks[h%uint32(len(w.keyLocks))]
}

// nextRevision returns the next status revision. w.mu must be held.
func (w *Worker) nextRevision() uint64 {
	w.revision++
	return w.revision
}
