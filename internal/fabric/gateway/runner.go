// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gateway

import (
	"context"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/protobuf/types/known/timestamppb"

	fabricv1 "go.datum.net/galactic/api/fabric/v1"
	"go.datum.net/galactic/internal/fabric/errcode"
	"go.datum.net/galactic/internal/fabric/gateway/limit"
	"go.datum.net/galactic/internal/fabric/identity"
	"go.datum.net/galactic/internal/fabric/node"
	"go.datum.net/galactic/internal/fabric/query"
)

// NodeClients returns a FabricService client for a node.
type NodeClients interface {
	Client(n Node) (fabricv1.FabricServiceClient, error)
}

// Pool keeps one mTLS connection per sidecar pod, each verifying that the
// server proves that pod's identity.
type Pool struct {
	Credentials *identity.Credentials
	Cell        string
	Namespace   string
	// MaxRecvBytes caps a node response at the gRPC layer.
	MaxRecvBytes int
	// DialOptions are added to every connection, e.g. tracing.
	DialOptions []grpc.DialOption

	mu    sync.Mutex
	conns map[string]*grpc.ClientConn
}

func (p *Pool) key(n Node) string {
	return n.PodUID + "|" + strings.Join(n.IdentityPods, ",") + "|" + n.Address()
}

// Client returns a client for n, dialing lazily.
func (p *Pool) Client(n Node) (fabricv1.FabricServiceClient, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.conns == nil {
		p.conns = map[string]*grpc.ClientConn{}
	}
	k := p.key(n)
	if c, ok := p.conns[k]; ok {
		return fabricv1.NewFabricServiceClient(c), nil
	}
	pods := n.IdentityPods
	if len(pods) == 0 {
		pods = []string{n.IdentityPod}
	}
	want := make([]identity.ID, 0, len(pods))
	for _, pod := range pods {
		want = append(want, identity.Node(p.Cell, p.Namespace, pod))
	}
	maxRecv := p.MaxRecvBytes
	if maxRecv <= 0 {
		maxRecv = query.Ceilings.MaxNodeResponseBytes + 16<<10
	}
	opts := append([]grpc.DialOption{
		grpc.WithTransportCredentials(credentials.NewTLS(p.Credentials.ClientConfigAny(want...))),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(maxRecv)),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{Time: time.Minute, Timeout: 10 * time.Second}),
	}, p.DialOptions...)
	conn, err := grpc.NewClient(n.Address(), opts...)
	if err != nil {
		return nil, err
	}
	p.conns[k] = conn
	return fabricv1.NewFabricServiceClient(conn), nil
}

// Retain closes connections to pods not in live.
func (p *Pool) Retain(live []Node) {
	keep := map[string]bool{}
	for _, n := range live {
		keep[p.key(n)] = true
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for k, c := range p.conns {
		if !keep[k] {
			_ = c.Close()
			delete(p.conns, k)
		}
	}
}

// Close closes every connection.
func (p *Pool) Close() { p.Retain(nil) }

// Outcome is one node's result: an observation or an error code.
type Outcome struct {
	Node        Node
	Observation *fabricv1.Observation
	Err         error
	// Completed is when the node's result was handed off.
	Completed time.Time
}

// ServiceQueueWait bounds how long a Looking Glass service router job waits
// for a cell execution slot.
const ServiceQueueWait = 10 * time.Second

// Runner fans one query out to a node snapshot through the cell's executor.
type Runner struct {
	Clients  NodeClients
	Executor *Executor
	Metrics  *Metrics
	// Admission, when set, enforces the cell's aggregate probe budgets on
	// every caller: each probe is dispatched only with a permit charged to
	// its principal, destination and cell, a probe's slot whose node answer
	// was lost stays held until the job's deadline plus ReservationGrace,
	// and a full principal or cell queue is QueueFull with retry guidance.
	Admission *Admission
	// QueueWait bounds a Stream job's wait for an execution slot; zero
	// selects ServiceQueueWait.
	QueueWait time.Duration
	// Now returns the current time; nil selects time.Now.
	Now func() time.Time

	// permitPods caches, per sidecar pod UID, whether the node enforces
	// probe permits; it is cleared when it reaches maxPermitPods.
	permitMu   sync.Mutex
	permitPods map[string]bool
}

// maxPermitPods bounds the probe-permit capability cache.
const maxPermitPods = 1024

func (r *Runner) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// runOptions distinguish the service's execution from the operator's and
// FabricQuery's.
type runOptions struct {
	// retryReads repeats a cheap read once when it failed to connect.
	retryReads bool
	// queueWait, when positive, bounds a job's wait for an execution slot;
	// exceeding it fails the job with QueueTimeout.
	queueWait time.Duration
	// requestCodes reports a failure caused by ctx ending as
	// DeadlineExceeded or Cancelled rather than Timeout.
	requestCodes bool
	// reservation, when set, holds the queue capacity every job uses.
	reservation *Reservation
	// checkOwnership confirms the election before every dispatch, not
	// only a probe's.
	checkOwnership bool
}

// Run executes q on every selected node in nodes and returns one outcome per
// selected node, sorted by node name. Each node's deadline is the earlier of
// the request's expiration and the node maximum, fixed before it queues for
// a slot, so time spent waiting counts against it. A failed node does not
// fail the others.
func (r *Runner) Run(ctx context.Context, project, requestID string, q query.Query, nodes []Node,
	budgets *fabricv1.Budgets, expires time.Time) []Outcome {
	var mu sync.Mutex
	var out []Outcome
	r.fanOut(ctx, project, requestID, q, nodes, budgets, expires, runOptions{retryReads: true}, func(o Outcome) {
		mu.Lock()
		out = append(out, o)
		mu.Unlock()
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Node.Name < out[j].Node.Name })
	return out
}

// Stream executes q on every selected node in nodes like Run, but hands each
// node's outcome to emit as soon as that node finishes, so a slow node never
// delays a finished one. emit runs on the finished node's goroutine and may
// be called concurrently; Stream returns once every call has returned. It
// never repeats a node call, bounds each job's wait for a slot by
// QueueWait (QueueTimeout), and reports a job cut short by ctx ending
// as DeadlineExceeded or Cancelled; a node's own 30 s bound stays Timeout.
// Jobs queue on res when it is set, and with Admission set every dispatch
// first confirms the election.
func (r *Runner) Stream(ctx context.Context, project, requestID string, q query.Query, nodes []Node,
	budgets *fabricv1.Budgets, expires time.Time, res *Reservation, emit func(Outcome)) {
	wait := r.QueueWait
	if wait <= 0 {
		wait = ServiceQueueWait
	}
	r.fanOut(ctx, project, requestID, q, nodes, budgets, expires,
		runOptions{queueWait: wait, requestCodes: true, reservation: res, checkOwnership: true}, emit)
}

func (r *Runner) fanOut(ctx context.Context, project, requestID string, q query.Query, nodes []Node,
	budgets *fabricv1.Budgets, expires time.Time, opts runOptions, emit func(Outcome)) {
	wire := node.QueryToProto(q)
	var wg sync.WaitGroup
	for _, n := range nodes {
		if !n.Selected {
			continue
		}
		deadline := r.now().Add(query.MaxNodeExecution)
		if expires.Before(deadline) {
			deadline = expires
		}
		wg.Go(func() {
			nctx, cancel := context.WithDeadline(ctx, deadline)
			defer cancel()
			obs, err := r.one(nctx, project, requestID, wire, q, n, budgets, expires, deadline, opts)
			if opts.requestCodes {
				// When the request's expiration is the node's deadline, the
				// node's timer can fire before ctx's: both mean the request
				// expired.
				expired := deadline.Equal(expires) && errors.Is(nctx.Err(), context.DeadlineExceeded)
				err = requestErr(ctx, err, expired)
			}
			emit(Outcome{Node: n, Observation: obs, Err: err, Completed: r.now()})
		})
	}
	wg.Wait()
}

// errOwnershipLost is the cause with which a service request's execution is
// cancelled when the gateway loses the election.
var errOwnershipLost = errors.New("the gateway lost execution ownership")

// errOutputLimit is the cause with which a service request's execution is
// cancelled when its stream's output budget runs out.
var errOutputLimit = errors.New("the stream's output budget is exhausted")

// requestErr reports a failure that ctx's end, or the request's expiration,
// caused as the request's own DeadlineExceeded, Cancelled (also when the
// service was turned off) or, when the election was lost or the output
// budget ran out, OwnershipLost or OutputLimitExceeded.
func requestErr(ctx context.Context, err error, expired bool) error {
	if err == nil || (ctx.Err() == nil && !expired) {
		return err
	}
	switch errcode.Of(err) {
	case errcode.Timeout, errcode.NodeUnreachable, errcode.QueueTimeout, errcode.Cancelled:
	default:
		return err
	}
	if errors.Is(context.Cause(ctx), errOwnershipLost) {
		return errcode.Status(errcode.OwnershipLost, "the gateway lost execution ownership before the router finished")
	}
	if errors.Is(context.Cause(ctx), errServiceDisabled) {
		return errcode.Status(errcode.Cancelled, "the service was disabled before the router finished")
	}
	if errors.Is(context.Cause(ctx), errOutputLimit) {
		return errcode.Status(errcode.OutputLimitExceeded, "the stream's output budget ran out before the router finished")
	}
	if expired || errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return errcode.Status(errcode.DeadlineExceeded, "the request's deadline passed before the router finished")
	}
	return errcode.Status(errcode.Cancelled, "the request was cancelled before the router finished")
}

func (r *Runner) one(ctx context.Context, project, requestID string, wire *fabricv1.Query, q query.Query, n Node,
	budgets *fabricv1.Budgets, expires, deadline time.Time, opts runOptions) (*fabricv1.Observation, error) {
	actx := ctx
	if opts.queueWait > 0 {
		var cancel context.CancelFunc
		actx, cancel = context.WithTimeout(ctx, opts.queueWait)
		defer cancel()
	}
	var release func()
	var err error
	if opts.reservation != nil {
		release, err = opts.reservation.Acquire(actx, q.Type.Expensive())
	} else {
		release, err = r.Executor.Acquire(actx, project, q.Type.Expensive())
	}
	if err != nil {
		if errors.Is(err, ErrQueueFull) {
			if r.Admission != nil {
				err := errcode.Retry(errcode.QueueFull, "the cell's execution queue is full",
					string(limit.ScopeQueue), time.Second)
				r.Admission.Metrics.refused(project, err)
				return nil, err
			}
			return nil, errcode.Status(errcode.NodeBusy, "cell execution queue is full")
		}
		if ctx.Err() == nil {
			return nil, errcode.Status(errcode.QueueTimeout, "waited too long for a cell execution slot")
		}
		return nil, errcode.Status(errcode.Timeout, "deadline passed waiting for a cell execution slot")
	}
	held := false
	defer func() {
		if !held {
			release()
		}
	}()

	c, err := r.Clients.Client(n)
	if err != nil {
		return nil, errcode.Status(errcode.NodeUnreachable, err.Error())
	}
	req := &fabricv1.ExecuteRequest{
		RequestId: requestID, Node: n.Name, Query: wire, Budgets: budgets, ExpiresAt: timestamppb.New(expires),
	}
	if a := r.Admission; a != nil {
		switch {
		case q.Type.Probe():
			if err := r.checkPermits(ctx, c, n); err != nil {
				return nil, err
			}
			if req.Permit, err = a.permit(ctx, project, requestID, n.Name, q, deadline); err != nil {
				return nil, err
			}
		case opts.checkOwnership:
			if _, _, err := a.Authority.Check(ctx); err != nil {
				a.Metrics.refused(project, err)
				return nil, err
			}
		}
	}
	start := r.now()
	resp, err := c.Execute(ctx, req)
	if r.Admission != nil && q.Type.Probe() && err != nil && !errcode.Typed(err) {
		// No answer from the node: it may still be sending the probe.
		held = true
		holdUntil(release, deadline.Add(ReservationGrace), r.now())
	}
	// A cheap read that failed to connect is safe to repeat once: the node
	// deduplicates by request ID. Searches and probes are never retried
	// within an attempt, since their first execution may have run.
	if err != nil && opts.retryReads && errcode.Of(err) == errcode.NodeUnreachable &&
		!q.Type.Expensive() && !q.Type.Probe() && ctx.Err() == nil {
		resp, err = c.Execute(ctx, req)
	}
	if r.Metrics != nil {
		code := "OK"
		if err != nil {
			code = string(errcode.Of(err))
		}
		r.Metrics.rpcDuration.WithLabelValues(string(q.Type), code).Observe(r.now().Sub(start).Seconds())
	}
	if err != nil {
		if ctx.Err() != nil && errcode.Of(err) == errcode.NodeUnreachable {
			return nil, errcode.Status(errcode.Timeout, "node did not answer before the deadline")
		}
		return nil, err
	}
	return resp.GetObservation(), nil
}

// checkPermits refuses a node whose sidecar does not enforce probe permits:
// it would ignore its permit's allowance and deadline. The answer is cached
// per pod, whose UID changes with its image.
func (r *Runner) checkPermits(ctx context.Context, c fabricv1.FabricServiceClient, n Node) error {
	r.permitMu.Lock()
	ok, cached := r.permitPods[n.PodUID]
	r.permitMu.Unlock()
	if !cached {
		info, err := c.Info(ctx, &fabricv1.InfoRequest{})
		if err != nil {
			return errcode.Status(errcode.NodeUnreachable, "the node did not report its capabilities")
		}
		ok = info.GetProbePermits()
		r.permitMu.Lock()
		if r.permitPods == nil || len(r.permitPods) >= maxPermitPods {
			r.permitPods = map[string]bool{}
		}
		r.permitPods[n.PodUID] = ok
		r.permitMu.Unlock()
	}
	if !ok {
		return errcode.Status(errcode.QueryTypeUnavailable, "the node does not enforce probe permits")
	}
	return nil
}
