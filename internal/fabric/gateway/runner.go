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
}

// Runner fans one query out to a node snapshot through the cell's executor.
type Runner struct {
	Clients  NodeClients
	Executor *Executor
	Metrics  *Metrics
	// Now returns the current time; nil selects time.Now.
	Now func() time.Time
}

func (r *Runner) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// Run executes q on every selected node in nodes and returns one outcome per
// selected node, sorted by node name. Each node's deadline is the earlier of
// the request's expiration and the node maximum, fixed before it queues for
// a slot, so time spent waiting counts against it. A failed node does not
// fail the others.
func (r *Runner) Run(ctx context.Context, project, requestID string, q query.Query, nodes []Node,
	budgets *fabricv1.Budgets, expires time.Time) []Outcome {
	var selected []Node
	for _, n := range nodes {
		if n.Selected {
			selected = append(selected, n)
		}
	}
	out := make([]Outcome, len(selected))
	wire := node.QueryToProto(q)
	var wg sync.WaitGroup
	for i, n := range selected {
		deadline := r.now().Add(query.MaxNodeExecution)
		if expires.Before(deadline) {
			deadline = expires
		}
		wg.Go(func() {
			nctx, cancel := context.WithDeadline(ctx, deadline)
			defer cancel()
			obs, err := r.one(nctx, project, requestID, wire, q, n, budgets, expires)
			out[i] = Outcome{Node: n, Observation: obs, Err: err}
		})
	}
	wg.Wait()
	sort.Slice(out, func(i, j int) bool { return out[i].Node.Name < out[j].Node.Name })
	return out
}

func (r *Runner) one(ctx context.Context, project, requestID string, wire *fabricv1.Query, q query.Query, n Node,
	budgets *fabricv1.Budgets, expires time.Time) (*fabricv1.Observation, error) {
	release, err := r.Executor.Acquire(ctx, project, q.Type.Expensive())
	if err != nil {
		if errors.Is(err, ErrQueueFull) {
			return nil, errcode.Status(errcode.NodeBusy, "cell execution queue is full")
		}
		return nil, errcode.Status(errcode.Timeout, "deadline passed waiting for a cell execution slot")
	}
	defer release()

	c, err := r.Clients.Client(n)
	if err != nil {
		return nil, errcode.Status(errcode.NodeUnreachable, err.Error())
	}
	req := &fabricv1.ExecuteRequest{
		RequestId: requestID, Node: n.Name, Query: wire, Budgets: budgets, ExpiresAt: timestamppb.New(expires),
	}
	start := r.now()
	resp, err := c.Execute(ctx, req)
	// A cheap read that failed to connect is safe to repeat once: the node
	// deduplicates by request ID. Searches and probes are never retried
	// within an attempt, since their first execution may have run.
	if err != nil && errcode.Of(err) == errcode.NodeUnreachable &&
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
