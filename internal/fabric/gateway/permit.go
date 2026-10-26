// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gateway

import (
	"context"
	"errors"
	"slices"
	"sync"
	"time"

	"google.golang.org/grpc/metadata"

	permitv1 "go.datum.net/galactic/api/fabric/permit/v1"
	"go.datum.net/galactic/internal/fabric/errcode"
	"go.datum.net/galactic/internal/fabric/gateway/limit"
	"go.datum.net/galactic/internal/fabric/identity"
	"go.datum.net/galactic/internal/fabric/node"
	"go.datum.net/galactic/internal/fabric/query"
)

// nodePodHeader carries the calling node identity's pod name on a permit
// call a follower forwards to the leader.
const nodePodHeader = forwardingPrefix + "node-pod"

// Permits issues probe permits to nodes for the probes operators send them
// directly, from the same executor and packet budgets as the gateway's own
// node calls. A permit holds one execution slot of the operator's principal
// until the node releases it or the permit's deadline plus
// ReservationGrace passes. Only the leader issues; a follower forwards a
// call once.
type Permits struct {
	permitv1.UnimplementedPermitServiceServer

	// Admission, when nil, refuses every permit: the cell does not enforce
	// aggregate probe budgets.
	Admission *Admission
	Executor  *Executor
	// Discoverer maps a node identity's pod to its node.
	Discoverer *Discoverer
	Elected    func() bool
	Leader     LeaderDialer
	// Now returns the current time; nil selects time.Now.
	Now func() time.Time

	mu   sync.Mutex
	held map[string]heldPermit
}

type heldPermit struct {
	node    string
	release func()
}

func (p *Permits) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

// callerPod returns the node identity's pod a call acts for: the caller
// itself, which must be in namespace, or, on a call a follower forwarded
// after that check, the pod it names.
func callerPod(ctx context.Context, namespace string) (string, error) {
	id, ok := node.CallerFrom(ctx)
	if ok && id.Role == identity.RoleNode && id.Namespace == namespace {
		return id.Name, nil
	}
	if ok && id.Role == identity.RoleGateway {
		md, _ := metadata.FromIncomingContext(ctx)
		if v := md.Get(nodePodHeader); len(v) == 1 && v[0] != "" {
			return v[0], nil
		}
	}
	return "", errcode.Status(errcode.Unauthorized, "only nodes may request probe permits")
}

// forwarded reports whether the call came from the gateway identity, which
// only a follower forwarding to the leader presents.
func forwarded(ctx context.Context) bool {
	id, ok := node.CallerFrom(ctx)
	return ok && id.Role == identity.RoleGateway
}

// operatorPrincipal is the budget key of an operator, whether it calls the
// gateway or a node. Service project IDs cannot contain "/", and a
// FabricQuery's key starts with "fabricquery/", so the families cannot
// collide.
func operatorPrincipal(name string) string { return "operator/" + name }

// forwardCtx hands the caller's pod to the leader.
func forwardCtx(ctx context.Context, pod string) context.Context {
	return metadata.AppendToOutgoingContext(ctx, nodePodHeader, pod)
}

// checkNode refuses a node name the caller's pod does not certify.
func (p *Permits) checkNode(ctx context.Context, pod, nodeName string) error {
	pods, err := p.Discoverer.certPods(ctx)
	if err != nil {
		return errcode.Status(errcode.Internal, "node identities could not be read")
	}
	if !slices.Contains(pods[nodeName], pod) {
		return errcode.Status(errcode.Unauthorized, "the caller's identity does not belong to node "+nodeName)
	}
	return nil
}

// RequestPermit issues a permit for one probe on the calling node.
func (p *Permits) RequestPermit(
	ctx context.Context, req *permitv1.RequestPermitRequest,
) (*permitv1.RequestPermitResponse, error) {
	pod, err := callerPod(ctx, p.Discoverer.Namespace)
	if err != nil {
		return nil, err
	}
	if !p.Elected() {
		if forwarded(ctx) {
			return nil, errcode.Status(errcode.OwnershipLost, "this replica is not the leader")
		}
		conn, err := p.Leader.LeaderConn(ctx)
		if err != nil {
			return nil, errcode.Status(errcode.OwnershipLost, "no leader can issue probe permits")
		}
		return permitv1.NewPermitServiceClient(conn).RequestPermit(forwardCtx(ctx, pod), req)
	}
	if p.Admission == nil {
		return nil, errcode.Status(errcode.LimiterUnavailable, "this cell does not issue probe permits")
	}
	if err := p.checkNode(ctx, pod, req.GetNode()); err != nil {
		return nil, err
	}
	if _, err := identity.Parse(identity.Operator("cell", req.GetOperator()).URI()); err != nil ||
		req.GetOperator() == "" {
		return nil, errcode.Status(errcode.InvalidQuery, "operator is not a valid identity name")
	}
	q := node.QueryFromProto(req.GetQuery())
	if c, err := query.Canonicalize(q); err != nil || c != q || !q.Type.Probe() {
		return nil, errcode.Status(errcode.InvalidQuery, "query is not a canonical probe")
	}
	now := p.now()
	if !req.GetExpiresAt().IsValid() || !req.GetExpiresAt().AsTime().After(now) {
		return nil, errcode.Status(errcode.DeadlineExceeded, "the request has expired")
	}
	deadline := now.Add(query.MaxNodeExecution)
	if e := req.GetExpiresAt().AsTime(); e.Before(deadline) {
		deadline = e
	}
	principal := operatorPrincipal(req.GetOperator())

	wait := min(p.Admission.Limits.QueueWait, deadline.Sub(now))
	actx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	release, err := p.Executor.Acquire(actx, principal, false)
	switch {
	case errors.Is(err, ErrQueueFull):
		return nil, errcode.Retry(errcode.QueueFull, "the cell's execution queue is full", string(limit.ScopeQueue),
			time.Second)
	case err != nil:
		return nil, errcode.Status(errcode.QueueTimeout, "waited too long for a cell execution slot")
	}
	permit, err := p.Admission.permit(ctx, principal, req.GetRequestId(), req.GetNode(), q, deadline)
	if err != nil {
		release()
		return nil, err
	}
	p.hold(permit.GetId(), req.GetNode(), release, deadline.Add(ReservationGrace))
	return &permitv1.RequestPermitResponse{Permit: permit}, nil
}

// hold keeps a permit's slot until it is released or until.
func (p *Permits) hold(id, nodeName string, release func(), until time.Time) {
	var once sync.Once
	free := func() { once.Do(release) }
	p.mu.Lock()
	if p.held == nil {
		p.held = map[string]heldPermit{}
	}
	p.held[id] = heldPermit{node: nodeName, release: free}
	p.mu.Unlock()
	holdUntil(func() {
		p.mu.Lock()
		delete(p.held, id)
		p.mu.Unlock()
		free()
	}, until, p.now())
}

// ReleasePermit frees a finished permit's slot. Only the node the permit
// was issued to may release it; an unknown permit is not an error.
func (p *Permits) ReleasePermit(
	ctx context.Context, req *permitv1.ReleasePermitRequest,
) (*permitv1.ReleasePermitResponse, error) {
	pod, err := callerPod(ctx, p.Discoverer.Namespace)
	if err != nil {
		return nil, err
	}
	if !p.Elected() {
		if forwarded(ctx) {
			return nil, errcode.Status(errcode.OwnershipLost, "this replica is not the leader")
		}
		conn, err := p.Leader.LeaderConn(ctx)
		if err != nil {
			return nil, errcode.Status(errcode.OwnershipLost, "no leader holds probe permits")
		}
		return permitv1.NewPermitServiceClient(conn).ReleasePermit(forwardCtx(ctx, pod), req)
	}
	if p.Admission == nil {
		return &permitv1.ReleasePermitResponse{}, nil
	}
	if err := p.checkNode(ctx, pod, req.GetNode()); err != nil {
		return nil, err
	}
	p.mu.Lock()
	h, ok := p.held[req.GetId()]
	if ok && h.node == req.GetNode() {
		delete(p.held, req.GetId())
	}
	p.mu.Unlock()
	if ok && h.node == req.GetNode() {
		h.release()
	}
	return &permitv1.ReleasePermitResponse{}, nil
}
