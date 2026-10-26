// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gateway

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	servicev1 "go.datum.net/galactic/api/fabric/service/v1"
	fabricv1 "go.datum.net/galactic/api/fabric/v1"
	"go.datum.net/galactic/internal/fabric/errcode"
	"go.datum.net/galactic/internal/fabric/gateway/limit"
	"go.datum.net/galactic/internal/fabric/identity"
	"go.datum.net/galactic/internal/fabric/node"
	"go.datum.net/galactic/internal/fabric/query"
)

// ReservationGrace is how long past a probe job's deadline its execution
// slot stays held when the node's answer was lost: the node may still be
// sending it.
const ReservationGrace = 2 * time.Second

// Admission is the leader's aggregate accounting: service request tokens,
// attempt keys and live streams, and the packet budgets every probe in the
// cell draws from, whatever its caller. Nothing is admitted unless the
// Authority confirms this process holds the election, outside its recovery
// hold.
type Admission struct {
	Limits    limit.Limits
	Buckets   *limit.Buckets
	Attempts  *limit.Attempts
	Authority *limit.Authority
	// Metrics, when set, counts refusals and charged packets.
	Metrics *Metrics
	// Now returns the current time; nil selects time.Now.
	Now func() time.Time

	mu             sync.Mutex
	streams        int
	projectStreams map[string]int
}

// NewAdmission validates l and returns empty accounting under authority,
// which it gives its buckets.
func NewAdmission(l limit.Limits, authority *limit.Authority) (*Admission, error) {
	if err := l.Validate(); err != nil {
		return nil, err
	}
	b := limit.NewBuckets(l, time.Now())
	authority.Buckets = b
	return &Admission{Limits: l, Buckets: b, Attempts: limit.NewAttempts(l), Authority: authority}, nil
}

func (a *Admission) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

// Executor returns a shared executor bounded by the admission's limits.
func (a *Admission) Executor() *Executor {
	e := NewExecutor(a.Limits.Slots, 0, a.Limits.Queue)
	e.PrincipalSlots, e.PrincipalQueue = a.Limits.PrincipalSlots, a.Limits.PrincipalQueue
	return e
}

// openStream counts a live service stream for project, or refuses with
// QueueFull when the cell's or the project's stream limit is reached. The
// returned function ends it.
func (a *Admission) openStream(project string) (func(), error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.projectStreams == nil {
		a.projectStreams = map[string]int{}
	}
	if a.streams >= a.Limits.Streams || a.projectStreams[project] >= a.Limits.ProjectStreams {
		err := errcode.Retry(errcode.QueueFull, "the live stream limit is reached", string(limit.ScopeQueue),
			time.Second)
		a.Metrics.refused(project, err)
		return nil, err
	}
	a.streams++
	a.projectStreams[project]++
	return func() {
		a.mu.Lock()
		defer a.mu.Unlock()
		a.streams--
		if a.projectStreams[project]--; a.projectStreams[project] <= 0 {
			delete(a.projectStreams, project)
		}
	}, nil
}

// liveStreams returns the live service streams.
func (a *Admission) liveStreams() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.streams
}

// admit admits a service request before its discovery: it confirms the
// election, charges the cell's and the project's request tokens, registers
// the attempt key and opens a live stream. It returns the epoch's context
// and the function that ends the stream.
func (a *Admission) admit(
	ctx context.Context, caller identity.ID, req *servicev1.RunDiagnosticRequest,
) (context.Context, func(), error) {
	project := req.GetProjectId()
	refuse := func(err error) (context.Context, func(), error) {
		a.Metrics.refused(project, err)
		return nil, nil, err
	}
	_, epochCtx, err := a.Authority.Check(ctx)
	if err != nil {
		return refuse(err)
	}
	if err := a.Buckets.ChargeRequest(project, a.now()); err != nil {
		return refuse(err)
	}
	if err := a.Attempts.Register(attemptKey(caller, req), requestDigest(req), req.GetExpiresAt().AsTime(),
		a.now()); err != nil {
		return refuse(err)
	}
	closeStream, err := a.openStream(project)
	if err != nil {
		return nil, nil, err
	}
	return epochCtx, closeStream, nil
}

// probeCost is a probe's worst-case packet count.
func probeCost(t query.Type) int {
	if t == query.TypeTraceroute {
		return limit.TraceroutePackets
	}
	return limit.PingPackets
}

// permit confirms ownership, charges q's worst-case packets to the cell,
// principal and destination buckets, and returns a single-attempt permit
// for n until deadline. Nothing is refunded once charged.
func (a *Admission) permit(
	ctx context.Context, principal, requestID, nodeName string, q query.Query, deadline time.Time,
) (*fabricv1.ProbePermit, error) {
	epoch, _, err := a.Authority.Check(ctx)
	if err != nil {
		a.Metrics.refused(principal, err)
		return nil, err
	}
	dst, err := query.ResolvedProbe(q)
	if err != nil {
		return nil, errcode.FromError(err)
	}
	cost := probeCost(q.Type)
	if err := a.Buckets.ChargePackets(principal, dst, cost, a.now()); err != nil {
		a.Metrics.refused(principal, err)
		return nil, err
	}
	a.Metrics.charged(principal, cost)
	return &fabricv1.ProbePermit{
		Id:          newPermitID(),
		Epoch:       epoch.String(),
		RequestId:   requestID,
		Node:        nodeName,
		Destination: dst.String(),
		Operation:   node.QueryToProto(q).GetType(),
		Packets:     uint32(cost),
		Deadline:    timestamppb.New(deadline),
	}, nil
}

func newPermitID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// holdUntil releases a slot at until rather than now: a node whose answer
// was lost may still be executing until its deadline plus
// ReservationGrace.
func holdUntil(release func(), until, now time.Time) {
	if d := until.Sub(now); d > 0 {
		time.AfterFunc(d, release)
		return
	}
	release()
}
