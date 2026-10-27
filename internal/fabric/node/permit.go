// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package node

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"google.golang.org/grpc"
	"sigs.k8s.io/controller-runtime/pkg/client"

	permitv1 "go.datum.net/galactic/api/fabric/permit/v1"
	fabricv1 "go.datum.net/galactic/api/fabric/v1"
	"go.datum.net/galactic/internal/fabric/errcode"
	"go.datum.net/galactic/internal/fabric/gateway/limit"
	"go.datum.net/galactic/internal/fabric/query"
)

// Probe permit bounds on the node.
const (
	// PermitStartupRefusal is how long after start a node refuses every
	// permit: its record of consumed permits was lost with its last process,
	// and a surviving permit lives at most 30 s plus skew.
	PermitStartupRefusal = 32 * time.Second
	// PermitGrace is how long a consumed permit ID is kept past its
	// deadline.
	PermitGrace = 2 * time.Second
	// MaxPermitLifetime bounds how far away a permit's deadline may be,
	// with one second of clock skew allowed.
	MaxPermitLifetime = query.MaxNodeExecution + time.Second
	// DefaultConsumedPermits and DefaultConsumedPermitBytes bound the
	// consumed-permit set.
	DefaultConsumedPermits     = 4096
	DefaultConsumedPermitBytes = 2 << 20
	// permitReleaseTimeout bounds the best-effort release of a direct
	// operator permit.
	permitReleaseTimeout = 2 * time.Second
	consumedOverhead     = 64
)

// PermitGateway obtains and releases permits from the cell's gateway on a
// direct operator's behalf. GatewayConn and permitv1.PermitServiceClient
// satisfy it.
type PermitGateway interface {
	RequestPermit(ctx context.Context, in *permitv1.RequestPermitRequest,
		opts ...grpc.CallOption) (*permitv1.RequestPermitResponse, error)
	ReleasePermit(ctx context.Context, in *permitv1.ReleasePermitRequest,
		opts ...grpc.CallOption) (*permitv1.ReleasePermitResponse, error)
}

// Permits verifies and consumes probe permits. A permit is accepted once:
// for this node, request, operation and destination, before its deadline,
// at least PermitStartupRefusal after the node started, and only while the
// gateway election Lease, read uncached, still carries the permit's epoch.
// Consumed IDs are kept until their deadline plus PermitGrace in a set that
// fails closed when full. A node whose Clock is unhealthy refuses every
// permit.
type Permits struct {
	// Reader reads the gateway's election Lease uncached.
	Reader    client.Reader
	Namespace string
	LeaseName string
	// Require refuses a probe without a permit. A direct operator's probe
	// then obtains one from Gateway.
	Require bool
	// Gateway issues permits for direct operator probes; nil refuses them
	// when Require is set.
	Gateway PermitGateway
	// Started is when this process started.
	Started time.Time
	// MaxConsumed and MaxConsumedBytes bound the consumed set; zero selects
	// the defaults.
	MaxConsumed, MaxConsumedBytes int
	// Clock, when set, reports an error while this host's clock cannot be
	// trusted within limit.MaxClockError; every permit is then refused.
	Clock func() error
	// Metrics, when set, counts each permit decision.
	Metrics *Metrics

	mu       sync.Mutex
	consumed map[string]consumedPermit
	bytes    int
}

type consumedPermit struct {
	until time.Time
	size  int
}

// grant is a consumed permit's packet allowance and deadline.
type grant struct {
	packets  int
	deadline time.Time
}

// Permit decisions, as fabric_api_node_permits_total's outcome label
// reports them.
const (
	PermitAccepted  = "accepted"
	permitInvalid   = "invalid"
	permitMalformed = "malformed"
	permitMismatch  = "mismatch"
	permitExpired   = "expired"
	permitStarting  = "starting"
	permitClock     = "clock"
	permitLease     = "lease"
	permitEpoch     = "epoch"
	permitReplayed  = "replayed"
	permitFull      = "full"
)

// consume verifies p for q on node and records it consumed.
func (p *Permits) consume(ctx context.Context, pm *fabricv1.ProbePermit, node, requestID string, q query.Query,
	now time.Time) (grant, error) {
	refuse := func(outcome, msg string) (grant, error) {
		p.observe(outcome)
		return grant{}, errcode.Status(errcode.LimiterUnavailable, msg)
	}
	dst, err := query.ResolvedProbe(q)
	if err != nil {
		p.observe(permitInvalid)
		return grant{}, errcode.FromError(err)
	}
	deadline := pm.GetDeadline().AsTime()
	switch {
	case pm.GetId() == "" || !pm.GetDeadline().IsValid():
		return refuse(permitMalformed, "the probe permit is malformed")
	case pm.GetNode() != node || pm.GetRequestId() != requestID ||
		pm.GetOperation() != QueryToProto(q).GetType() || pm.GetDestination() != dst.String():
		return refuse(permitMismatch, "the probe permit does not match this probe")
	case !now.Before(deadline) || deadline.Sub(now) > MaxPermitLifetime:
		return refuse(permitExpired, "the probe permit has expired or is too long-lived")
	case p.starting(now):
		return refuse(permitStarting, "this node accepts no probe permit until its startup refusal ends")
	case p.Clock != nil && p.Clock() != nil:
		return refuse(permitClock, "this node's clock is not synchronised")
	}
	epoch, err := limit.ReadEpoch(ctx, p.Reader, p.Namespace, p.LeaseName, now)
	if err != nil {
		p.observe(permitLease)
		return grant{}, err
	}
	if epoch.String() != pm.GetEpoch() {
		p.observe(permitEpoch)
		return grant{}, errcode.Status(errcode.OwnershipLost, "the probe permit is from another gateway epoch")
	}
	if outcome, err := p.record(pm.GetId(), deadline.Add(PermitGrace), now); err != nil {
		p.observe(outcome)
		return grant{}, err
	}
	p.observe(PermitAccepted)
	return grant{packets: int(pm.GetPackets()), deadline: deadline}, nil
}

func (p *Permits) observe(outcome string) {
	if p.Metrics != nil {
		p.Metrics.permits.WithLabelValues(outcome).Inc()
	}
}

// starting reports whether the node is still in its startup refusal.
func (p *Permits) starting(now time.Time) bool {
	return now.Before(p.Started.Add(PermitStartupRefusal))
}

// record adds id to the consumed set, refusing a consumed ID and failing
// closed when the set is full of live entries. A refusal returns its
// outcome.
func (p *Permits) record(id string, until, now time.Time) (string, error) {
	maxN, maxBytes := p.MaxConsumed, p.MaxConsumedBytes
	if maxN <= 0 {
		maxN = DefaultConsumedPermits
	}
	if maxBytes <= 0 {
		maxBytes = DefaultConsumedPermitBytes
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.consumed == nil {
		p.consumed = map[string]consumedPermit{}
	}
	if c, ok := p.consumed[id]; ok && now.Before(c.until) {
		return permitReplayed, errcode.Status(errcode.LimiterUnavailable, "the probe permit was already used")
	}
	size := len(id) + consumedOverhead
	if len(p.consumed) >= maxN || p.bytes+size > maxBytes {
		for k, c := range p.consumed {
			if !now.Before(c.until) {
				delete(p.consumed, k)
				p.bytes -= c.size
			}
		}
	}
	if len(p.consumed) >= maxN || p.bytes+size > maxBytes {
		return permitFull, errcode.Status(errcode.LimiterUnavailable, "this node's consumed-permit set is full")
	}
	p.consumed[id] = consumedPermit{until: until, size: size}
	p.bytes += size
	return "", nil
}

// obtain asks the gateway for a permit for a direct operator's probe. A
// node in its startup refusal asks for none, since it could not use it and
// the gateway refunds nothing.
func (p *Permits) obtain(ctx context.Context, node, operator string, req *fabricv1.ExecuteRequest, now time.Time,
) (*fabricv1.ProbePermit, error) {
	if p.Gateway == nil {
		return nil, errcode.Status(errcode.LimiterUnavailable, "this node cannot obtain probe permits")
	}
	if p.starting(now) {
		return nil, errcode.Status(errcode.LimiterUnavailable,
			"this node accepts no probe permit until its startup refusal ends")
	}
	resp, err := p.Gateway.RequestPermit(ctx, &permitv1.RequestPermitRequest{
		Node: node, Operator: operator, RequestId: req.GetRequestId(), Query: req.GetQuery(),
		ExpiresAt: req.GetExpiresAt(),
	})
	if err != nil {
		if errcode.Typed(err) {
			return nil, err
		}
		return nil, errcode.Status(errcode.LimiterUnavailable, "the gateway did not issue a probe permit")
	}
	return resp.GetPermit(), nil
}

// release tells the gateway a direct operator's permit is finished, so its
// slot frees before the permit expires. It is best effort: a lost release
// holds the slot only until the permit's deadline plus its grace.
func (p *Permits) release(node, id string) {
	if p.Gateway == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), permitReleaseTimeout)
	defer cancel()
	if _, err := p.Gateway.ReleasePermit(ctx, &permitv1.ReleasePermitRequest{Node: node, Id: id}); err != nil {
		slog.Debug("probe permit release failed", "code", errcode.Of(err))
	}
}
