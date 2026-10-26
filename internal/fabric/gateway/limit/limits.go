// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package limit holds the cell gateway's aggregate admission state: request
// and packet token buckets, the live attempt keys, and the election
// authority that decides when that state may be used. The leader keeps it
// all in bounded memory; followers keep none.
//
// Every probe a cell runs, whether for a service project, a FabricQuery or an
// operator, charges its worst-case packets to the cell, its principal, its
// destination host and its destination prefix; every request or node job
// takes an execution slot. Nothing charged is refunded. After the process
// acquires or loses the election it admits nothing for a recovery hold, then
// starts every bucket empty.
package limit

import (
	"errors"
	"fmt"
	"math"
	"time"

	"go.datum.net/galactic/internal/fabric/query"
)

// Rate is a token bucket's sustained refill rate, in tokens per second, and
// its burst.
type Rate struct {
	PerSecond float64
	Burst     float64
}

// Probe packet costs, charged as each probe's worst case.
const (
	PingPackets       = query.PingCount
	TraceroutePackets = query.TracerouteMaxHops * query.TracerouteProbesPerHop
)

// Hard bounds on the limiter's own memory and on what one request may hold.
// A configuration may lower them, never raise them.
const (
	MaxProjectKeys     = 4096
	MaxDestinationKeys = 16384
	MaxAttempts        = 4096
	MaxAttemptBytes    = 2 << 20
	MaxSlots           = 8
	MaxQueue           = 256
	MaxStreams         = 16
	// MaxBurstSeconds bounds every bucket's burst/rate, so the recovery
	// hold also clears the largest token debt a prior epoch could leave.
	MaxBurstSeconds = 120
	// MaxQueueWait bounds a node job's wait for an execution slot.
	MaxQueueWait = 10 * time.Second
)

// Limits are the cell's aggregate admission settings.
type Limits struct {
	// RequestCell and RequestProject charge one token per service request.
	RequestCell, RequestProject Rate
	// PacketCell, PacketPrincipal, PacketHost and PacketPrefix charge each
	// probe's worst-case packets; PacketPrincipal is a project's or a direct
	// operator's budget.
	PacketCell, PacketPrincipal, PacketHost, PacketPrefix Rate
	// Slots and PrincipalSlots bound active node jobs in the cell and per
	// principal.
	Slots, PrincipalSlots int
	// Queue and PrincipalQueue bound queued node jobs in the cell and per
	// principal.
	Queue, PrincipalQueue int
	// Streams and ProjectStreams bound live service streams in the cell and
	// per project, queued and draining ones included.
	Streams, ProjectStreams int
	// QueueWait bounds a node job's wait for an execution slot.
	QueueWait time.Duration
	// ProjectKeys and DestinationKeys bound the limiter's bucket maps.
	ProjectKeys, DestinationKeys int
	// Attempts and AttemptBytes bound the live attempt-key cache.
	Attempts, AttemptBytes int
}

// Defaults returns the contract's initial limits.
func Defaults() Limits {
	return Limits{
		RequestCell:     Rate{PerSecond: 2, Burst: 8},
		RequestProject:  Rate{PerSecond: 0.2, Burst: 2},
		PacketCell:      Rate{PerSecond: 100, Burst: 640},
		PacketPrincipal: Rate{PerSecond: 20, Burst: 640},
		PacketHost:      Rate{PerSecond: 20, Burst: 640},
		PacketPrefix:    Rate{PerSecond: 40, Burst: 640},
		Slots:           MaxSlots,
		PrincipalSlots:  2,
		Queue:           MaxQueue,
		PrincipalQueue:  32,
		Streams:         MaxStreams,
		ProjectStreams:  2,
		QueueWait:       MaxQueueWait,
		ProjectKeys:     MaxProjectKeys,
		DestinationKeys: MaxDestinationKeys,
		Attempts:        MaxAttempts,
		AttemptBytes:    MaxAttemptBytes,
	}
}

// Validate refuses limits that break a cross-field rule: a non-positive
// rate, a burst/rate above MaxBurstSeconds, a packet burst that cannot fund
// one traceroute, a per-project or per-principal limit above its cell's, or
// any bound above its hard maximum.
func (l Limits) Validate() error {
	var errs []error
	rate := func(name string, r Rate, minBurst float64) {
		switch {
		case !(r.PerSecond > 0) || !(r.Burst > 0) || math.IsInf(r.PerSecond, 0) || math.IsInf(r.Burst, 0):
			errs = append(errs, fmt.Errorf("%s: rate and burst must be positive and finite", name))
		case r.Burst/r.PerSecond > MaxBurstSeconds:
			errs = append(errs, fmt.Errorf("%s: burst/rate exceeds %d s", name, MaxBurstSeconds))
		case r.Burst < minBurst:
			errs = append(errs, fmt.Errorf("%s: burst %g cannot fund a %g-token charge", name, r.Burst, minBurst))
		}
	}
	rate("request cell", l.RequestCell, 1)
	rate("request project", l.RequestProject, 1)
	rate("packet cell", l.PacketCell, TraceroutePackets)
	rate("packet principal", l.PacketPrincipal, TraceroutePackets)
	rate("packet host", l.PacketHost, TraceroutePackets)
	rate("packet prefix", l.PacketPrefix, TraceroutePackets)
	within := func(name string, inner, outer Rate) {
		if inner.PerSecond > outer.PerSecond || inner.Burst > outer.Burst {
			errs = append(errs, fmt.Errorf("%s exceeds its cell limit", name))
		}
	}
	within("request project", l.RequestProject, l.RequestCell)
	within("packet principal", l.PacketPrincipal, l.PacketCell)
	within("packet host", l.PacketHost, l.PacketCell)
	within("packet prefix", l.PacketPrefix, l.PacketCell)
	bound := func(name string, v, lo, hi int) {
		if v < lo || v > hi {
			errs = append(errs, fmt.Errorf("%s must be %d to %d, not %d", name, lo, hi, v))
		}
	}
	bound("slots", l.Slots, 1, MaxSlots)
	bound("principal slots", l.PrincipalSlots, 1, l.Slots)
	bound("queue", l.Queue, 1, MaxQueue)
	bound("principal queue", l.PrincipalQueue, 1, l.Queue)
	bound("streams", l.Streams, 1, MaxStreams)
	bound("project streams", l.ProjectStreams, 1, l.Streams)
	bound("project keys", l.ProjectKeys, 1, MaxProjectKeys)
	bound("destination keys", l.DestinationKeys, 2, MaxDestinationKeys)
	bound("attempts", l.Attempts, 1, MaxAttempts)
	bound("attempt bytes", l.AttemptBytes, 1, MaxAttemptBytes)
	if l.QueueWait <= 0 || l.QueueWait > MaxQueueWait {
		errs = append(errs, fmt.Errorf("queue wait must be positive and at most %s", MaxQueueWait))
	}
	return errors.Join(errs...)
}
