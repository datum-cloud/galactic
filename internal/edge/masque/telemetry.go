// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package masque

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"go.miloapis.com/instrumentation/labels"
	"go.miloapis.com/instrumentation/metrics"
)

// Admission outcomes, the outcome label of admissionsTotal.
const (
	admitAdmitted = "admitted"
	// admitUnauthenticated and admitForbidden are the Authorizer's
	// connectip.ErrUnauthenticated and connectip.ErrForbidden.
	admitUnauthenticated = "unauthenticated"
	admitForbidden       = "forbidden"
	// admitAuthorizerFailed is any other Authorizer error, its timeout
	// included.
	admitAuthorizerFailed = "authorizer_failed"
	// admitInvalidGrant is a grant that fails validation.
	admitInvalidGrant = "invalid_grant"
	// admitNoLease is an instance that holds no lease.
	admitNoLease = "no_lease"
	// admitShuttingDown is an adapter in Shutdown.
	admitShuttingDown = "shutting_down"
	// admitBusy is a connector with another request being admitted.
	admitBusy = "busy"
	// admitCancelled is a request whose client went away during
	// preparation. It counts under neither attachment_failed nor
	// route_failed.
	admitCancelled = "cancelled"
	// admitAttachmentFailed is an attachment that was refused, or not
	// programmed and served within the preparation time.
	admitAttachmentFailed = "attachment_failed"
	// admitRouteRefused is a route claim core refuses for good.
	admitRouteRefused = "route_refused"
	// admitRouteFailed is a route claim not accepted within the preparation
	// time, or lost to a lease or attachment change while it was made.
	admitRouteFailed = "route_failed"
	// admitReplaceFailed is a connector's earlier request that did not stop
	// in time.
	admitReplaceFailed = "replace_failed"
	// admitChanged is the lease, attachment or route changing, a revocation,
	// or Shutdown, between preparation and registration.
	admitChanged = "changed"
)

// Request end reasons, the reason label of requestEnds. endReason maps the
// reason a request ended with to one of them.
const (
	endClosed       = "closed"
	endGrantExpired = "grant_expired"
	endGrantRevoked = "grant_revoked"
	endGrantChanged = "grant_changed"
	endGrantInvalid = "grant_invalid"
	endReplaced     = "replaced"
	endRevoked      = "revoked"
	endLeaseLost    = "lease_lost"
	// endRouteMoved is the connector's route claimed again for another
	// attachment or lease epoch.
	endRouteMoved    = "route_moved"
	endRouteReleased = "route_released"
	// endRouteRevoked is core no longer accepting the route's claim.
	endRouteRevoked = "route_revoked"
	// endAttachmentGone is the attachment deleted or replaced.
	endAttachmentGone = "attachment_gone"
	// endAttachmentDraining is the attachment draining for maintenance.
	endAttachmentDraining = "attachment_draining"
	// endAttachmentUnprogrammed is the attachment no longer programmed, or
	// programmed on other host state.
	endAttachmentUnprogrammed = "attachment_unprogrammed"
	// endAttachmentClosed is the adapter closing the device: Ready not
	// reported, idle, or Shutdown.
	endAttachmentClosed = "attachment_closed"
	endOther            = "other"
)

// Reasons a request ends with, as its log line gives them. endReasons maps
// each to its label.
const (
	reasonClosed                 = "closed"
	reasonGrantExpired           = "grant expired"
	reasonGrantRevoked           = "grant revoked"
	reasonGrantChanged           = "grant changed"
	reasonGrantInvalid           = "refreshed grant is invalid"
	reasonReplaced               = "replaced"
	reasonRevoked                = "revoked"
	reasonLeaseLost              = "lease lost"
	reasonRouteMoved             = "route claimed again"
	reasonRouteReleased          = "route released"
	reasonRouteRevoked           = "route no longer accepted"
	reasonAttachmentDeleted      = "attachment deleted"
	reasonAttachmentReplaced     = "attachment replaced"
	reasonAttachmentDraining     = "attachment draining"
	reasonAttachmentUnprogrammed = "attachment no longer programmed"
	reasonAttachmentReprogrammed = "attachment reprogrammed"
	reasonNotReady               = "Ready not reported"
	reasonIdle                   = "idle"
	reasonShuttingDown           = "shutting down"
)

// endReasons maps every reason the adapter ends a request with to its
// label. A reason not listed is counted as other.
var endReasons = map[string]string{
	reasonClosed:                 endClosed,
	reasonGrantExpired:           endGrantExpired,
	reasonGrantRevoked:           endGrantRevoked,
	reasonGrantChanged:           endGrantChanged,
	reasonGrantInvalid:           endGrantInvalid,
	reasonReplaced:               endReplaced,
	reasonRevoked:                endRevoked,
	reasonLeaseLost:              endLeaseLost,
	reasonRouteMoved:             endRouteMoved,
	reasonRouteReleased:          endRouteReleased,
	reasonRouteRevoked:           endRouteRevoked,
	reasonAttachmentDeleted:      endAttachmentGone,
	reasonAttachmentReplaced:     endAttachmentGone,
	reasonAttachmentDraining:     endAttachmentDraining,
	reasonAttachmentUnprogrammed: endAttachmentUnprogrammed,
	reasonAttachmentReprogrammed: endAttachmentUnprogrammed,
	reasonNotReady:               endAttachmentClosed,
	reasonIdle:                   endAttachmentClosed,
	reasonShuttingDown:           endAttachmentClosed,
}

func endReason(reason string) string {
	if r, ok := endReasons[reason]; ok {
		return r
	}
	return endOther
}

// Route claim outcomes, the outcome label of routeClaims.
const (
	claimAccepted = "accepted"
	claimRefused  = "refused"
	claimFailed   = "failed"
	// claimRevoked is an accepted claim core no longer accepts.
	claimRevoked = "revoked"
)

// Request states, the state label of galactic_masque_requests. Each open
// request is in exactly one.
const (
	// stateAdmitted is a registered request whose attachment no longer
	// serves the generation it was admitted on, or whose route claim is no
	// longer accepted.
	stateAdmitted = "admitted"
	// stateProgrammed is a request whose attachment serves its device and
	// whose route claim core accepts, but which does not forward: its
	// packet path is not open, or its grant, lease or request ended.
	stateProgrammed = "programmed"
	// stateForwarding is a programmed request with its packet path open
	// that may carry a packet now.
	stateForwarding = "forwarding"
)

const labelState = "state"

// Every label is an enum, never a connector, principal, VPC, prefix,
// service or attachment, so the series count does not grow with the
// connectors served. Those identities go to the adapter's log lines.
var (
	admissionsTotal = metrics.NewCounterVec(prometheus.CounterOpts{
		Name: "galactic_masque_admissions_total",
		Help: "MASQUE provider admissions, by outcome.",
	}, []string{labels.Outcome})
	requestEnds = metrics.NewCounterVec(prometheus.CounterOpts{
		Name: "galactic_masque_request_ends_total",
		Help: "Admitted MASQUE requests that stopped forwarding, by reason.",
	}, []string{labels.Reason})
	routeClaims = metrics.NewCounterVec(prometheus.CounterOpts{
		Name: "galactic_masque_route_claims_total",
		Help: "Connector /96 route claims, by outcome: accepted, refused, failed, or revoked once accepted.",
	}, []string{labels.Outcome})
	deviceDrops = metrics.NewCounter(prometheus.CounterOpts{
		Name: "galactic_masque_device_drops_total",
		Help: "Client packets dropped because the attachment's packet device was full.",
	})
	leaseLosses = metrics.NewCounter(prometheus.CounterOpts{
		Name: "galactic_masque_lease_losses_total",
		Help: "Times the provider instance lost its lease, ending every request.",
	})
)

var (
	requestsDesc = prometheus.NewDesc("galactic_masque_requests",
		"Open MASQUE requests, by state: admitted, programmed or forwarding.", []string{labelState}, nil)
	leaseHeldDesc = prometheus.NewDesc("galactic_masque_lease_held",
		"1 while the provider instance holds a valid lease, otherwise 0.", nil, nil)
)

// live holds the started adapters the collector reads; a process runs one,
// tests several.
var live = struct {
	sync.Mutex
	adapters map[*Adapter]struct{}
}{adapters: map[*Adapter]struct{}{}}

func init() { metrics.MustRegister(collector{}) }

func track(a *Adapter) {
	live.Lock()
	defer live.Unlock()
	live.adapters[a] = struct{}{}
}

func untrack(a *Adapter) {
	live.Lock()
	defer live.Unlock()
	delete(live.adapters, a)
}

// collector reports request states and lease possession at scrape time.
type collector struct{}

func (collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- requestsDesc
	ch <- leaseHeldDesc
}

func (collector) Collect(ch chan<- prometheus.Metric) {
	counts := map[string]int{stateAdmitted: 0, stateProgrammed: 0, stateForwarding: 0}
	held := 0
	live.Lock()
	for a := range live.adapters {
		if _, ok := a.heldLease(); ok {
			held++
		}
		a.mu.Lock()
		for _, s := range a.sessions {
			counts[s.state()]++
		}
		a.mu.Unlock()
	}
	live.Unlock()
	for state, n := range counts {
		ch <- prometheus.MustNewConstMetric(requestsDesc, prometheus.GaugeValue, float64(n), state)
	}
	ch <- prometheus.MustNewConstMetric(leaseHeldDesc, prometheus.GaugeValue, float64(min(held, 1)))
}

// state returns the request's state. The caller holds Adapter.mu.
func (s *session) state() string {
	if !s.att.serving(s.attGen) || !s.rt.active || s.rt.gen != s.rtGen {
		return stateAdmitted
	}
	if p := s.pkt.Load(); p == nil || p == closedPacketPath || !s.forwarding() {
		return stateProgrammed
	}
	return stateForwarding
}
