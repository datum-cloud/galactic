// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package connectip

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"go.miloapis.com/instrumentation/labels"
	"go.miloapis.com/instrumentation/metrics"
)

// Transports, the transport label of every server metric. A request over
// any other HTTP version is counted as http1.
const (
	transportH3    = "h3"
	transportH2    = "h2"
	transportHTTP1 = "http1"
)

// transportOf returns the transport label of r.
func transportOf(r *http.Request) string {
	switch r.ProtoMajor {
	case 3:
		return transportH3
	case 2:
		return transportH2
	}
	return transportHTTP1
}

// Request outcomes, the outcome label of requestsTotal. Every rejection
// maps to one of them, so a 503 from a full server is told apart from one
// from an unavailable authority.
const (
	// outcomeAccepted is a request answered with 2xx and proxied.
	outcomeAccepted = "accepted"
	// outcomeBadRequest is a request that is not a valid CONNECT-IP request
	// for this server: wrong method, protocol, authority, path, headers or
	// HTTP version.
	outcomeBadRequest = "bad_request"
	// outcomeUnauthenticated is a missing credential or one Admission does
	// not recognize.
	outcomeUnauthenticated = "unauthenticated"
	// outcomeForbidden is a credential Admission denies the requested VPC.
	outcomeForbidden = "forbidden"
	// outcomeLimited is a request over a session or admission cap.
	outcomeLimited = "limited"
	// outcomeUnavailable is a closing server, or Admission failing for any
	// reason but authentication and authorization.
	outcomeUnavailable = "unavailable"
	// outcomeInvalidGrant is an admitted request whose lease is missing or
	// fails the grant checks.
	outcomeInvalidGrant = "invalid_grant"
	// outcomeExpired is an admission that ended before the tunnel opened.
	outcomeExpired = "expired"
	// outcomeMTU is a path that cannot carry MinInnerMTU.
	outcomeMTU = "mtu"
	// outcomeBackendUnavailable is a PacketBackend that would not open the
	// request's session.
	outcomeBackendUnavailable = "backend_unavailable"
	// outcomeAcceptFailed is a request whose 2xx answer could not be sent.
	outcomeAcceptFailed = "accept_failed"
)

// Connection rejection reasons, the reason label of connsRejected.
const (
	connReasonTotal     = "max_connections"
	connReasonPerSource = "max_connections_per_source"
)

// Tunnel end causes, the cause label of tunnelEnds. When several apply, the
// first in this list wins.
const (
	// causeLeaseEnded is the admission lease ending: expiry, revocation,
	// replacement or the adapter stopping forwarding.
	causeLeaseEnded = "lease_ended"
	// causeServerClosed is Server.Close.
	causeServerClosed = "server_closed"
	// causePathMTU is the path toward the client no longer carrying
	// MinInnerMTU.
	causePathMTU = "path_mtu"
	// causeSlowClient is a write toward the client blocked for
	// deliveryTimeout.
	causeSlowClient = "slow_client"
	// causeBackendError is the backend session failing a read or write.
	causeBackendError = "backend_error"
	// causeSetupFailed is the address assignment or route advertisement
	// failing after the tunnel was accepted.
	causeSetupFailed = "setup_failed"
	// causeClientClosed is the client, or its connection, ending the
	// request.
	causeClientClosed = "client_closed"
)

const labelTransport, labelDirection, labelCause = "transport", "direction", "cause"

// Every label is a transport, direction or one of the enums above, never a
// connector, principal, VPC, prefix, attachment or address, so the series
// count does not grow with the connectors served. Those identities go to the
// session's log lines.
var (
	requestsTotal = metrics.NewCounterVec(prometheus.CounterOpts{
		Name: "galactic_connectip_requests_total",
		Help: "CONNECT-IP requests answered, by transport and outcome.",
	}, []string{labelTransport, labels.Outcome})
	admissionSeconds = metrics.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "galactic_connectip_admission_duration_seconds",
		Help:    "Time spent in Admission.Admit, by transport.",
		Buckets: []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10, 30},
	}, []string{labelTransport})
	openConnections = metrics.NewGaugeVec(prometheus.GaugeOpts{
		Name: "galactic_connectip_connections",
		Help: "Open QUIC (h3) and TCP (h2) connections, by transport.",
	}, []string{labelTransport})
	connsRejected = metrics.NewCounterVec(prometheus.CounterOpts{
		Name: "galactic_connectip_connections_rejected_total",
		Help: "Connections closed for exceeding a connection cap, by transport and reason.",
	}, []string{labelTransport, labels.Reason})
	admissionsInProgress = metrics.NewGaugeVec(prometheus.GaugeOpts{
		Name: "galactic_connectip_admissions",
		Help: "Requests waiting on Admission.Admit, by transport.",
	}, []string{labelTransport})
	openTunnels = metrics.NewGaugeVec(prometheus.GaugeOpts{
		Name: "galactic_connectip_tunnels",
		Help: "Accepted CONNECT-IP requests proxying packets, by transport.",
	}, []string{labelTransport})
	tunnelEnds = metrics.NewCounterVec(prometheus.CounterOpts{
		Name: "galactic_connectip_tunnel_ends_total",
		Help: "Accepted CONNECT-IP requests that ended, by transport and cause.",
	}, []string{labelTransport, labelCause})
	packetsForwarded = metrics.NewCounterVec(prometheus.CounterOpts{
		Name: "galactic_connectip_packets_total",
		Help: "Packets the CONNECT-IP proxy forwarded, by transport and direction.",
	}, []string{labelTransport, labelDirection})
	bytesForwarded = metrics.NewCounterVec(prometheus.CounterOpts{
		Name: "galactic_connectip_bytes_total",
		Help: "Bytes of IP packets the CONNECT-IP proxy forwarded, by transport and direction.",
	}, []string{labelTransport, labelDirection})
)

// forwardCounters are one session's packet and byte counters, resolved once
// so the packet path does no label lookups.
type forwardCounters struct {
	toVPCPackets, toVPCBytes, toClientPackets, toClientBytes prometheus.Counter
}

func newForwardCounters(transport string) forwardCounters {
	return forwardCounters{
		toVPCPackets:    packetsForwarded.WithLabelValues(transport, toVPC),
		toVPCBytes:      bytesForwarded.WithLabelValues(transport, toVPC),
		toClientPackets: packetsForwarded.WithLabelValues(transport, toClient),
		toClientBytes:   bytesForwarded.WithLabelValues(transport, toClient),
	}
}

func (f forwardCounters) toVPC(n int) {
	f.toVPCPackets.Inc()
	f.toVPCBytes.Add(float64(n))
}

func (f forwardCounters) toClient(n int) {
	f.toClientPackets.Inc()
	f.toClientBytes.Add(float64(n))
}
