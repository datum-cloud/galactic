package controller

import (
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

var (
	// sessionStateGauge tracks the current BGP session state per BGPSession resource.
	// One time series per (session, state) pair; value is 1 for the active state.
	sessionStateGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "bgp_session_state",
			Help: "Current BGP session state per BGPSession resource (1 = active state, 0 = inactive)",
		},
		[]string{"session", "state"},
	)

	// receivedPrefixesGauge tracks the number of prefixes received per BGPSession resource.
	receivedPrefixesGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "bgp_received_prefixes_total",
			Help: "Prefixes received from a BGP session",
		},
		[]string{"session"},
	)

	// sessionFlapsCounter counts the number of times a session left Established state.
	sessionFlapsCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "bgp_session_flaps_total",
			Help: "Number of times a BGP session left Established state",
		},
		[]string{"session"},
	)

	// all known session states, used to zero out inactive states.
	knownStates = []string{"Unknown", "Idle", "Connect", "Active", "OpenSent", "OpenConfirm", "Established"}

	// advertisedPrefixesGauge tracks the number of prefixes advertised per BGPAdvertisement.
	advertisedPrefixesGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "bgp_advertised_prefixes_total",
			Help: "Number of prefixes advertised from a BGPAdvertisement resource",
		},
		[]string{"advertisement"},
	)

	// routePoliciesAppliedGauge tracks whether a BGPRoutePolicy is successfully applied.
	routePoliciesAppliedGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "bgp_route_policies_applied",
			Help: "1 if the BGPRoutePolicy is applied to GoBGP, 0 otherwise",
		},
		[]string{"policy"},
	)
)

func init() {
	// Register metrics with the controller-runtime metrics registry so they
	// are exposed on the manager's /metrics endpoint.
	metrics.Registry.MustRegister(
		sessionStateGauge,
		receivedPrefixesGauge,
		sessionFlapsCounter,
		advertisedPrefixesGauge,
		routePoliciesAppliedGauge,
	)
}

// RecordSessionState sets the session state gauge for a BGPSession resource.
// It zeroes out all other state labels so the gauge accurately reflects the current state.
func RecordSessionState(sessionName, state string) {
	for _, s := range knownStates {
		v := 0.0
		if s == state {
			v = 1.0
		}
		sessionStateGauge.WithLabelValues(sessionName, s).Set(v)
	}
}

// RecordReceivedPrefixes sets the received-prefixes gauge for a BGPSession resource.
func RecordReceivedPrefixes(sessionName string, count int64) {
	receivedPrefixesGauge.WithLabelValues(sessionName).Set(float64(count))
}

// RecordSessionFlap increments the flap counter for a BGPSession resource.
func RecordSessionFlap(sessionName string) {
	sessionFlapsCounter.WithLabelValues(sessionName).Inc()
}

// RecordAdvertisedPrefixes sets the advertised-prefixes gauge for a BGPAdvertisement.
func RecordAdvertisedPrefixes(advertisementName string, count int) {
	advertisedPrefixesGauge.WithLabelValues(advertisementName).Set(float64(count))
}

// RecordRoutePolicyApplied sets the route-policy-applied gauge to 1 (applied) or 0 (not applied).
func RecordRoutePolicyApplied(policyName string, applied bool) {
	v := 0.0
	if applied {
		v = 1.0
	}
	routePoliciesAppliedGauge.WithLabelValues(policyName).Set(v)
}
