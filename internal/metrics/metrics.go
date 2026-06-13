// Package metrics defines Prometheus metrics for galactic-agent.
package metrics

import "github.com/prometheus/client_golang/prometheus"

const namespace = "galactic_agent"

var (
	ReconcileTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "reconcile_total",
		Help:      "Total number of reconcile iterations per controller.",
	}, []string{"controller"})

	ReconcileErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "reconcile_errors_total",
		Help:      "Total number of reconcile errors per controller.",
	}, []string{"controller"})

	ProviderReady = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "provider_ready",
		Help:      "1 when a backend provider is ready, 0 otherwise.",
	}, []string{"provider", "daemon"})

	BackendApplyDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: namespace,
		Name:      "backend_apply_duration_seconds",
		Help:      "Time spent applying desired state to a backend.",
		Buckets:   prometheus.DefBuckets,
	}, []string{"backend"})

	ConfigReloadTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "config_reload_total",
		Help:      "Total number of FRR config reloads triggered.",
	}, []string{"backend"})
)

// MustRegister registers all metrics with the default registry.
func MustRegister() {
	prometheus.MustRegister(
		ReconcileTotal,
		ReconcileErrors,
		ProviderReady,
		BackendApplyDuration,
		ConfigReloadTotal,
	)
}
