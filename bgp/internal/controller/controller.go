package controller

import (
	"context"
	"fmt"
	"log"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	bgpv1alpha1 "go.miloapis.com/bgp/api/v1alpha1"
)

// ControllerOptions holds runtime configuration for the BGP CRD controller.
type ControllerOptions struct {
	// LocalEndpoint is the name of the BGPEndpoint resource representing this instance.
	// Used for router ID resolution, next-hop address lookup, and session ownership.
	LocalEndpoint string

	// SRv6Net is the node's SRv6 prefix (e.g. a /48).
	// The route watcher skips routes matching this prefix to avoid self-routing.
	SRv6Net string

	// GoBGPAddr is the gRPC address of the local GoBGP sidecar (e.g. "127.0.0.1:50051").
	// Defaults to "127.0.0.1:50051" when empty.
	GoBGPAddr string

	// MetricsAddr is the address to serve Prometheus metrics on (e.g. ":8082").
	// Defaults to ":8082" when empty.
	MetricsAddr string

	// HealthAddr is the address to serve health/readiness probes on (e.g. ":8083").
	// Defaults to ":8083" when empty.
	HealthAddr string
}

// scheme holds the runtime.Scheme for all types used by the manager.
var scheme = runtime.NewScheme()

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(corev1.AddToScheme(scheme))
	utilruntime.Must(bgpv1alpha1.AddToScheme(scheme))
}

// Run starts the BGP CRD controller and blocks until ctx is cancelled.
//
// A single controller-runtime manager runs all reconcilers. Every DaemonSet
// pod runs the full set of reconcilers:
//
//   - ConfigReconciler, SessionReconciler, AdvertisementReconciler,
//     RoutePolicyReconciler: node-local — each pod only acts on resources
//     that reference its own LocalEndpoint.
//
//   - PeeringPolicyReconciler: runs on all pods concurrently. Session
//     creation is idempotent (AlreadyExists is handled gracefully) and all
//     pods compute identical desired session sets, making concurrent
//     reconciliation safe without leader election.
func Run(ctx context.Context, opts ControllerOptions, routeWatcher func(ctx context.Context, gobgp *GoBGPClient, srv6Net string)) error {
	if opts.GoBGPAddr == "" {
		opts.GoBGPAddr = gobgpDefaultAddr
	}
	if opts.MetricsAddr == "" {
		opts.MetricsAddr = ":8082"
	}
	if opts.HealthAddr == "" {
		opts.HealthAddr = ":8083"
	}

	// Connect to GoBGP first — reconcilers depend on this connection.
	gobgp := NewGoBGPClientWithAddr(opts.GoBGPAddr)
	if err := gobgp.Connect(ctx); err != nil {
		return fmt.Errorf("connect GoBGP: %w", err)
	}
	log.Printf("bgp/controller: GoBGP connected")

	// Build the REST config.
	restCfg, err := config.GetConfig()
	if err != nil {
		return fmt.Errorf("get k8s config: %w", err)
	}

	mgr, err := ctrl.NewManager(restCfg, ctrl.Options{
		Scheme:                 scheme,
		HealthProbeBindAddress: opts.HealthAddr,
		Metrics:                metricsserver.Options{BindAddress: opts.MetricsAddr},
	})
	if err != nil {
		return fmt.Errorf("new manager: %w", err)
	}

	// BGPConfiguration: reads global config, applies to GoBGP global settings.
	if err := (&ConfigReconciler{
		Client:        mgr.GetClient(),
		GoBGP:         gobgp,
		LocalEndpoint: opts.LocalEndpoint,
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("setup BGPConfiguration reconciler: %w", err)
	}

	// BGPSession: each node configures its own GoBGP peer for sessions that
	// involve its LocalEndpoint.
	if err := (&SessionReconciler{
		Client:        mgr.GetClient(),
		GoBGP:         gobgp,
		LocalEndpoint: opts.LocalEndpoint,
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("setup BGPSession reconciler: %w", err)
	}

	// BGPAdvertisement: each node advertises prefixes into its local GoBGP.
	if err := (&AdvertisementReconciler{
		Client:        mgr.GetClient(),
		GoBGP:         gobgp,
		LocalEndpoint: opts.LocalEndpoint,
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("setup BGPAdvertisement reconciler: %w", err)
	}

	// BGPRoutePolicy: each node programs route policies into its local GoBGP.
	if err := (&RoutePolicyReconciler{
		Client: mgr.GetClient(),
		GoBGP:  gobgp,
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("setup BGPRoutePolicy reconciler: %w", err)
	}

	// BGPPeeringPolicy: creates/deletes BGPSession objects for matching endpoint
	// pairs. All DaemonSet pods run this reconciler; concurrent creates and GC
	// are safe because create uses AlreadyExists handling and all pods compute
	// identical desired session sets from the same policy spec.
	if err := (&PeeringPolicyReconciler{
		Client: mgr.GetClient(),
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("setup BGPPeeringPolicy reconciler: %w", err)
	}

	// Health and readiness probes.
	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		return fmt.Errorf("add healthz check: %w", err)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		return fmt.Errorf("add readyz check: %w", err)
	}

	// Start background goroutines.
	go gobgp.WatchHealth(ctx, mgr.GetClient())
	if routeWatcher != nil {
		go routeWatcher(ctx, gobgp, opts.SRv6Net)
	}

	log.Printf("bgp/controller: starting manager (endpoint=%s)", opts.LocalEndpoint)
	return mgr.Start(ctx)
}
