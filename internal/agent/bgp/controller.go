package bgp

import (
	"context"
	"fmt"
	"log"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/kubernetes"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	bgpv1alpha1 "go.datum.net/galactic/pkg/apis/bgp/v1alpha1"
)

// ControllerOptions holds runtime configuration for the BGP CRD controller.
type ControllerOptions struct {
	// NodeName is the Kubernetes node name this agent is running on (from NODE_NAME env).
	NodeName string

	// SRv6Net is the node's SRv6 /48 prefix (from SRV6_NET env var).
	// The route watcher skips routes matching this prefix.
	SRv6Net string
}

// scheme holds the runtime.Scheme for all types used by the manager.
var scheme = runtime.NewScheme()

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(corev1.AddToScheme(scheme))
	utilruntime.Must(bgpv1alpha1.AddToScheme(scheme))
}

// Run starts the BGP CRD controller and blocks until ctx is cancelled.
// It connects to GoBGP, starts the controller-runtime manager with the
// BGPConfiguration and BGPSession reconcilers, and starts supporting goroutines
// for health watching, status polling, and route watching.
func Run(ctx context.Context, opts ControllerOptions) error {
	// Connect to GoBGP first — reconcilers depend on this connection.
	gobgp := NewGoBGPClient()
	if err := gobgp.Connect(ctx); err != nil {
		return fmt.Errorf("connect GoBGP: %w", err)
	}
	log.Printf("bgp/controller: GoBGP connected")

	// Build controller-runtime manager.
	restCfg, err := config.GetConfig()
	if err != nil {
		return fmt.Errorf("get k8s config: %w", err)
	}

	mgr, err := ctrl.NewManager(restCfg, ctrl.Options{
		Scheme:                 scheme,
		HealthProbeBindAddress: ":8082",
		Metrics:                metricsserver.Options{BindAddress: ":8084"},
	})
	if err != nil {
		return fmt.Errorf("new manager: %w", err)
	}

	// Build a typed k8s client for helpers that need it (nodeutil, config reconciler).
	k8sClient, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		return fmt.Errorf("create k8s client: %w", err)
	}

	// Register BGPConfiguration reconciler.
	if err := (&ConfigReconciler{
		Client:    mgr.GetClient(),
		GoBGP:     gobgp,
		K8sClient: k8sClient,
		NodeName:  opts.NodeName,
		SRv6Net:   opts.SRv6Net,
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("setup BGPConfiguration reconciler: %w", err)
	}

	// Register BGPSession reconciler.
	// Each node only reconciles sessions where its own endpoint is local.
	if err := (&SessionReconciler{
		Client:   mgr.GetClient(),
		GoBGP:    gobgp,
		NodeName: opts.NodeName,
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("setup BGPSession reconciler: %w", err)
	}

	// Register BGPPeeringPolicy reconciler.
	// Creates BGPSession resources for every matching endpoint pair.
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
	go gobgp.WatchHealth(ctx, mgr.GetClient(), opts.SRv6Net)
	go RunStatusPoller(ctx, mgr.GetClient(), gobgp, opts.NodeName)
	go RunRouteWatcher(ctx, gobgp, opts.SRv6Net)

	log.Printf("bgp/controller: starting manager")
	return mgr.Start(ctx)
}
