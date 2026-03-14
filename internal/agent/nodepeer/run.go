package nodepeer

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

	bgpv1alpha1 "go.datum.net/galactic/pkg/apis/bgp/v1alpha1"
)

// Options holds runtime configuration for the node auto-peer operator.
type Options struct {
	// NodeName is the Kubernetes node name this agent is running on.
	NodeName string

	// LocalNodeIPv6 is kept for backward compatibility; BGPEndpoint resources
	// use the reconciled node's own IPv6 address, not a local override.
	LocalNodeIPv6 string
}

var nodepeerScheme = runtime.NewScheme()

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(nodepeerScheme))
	utilruntime.Must(corev1.AddToScheme(nodepeerScheme))
	utilruntime.Must(bgpv1alpha1.AddToScheme(nodepeerScheme))
}

// Run starts the node auto-peer operator manager and blocks until ctx is cancelled.
func Run(ctx context.Context, opts Options) error {
	restCfg, err := config.GetConfig()
	if err != nil {
		return fmt.Errorf("get k8s config: %w", err)
	}

	mgr, err := ctrl.NewManager(restCfg, ctrl.Options{
		Scheme:                 nodepeerScheme,
		HealthProbeBindAddress: ":8083",
		Metrics:                metricsserver.Options{BindAddress: ":8085"},
	})
	if err != nil {
		return fmt.Errorf("new manager: %w", err)
	}

	op := &Operator{
		Client:        mgr.GetClient(),
		LocalNodeName: opts.NodeName,
		LocalNodeIPv6: opts.LocalNodeIPv6,
	}
	if err := op.SetupWithManager(mgr); err != nil {
		return fmt.Errorf("setup node auto-peer operator: %w", err)
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		return fmt.Errorf("add healthz check: %w", err)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		return fmt.Errorf("add readyz check: %w", err)
	}

	log.Printf("nodepeer: starting node auto-peer operator for node %s", opts.NodeName)
	return mgr.Start(ctx)
}
