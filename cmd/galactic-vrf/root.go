// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	cloudv1alpha1 "go.datum.net/galactic/api/cloud/v1alpha1"
	bgpv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	"go.datum.net/galactic/internal/config"
	"go.datum.net/galactic/internal/ingresssidecar"
	"go.datum.net/galactic/internal/logging"
	"go.datum.net/galactic/internal/metadata"
	"go.datum.net/galactic/pkg/workerclient"
)

const (
	appName = "galactic-vrf"

	appDesc = `Galactic ingress sidecar: per-pod VPC backend VRF/SRv6 route lifecycle

 Find more information at: https://www.datum.net/docs`
)

// sidecarMetrics are the sidecar's metrics, all on the instrumentation
// library's registry.
type sidecarMetrics struct {
	store       *ingresssidecar.Metrics
	lifecycle   *ingresssidecar.LifecycleMetrics
	convergence *ingresssidecar.ConvergenceMetrics
	inputs      *ingresssidecar.InputMetrics
	datapath    *ingresssidecar.DatapathMetrics
	nodeSource  *ingresssidecar.NodeSourceMetrics
	claims      *ingresssidecar.ClaimMetrics
}

// newSidecarMetrics creates every metric the sidecar serves, configured from
// cfg, and registers the collectors among them. runCmd calls it once.
func newSidecarMetrics(cfg *config.VRFConfig) sidecarMetrics {
	m := sidecarMetrics{
		store:       ingresssidecar.NewMetrics(),
		lifecycle:   ingresssidecar.NewLifecycleMetrics(cfg.SweepInterval, cfg.TeardownGracePeriod),
		convergence: ingresssidecar.NewConvergenceMetrics(),
		inputs:      ingresssidecar.NewInputMetrics(),
		datapath:    ingresssidecar.NewDatapathMetrics(),
		nodeSource:  ingresssidecar.NewNodeSourceMetrics(),
		claims:      ingresssidecar.NewClaimMetrics(),
	}
	m.lifecycle.MustRegister()
	m.datapath.MustRegister()
	m.nodeSource.MustRegister()
	return m
}

// runCmd is the application startup: it registers the ingress sidecar's
// reconciler against a cluster-scoped EndpointSlice watch, then seeds the store
// from live API state and runs its startup inventory and periodic sweep. Beside
// it, the Worker claim runner holds one socket claim per VPC with Galactic
// Worker and configures the routed link Worker gives each claim.
func runCmd(cfg *config.VRFConfig) error {
	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(bgpv1alpha1.AddToScheme(scheme))
	utilruntime.Must(cloudv1alpha1.AddToScheme(scheme))

	selector, err := labels.Parse(cfg.AttachmentSelector)
	if err != nil {
		// Validate already parsed it.
		return fmt.Errorf("parse attachment selector: %w", err)
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		HealthProbeBindAddress: fmt.Sprintf(":%d", cfg.HealthPort),
		Metrics: metricsserver.Options{
			BindAddress: fmt.Sprintf(":%d", cfg.MetricsPort),
		},
	})
	if err != nil {
		return fmt.Errorf("create manager: %w", err)
	}

	ctx, cancel := context.WithCancel(ctrl.SetupSignalHandler())
	defer cancel()

	// Pre-flight RBAC check.
	checkWatchPermissions(mgr)

	m := newSidecarMetrics(cfg)

	backend := ingresssidecar.NewKernelBackend()
	store := ingresssidecar.NewStore(backend, cfg.TeardownGracePeriod, m.store)
	store.SetConvergenceMetrics(m.convergence)
	store.SetInputMetrics(m.inputs)
	store.SetDatapathMetrics(m.datapath)
	store.SetNodeSourceMetrics(m.nodeSource)

	// This node's own SRv6 SID, the source usid_egress stamps into every
	// outer header it pushes for a backend on another node. It is read from
	// this node's BGPRouter: nothing visible inside Envoy's pod namespace,
	// which is where this sidecar always runs, identifies the node's SID.
	ingresssidecar.SetNodeSourceAddressResolver(
		ingresssidecar.NewK8sNodeSourceAddressResolver(mgr.GetClient(), cfg.NodeName, cfg.Namespace),
	)

	if err := (&ingresssidecar.Reconciler{Store: store}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("setup EndpointSlice controller: %w", err)
	}

	if err := ingresssidecar.RegisterClaimIndexes(ctx, mgr.GetFieldIndexer()); err != nil {
		return fmt.Errorf("index VPCAttachments: %w", err)
	}
	claimLog := slog.Default().With("component", "worker-claims")
	inputs := &ingresssidecar.KubeClaimInputs{Reader: mgr.GetClient(), Namespace: cfg.PodNamespace,
		Selector: selector, Node: cfg.NodeName, Log: claimLog}
	podLink := ingresssidecar.NewKernelPodLink()
	runner := &ingresssidecar.ClaimsRunner{
		Dial: func(ctx context.Context) (*workerclient.Client, error) {
			return workerclient.Dial(ctx, workerclient.Options{SocketPath: cfg.WorkerSocket,
				TokenFile: cfg.WorkerTokenFile})
		},
		Build: func(c ingresssidecar.ClaimClient) *ingresssidecar.Claims {
			return ingresssidecar.NewClaims(c, inputs, podLink, cfg.NodeName, m.claims)
		},
		Cache:    mgr.GetCache(),
		Interval: cfg.SweepInterval,
		Metrics:  m.claims,
		Log:      claimLog,
	}
	if err := mgr.Add(runner); err != nil {
		return fmt.Errorf("add the Worker claim runner: %w", err)
	}
	if err := mgr.AddHealthzCheck("ping", healthz.Ping); err != nil {
		return fmt.Errorf("add health check: %w", err)
	}
	if err := mgr.AddReadyzCheck("worker-claims", func(*http.Request) error { return runner.Ready() }); err != nil {
		return fmt.Errorf("add readiness check: %w", err)
	}

	// Startup seed, then inventory, then the periodic sweep. Every
	// EndpointSlice existing at boot must be visible to the store before
	// inventory or a sweep runs, or a live VPC could be misjudged as
	// orphaned.
	//
	// Waiting for the cache to sync is not enough: that guarantees the
	// informer's initial list landed in the cache, not that the
	// controller's own reconciles have drained the workqueue that list
	// fed, so on a busy node at boot the two race. Seeding uses the
	// manager's uncached reader, which depends on neither.
	go ingresssidecar.RunStartup(ctx, mgr.GetAPIReader(), store, cfg.SweepInterval, m.lifecycle)

	if err := mgr.Start(ctx); err != nil {
		return fmt.Errorf("manager exited: %w", err)
	}

	// The manager returns nil only once the context is done, which here means
	// a signal-triggered shutdown; there is no other source of cancellation.
	//
	// No kernel teardown on exit: the pod's state is left for the next
	// container to reconcile from scratch, since a live Envoy container beside
	// a dying sidecar mid-rollout would otherwise blackhole in-flight
	// connections. The claim runner releases the Worker claims, so the
	// proxy's next pod takes the routed links over at once.
	return nil
}

// newRootCommand builds the root cobra command with all flags and the
// application startup logic.
func newRootCommand() *cobra.Command {
	var logOpts logging.Options
	cmd := &cobra.Command{
		Use:   appName,
		Short: strings.Split(appDesc, "\n")[0],
		Long:  appDesc,
		PersistentPreRunE: func(*cobra.Command, []string) error {
			return logOpts.Setup()
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			if ok, _ := cmd.Flags().GetBool("build-info"); ok {
				fmt.Println(metadata.BuildInfo(appName))
				return nil
			}
			if ok, _ := cmd.Flags().GetBool("version"); ok {
				fmt.Printf("galactic-vrf version %s\n", metadata.Version)
				return nil
			}

			cfg := config.NewVRFConfig()
			cfg.BindFlags(cmd.Flags())
			if err := cfg.Validate(); err != nil {
				return err
			}
			return runCmd(cfg)
		},
	}

	cmd.Flags().IntP("metrics-port", "",
		config.DefaultVRFMetricsPort,
		"Metrics listen port")
	cmd.Flags().DurationP("teardown-grace-period", "",
		config.DefaultVRFTeardownGracePeriod,
		"Delay before tearing down a route/VRF after it drops out of desired state")
	cmd.Flags().DurationP("sweep-interval", "",
		config.DefaultVRFSweepInterval,
		"How often to re-check pending teardowns")
	cmd.Flags().Int("health-port", config.DefaultVRFHealthPort,
		"Port serving /healthz and /readyz; ready once every VPC's Worker claim is held and configured")
	cmd.Flags().StringP("node-name", "", "",
		"This node's name, as Worker, the proxy's VPCAttachments and the node's BGPRouter record it "+
			"(env "+config.EnvVRFNodeName+" or legacy NODE_NAME); required")
	cmd.Flags().StringP("namespace", "", config.DefaultNamespace,
		"Namespace of the node's BGPRouter")
	cmd.Flags().String("pod-namespace", "",
		"The proxy pod's namespace, which holds its VPCAttachments (env "+config.EnvVRFPodNamespace+"); required")
	cmd.Flags().String("attachment-selector", "",
		"Label selector of the proxy's own VPCAttachments, one per VPC and node, which NSO creates (env "+
			config.EnvVRFAttachmentSelector+"); required")
	cmd.Flags().String("worker-socket", "",
		"Galactic Worker's unix socket (env "+config.EnvVRFWorkerSocket+")")
	cmd.Flags().String("worker-token-file", "",
		"The pod's projected token for Galactic Worker (env "+config.EnvVRFWorkerTokenFile+")")
	cmd.Flags().Bool("build-info", false, "Print build information and exit")
	cmd.Flags().BoolP("version", "V", false, "Print version and exit")
	logOpts.BindFlags(cmd.PersistentFlags())
	return cmd
}
