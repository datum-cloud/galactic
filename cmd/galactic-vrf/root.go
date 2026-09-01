// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"go.datum.net/galactic/internal/config"
	"go.datum.net/galactic/internal/ingresssidecar"
	"go.datum.net/galactic/internal/metadata"
	bgpv1alpha1 "go.datum.net/network/api/v1alpha1"
)

const (
	appName = "galactic-vrf"

	appDesc = `Galactic ingress sidecar: per-pod VPC backend VRF/SRv6 route lifecycle

 Find more information at: https://www.datum.net/docs`
)

// runCmd contains the application startup logic: it registers
// internal/ingresssidecar's Reconciler against a cluster-scoped
// EndpointSlice watch, then seeds Store from the live API state and runs
// its startup inventory and periodic sweep. There is no BGP runtime here —
// bgpv1alpha1 is registered on the scheme solely so the optional gateway
// publisher below can read BGPRouter/BGPVRFInstance and write
// BGPAdvertisement CRDs; see internal/config.VRFConfig's own doc comment
// for why cfg.NodeName, unlike everything else this binary reads, has no
// default and leaves that one feature off when unset.
func runCmd(cfg *config.VRFConfig) error {
	ctrl.SetLogger(zap.New(zap.UseDevMode(true)))

	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(bgpv1alpha1.AddToScheme(scheme))

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		HealthProbeBindAddress: "0",
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

	metrics := ingresssidecar.NewMetrics()
	metrics.MustRegister(ctrlmetrics.Registry)

	backend := ingresssidecar.NewKernelBackend()
	store := ingresssidecar.NewStore(backend, cfg.TeardownGracePeriod, metrics)

	// Return-path gateway-advertisement publishing (docs/plans/855-return-
	// path-gateway-advertisement.md) is opt-in on cfg.NodeName alone: most
	// deployments of this sidecar don't set it yet, and leaving it unset
	// here is exactly the no-op SetGatewayPublisher's own doc comment
	// describes -- Store behaves identically to before this feature
	// existed. mgr.GetClient() (the cached client) is fine for this: unlike
	// the reconcile hot path, publishing only runs once per VRF's lifetime.
	if cfg.NodeName != "" {
		store.SetGatewayPublisher(
			ingresssidecar.NewK8sGatewayPublisher(mgr.GetClient(), cfg.NodeName, cfg.Namespace),
			ingresssidecar.NetlinkGatewayAddressResolver{},
		)
	} else {
		log.Printf("no node name configured (%s / legacy NODE_NAME) -- "+
			"return-path gateway advertisement publishing is disabled", config.EnvVRFNodeName)
	}

	if err := (&ingresssidecar.Reconciler{Store: store}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("setup EndpointSlice controller: %w", err)
	}

	// Startup seed + inventory + periodic sweep. Every EndpointSlice that
	// exists at boot must be visible to Store *before* Inventory or Sweep
	// ever run, or a live VPC/pod could be misjudged as orphaned -- see
	// ingresssidecar.SeedFromAPI's own doc comment for why that can no
	// longer be mgr.GetCache().WaitForCacheSync's job: a synced cache only
	// guarantees the informer's initial List landed in the cache, not that
	// the controller's own Reconcile has drained the workqueue that same
	// List fed, so on a busy node at boot the two could race. SeedFromAPI
	// uses mgr.GetAPIReader(), the manager's uncached reader, so it
	// doesn't depend on cache/workqueue timing at all. Mirrors
	// cmd/galactic-router's own GC-ticker startup goroutine.
	go func() {
		if err := ingresssidecar.SeedFromAPI(ctx, mgr.GetAPIReader(), store); err != nil {
			log.Printf("startup seed: %v", err)
			return
		}
		if err := store.Inventory(ctx, time.Now()); err != nil {
			log.Printf("startup inventory: %v", err)
		}
		ingresssidecar.RunSweeper(ctx, store, cfg.SweepInterval)
	}()

	if err := mgr.Start(ctx); err != nil {
		return fmt.Errorf("manager exited: %w", err)
	}

	// mgr.Start only returns nil once ctx is Done (signal-triggered
	// shutdown -- there's no other source of cancellation here, unlike
	// cmd/galactic-router/cmd/galactic-gateway's health-server-failure
	// case). No proactive VRF/route teardown on exit: §6 of the plan
	// leans toward leaving kernel state for the next instance to
	// reconcile from scratch, since a live Envoy container next to a
	// dying sidecar mid-rollout would otherwise blackhole in-flight
	// connections.
	return nil
}

// newRootCommand builds the root cobra command with all flags and the
// application startup logic.
func newRootCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   appName,
		Short: strings.Split(appDesc, "\n")[0],
		Long:  appDesc,
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
	cmd.Flags().StringP("node-name", "", "",
		"This node's name, as it appears in a BGPRouter's spec.targetRef.name -- "+
			"enables return-path gateway advertisement publishing when set (env "+config.EnvVRFNodeName+" or legacy NODE_NAME)")
	cmd.Flags().StringP("namespace", "", config.DefaultNamespace,
		"Namespace to read BGPRouter/BGPVRFInstance and write BGPAdvertisement CRDs in")
	cmd.Flags().Bool("build-info", false, "Print build information and exit")
	cmd.Flags().BoolP("version", "V", false, "Print version and exit")
	return cmd
}
