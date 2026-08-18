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
)

const (
	appName = "galactic-vrf"

	appDesc = `Galactic ingress sidecar: per-pod VPC backend VRF/SRv6 route lifecycle

 Find more information at: https://www.datum.net/docs`
)

// runCmd contains the application startup logic: it registers
// internal/ingresssidecar's Reconciler against a cluster-scoped
// EndpointSlice watch, then runs its startup inventory and periodic sweep
// once the manager's caches have synced. There is no BGP runtime, CRD
// scheme beyond clientgoscheme's built-in discoveryv1 registration, or
// per-node identity of any kind here — see internal/config.VRFConfig's own
// doc comment for why.
func runCmd(cfg *config.VRFConfig) error {
	ctrl.SetLogger(zap.New(zap.UseDevMode(true)))

	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))

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

	if err := (&ingresssidecar.Reconciler{Store: store}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("setup EndpointSlice controller: %w", err)
	}

	// Startup inventory + periodic sweep, gated on the manager's caches
	// having synced -- see Store.Inventory's own doc comment for why: every
	// EndpointSlice that exists at boot must have already gone through its
	// own initial Reconcile (and therefore SetDesired) before Inventory or
	// Sweep ever run, or a live VPC/pod could be misjudged as orphaned.
	// Mirrors cmd/galactic-router's own GC-ticker startup goroutine.
	go func() {
		if !mgr.GetCache().WaitForCacheSync(ctx) {
			log.Printf("startup inventory: cache sync failed, skipping")
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
	cmd.Flags().Bool("build-info", false, "Print build information and exit")
	cmd.Flags().BoolP("version", "V", false, "Print version and exit")
	return cmd
}
