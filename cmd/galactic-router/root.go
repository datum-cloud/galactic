// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
	grpchealth "google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"go.datum.net/galactic/internal/controller"
	"go.datum.net/galactic/internal/hash"
	"go.datum.net/galactic/internal/metadata"
	"go.datum.net/galactic/internal/reconcile"
	galacticruntime "go.datum.net/galactic/internal/runtime"
	"go.datum.net/galactic/internal/runtime/frr"
	"go.datum.net/galactic/internal/runtime/gobgp"
	bgpv1alpha1 "go.datum.net/network/api/v1alpha1"
)

const (
	appName = "galactic-router"

	appDesc = `Galactic SRv6 data plane router

 Find more information at: https://www.datum.net/docs`
)

// newViper returns a configured viper instance with defaults, env var
// bindings, and automatic fallback for keys not explicitly bound.
func newViper() *viper.Viper {
	v := viper.New()
	v.SetDefault("galactic_router.bgp_listen_port", 179)
	v.SetDefault("galactic_router.metrics_port", 8080)
	v.SetDefault("galactic_router.grpc_health_port", 5000)
	v.SetDefault("galactic_router.gc_namespace", "galactic-system")
	v.SetDefault("galactic_router.gc_interval", 5*time.Minute)

	v.AutomaticEnv()

	// Explicit bindings — AutomaticEnv uses the snake_case key derived from
	// the viper key path (e.g. galactic_router.node_name ->
	// GALACTIC_ROUTER_NODE_NAME), but some keys need explicit mapping.
	//nolint:errcheck // keys are controlled, BindEnv cannot fail here
	v.BindEnv("galactic_router.node_name", "GALACTIC_ROUTER_NODE_NAME")
	//nolint:errcheck
	v.BindEnv("galactic_router.router_mode", "GALACTIC_ROUTER_ROUTER_MODE")
	//nolint:errcheck
	v.BindEnv("galactic_router.bgp_listen_port", "GALACTIC_ROUTER_BGP_LISTEN_PORT")
	//nolint:errcheck
	v.BindEnv("galactic_router.bgp_local_address", "GALACTIC_ROUTER_BGP_LOCAL_ADDRESS")
	//nolint:errcheck
	v.BindEnv("galactic_router.metrics_port", "GALACTIC_ROUTER_METRICS_PORT")
	//nolint:errcheck
	v.BindEnv("galactic_router.grpc_health_port", "GALACTIC_ROUTER_GRPC_HEALTH_PORT")
	//nolint:errcheck
	v.BindEnv("galactic_router.gc_namespace", "GALACTIC_ROUTER_GC_NAMESPACE")
	//nolint:errcheck
	v.BindEnv("galactic_router.gc_interval", "GALACTIC_ROUTER_GC_INTERVAL")
	//nolint:errcheck
	v.BindEnv("reflector", "GALACTIC_ROUTER_REFLECTOR")

	return v
}

const (
	modeTransit = "transit"
	modeFabric  = "fabric"
	modeTenant  = "tenant"
)

// bindFlags registers each viper-configured flag on the command so that
// `viper.BindPFlags` can resolve flag values at runtime.
func bindFlags(cmd *cobra.Command, v *viper.Viper) { //nolint:lll // cobra flag defs are inherently long
	cmd.Flags().StringP("node-name", "n", "", "Kubernetes node name (required)")
	cmd.Flags().StringP("mode", "m", "",
		"Operating mode: 'transit', 'fabric', or 'tenant' (required)")
	cmd.Flags().Bool("reflector", false,
		"Enable route reflector mode (requires --mode=fabric or --mode=tenant)")
	cmd.Flags().IntP("bgp-listen-port", "p", v.GetInt("galactic_router.bgp_listen_port"),
		"BGP listen port")
	cmd.Flags().StringP("bgp-local-address", "",
		v.GetString("galactic_router.bgp_local_address"),
		"Source address for outgoing BGP connections")
	cmd.Flags().IntP("metrics-port", "",
		v.GetInt("galactic_router.metrics_port"),
		"Metrics listen port")
	cmd.Flags().IntP("grpc-health-port", "",
		v.GetInt("galactic_router.grpc_health_port"),
		"gRPC health check port")
	cmd.Flags().StringP("gc-namespace", "",
		v.GetString("galactic_router.gc_namespace"),
		"Namespace for orphaned CRD cleanup")
	cmd.Flags().DurationP("gc-interval", "",
		v.GetDuration("galactic_router.gc_interval"),
		"Cleanup interval")

	if err := v.BindPFlags(cmd.Flags()); err != nil {
		log.Fatalf("bind flags: %v", err)
	}
}

// validateConfig checks that the configuration values are valid.
func validateConfig(v *viper.Viper) error {
	nodeName := v.GetString("galactic_router.node_name")
	mode := v.GetString("galactic_router.router_mode")
	reflector := v.GetBool("reflector")
	bgpListenPort := v.GetInt("galactic_router.bgp_listen_port")
	metricsPort := v.GetInt("galactic_router.metrics_port")
	grpcHealthPort := v.GetInt("galactic_router.grpc_health_port")

	if nodeName == "" {
		return errors.New("--node-name is required")
	}
	if mode == "" {
		return errors.New("--mode is required (valid values: 'transit', 'fabric', 'tenant')")
	}
	if mode != modeTransit && mode != modeFabric && mode != modeTenant {
		return fmt.Errorf("GALACTIC_ROUTER_ROUTER_MODE must be 'transit', 'fabric', or 'tenant', got %q", mode)
	}
	if reflector && mode != modeFabric && mode != modeTenant {
		return errors.New("--reflector is only valid when --mode=fabric or --mode=tenant")
	}
	if bgpListenPort < -1 || bgpListenPort > 65535 {
		return fmt.Errorf("GALACTIC_ROUTER_BGP_LISTEN_PORT must be -1 or a valid port number, got %d", bgpListenPort)
	}
	if metricsPort < 1 || metricsPort > 65535 {
		return fmt.Errorf("GALACTIC_ROUTER_METRICS_PORT must be a valid port number (1-65535), got %d", metricsPort)
	}
	if grpcHealthPort < 1 || grpcHealthPort > 65535 {
		return fmt.Errorf("GALACTIC_ROUTER_GRPC_HEALTH_PORT must be a valid port number (1-65535), got %d", grpcHealthPort)
	}
	return nil
}

// runCmd contains the application startup logic. It reads configuration from
// the provided viper instance and initializes the BGP runtime.
func runCmd(v *viper.Viper) error {
	if err := validateConfig(v); err != nil {
		return err
	}

	nodeName := v.GetString("galactic_router.node_name")
	mode := v.GetString("galactic_router.router_mode")
	bgpListenPort := v.GetInt("galactic_router.bgp_listen_port")
	bgpLocalAddr := v.GetString("galactic_router.bgp_local_address")
	metricsPort := v.GetInt("galactic_router.metrics_port")
	grpcHealthPort := v.GetInt("galactic_router.grpc_health_port")

	var factory galacticruntime.RuntimeFactory
	switch mode {
	case modeTenant:
		factory = gobgp.NewRuntimeFactory(int32(bgpListenPort), bgpLocalAddr)
	case modeFabric:
		factory = frr.NewRuntimeFactory()
	case modeTransit:
		return errors.New("mode=transit is not yet supported")
	}

	ctrl.SetLogger(zap.New(zap.UseDevMode(true)))

	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(bgpv1alpha1.AddToScheme(scheme))

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		HealthProbeBindAddress: "0",
		Metrics: metricsserver.Options{
			BindAddress: fmt.Sprintf(":%d", metricsPort),
		},
	})
	if err != nil {
		return fmt.Errorf("create manager: %w", err)
	}

	ctx := ctrl.SetupSignalHandler()

	// Start gRPC health server.
	lis, err := (&net.ListenConfig{}).Listen(ctx, "tcp", fmt.Sprintf(":%d", grpcHealthPort))
	if err != nil {
		return fmt.Errorf("listen on gRPC health port %d: %w", grpcHealthPort, err)
	}
	grpcSrv := grpc.NewServer()
	healthSrv := grpchealth.NewServer()
	grpc_health_v1.RegisterHealthServer(grpcSrv, healthSrv)
	healthSrv.SetServingStatus("", grpc_health_v1.HealthCheckResponse_SERVING)
	go func() {
		if serveErr := grpcSrv.Serve(lis); serveErr != nil {
			log.Printf("gRPC health server: %v", serveErr)
		}
	}()
	go func() {
		<-ctx.Done()
		grpcSrv.GracefulStop()
	}()

	// Pre-flight RBAC check.
	checkWatchPermissions(mgr)

	// Register field indexes.
	if err := controller.RegisterIndexes(ctx, mgr); err != nil {
		return fmt.Errorf("register field indexes: %w", err)
	}

	// Create runtime manager.
	runtimeMgr := galacticruntime.NewRuntimeManager(factory)

	// Create reconciler.
	rec := reconcile.New(mgr.GetClient(), nodeName, mode, bgpLocalAddr)

	// Register BGPRouter controller.
	if err := (&controller.BGPRouterReconciler{
		Client:         mgr.GetClient(),
		Scheme:         mgr.GetScheme(),
		Reconciler:     rec,
		RuntimeManager: runtimeMgr,
		Hasher:         hash.DesiredRouter,
		NodeName:       nodeName,
		RouterMode:     mode,
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("setup BGPRouter controller: %w", err)
	}

	// Register BGPPeer controller.
	if err := (&controller.BGPPeerReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("setup BGPPeer controller: %w", err)
	}

	// Register BGPAdvertisement controller.
	if err := (&controller.BGPAdvertisementReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("setup BGPAdvertisement controller: %w", err)
	}

	// Register BGPVRFInstance controller.
	if err := (&controller.BGPVRFInstanceReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("setup BGPVRFInstance controller: %w", err)
	}

	// Register BGPPolicy controller.
	if err := (&controller.BGPPolicyReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("setup BGPPolicy controller: %w", err)
	}

	// Register Secret controller.
	if err := (&controller.SecretReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("setup Secret controller: %w", err)
	}

	// Register Node controller.
	if err := (&controller.NodeReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("setup Node controller: %w", err)
	}

	// Register GC controller for cleaning up orphaned BGP CRDs and VRFs.
	gcNamespace := v.GetString("galactic_router.gc_namespace")
	gcInterval := v.GetDuration("galactic_router.gc_interval")
	gcRec := &controller.GCReconciler{
		Client:    mgr.GetClient(),
		Scheme:    mgr.GetScheme(),
		Namespace: gcNamespace,
		Interval:  gcInterval,
	}
	if err := gcRec.SetupWithManager(mgr); err != nil {
		return fmt.Errorf("setup GC controller: %w", err)
	}

	// Start the GC ticker goroutine. It runs until the manager's context
	// is cancelled. The initial GC pass waits for informer caches to sync
	// so it doesn't see an empty BGPAdvertisement list and delete live VRFs.
	go func() {
		ticker := time.NewTicker(gcInterval)
		defer ticker.Stop()

		if !mgr.GetCache().WaitForCacheSync(ctx) {
			log.Printf("GC: cache sync failed, skipping initial pass")
			return
		}
		gcRec.RunGC(ctx)

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				gcRec.RunGC(ctx)
			}
		}
	}()

	if err := mgr.Start(ctx); err != nil {
		return fmt.Errorf("manager exited: %w", err)
	}

	return nil
}

// newRootCommand builds the root cobra command with all flags and the
// application startup logic.
func newRootCommand() *cobra.Command {
	v := newViper()

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
				fmt.Printf("galactic-router version %s\n", metadata.Version)
				return nil
			}
			return runCmd(v)
		},
	}

	bindFlags(cmd, v)
	cmd.Flags().Bool("build-info", false, "Print build information and exit")
	cmd.Flags().BoolP("version", "V", false, "Print version and exit")
	return cmd
}
