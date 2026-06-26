// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"log"
	"net"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
	grpchealth "google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"

	bgpv1alpha1 "go.miloapis.com/cosmos/api/bgp/v1alpha1"
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
	v.SetDefault("galactic_router.gobgp_grpc_port", defaultGrpcPort)
	v.SetDefault("galactic_router.gobgp_grpc_server_enabled", false)
	v.SetDefault("galactic_router.metrics_port", 8080)
	v.SetDefault("galactic_router.grpc_health_port", 5000)

	v.AutomaticEnv()

	// Explicit bindings — env var names do not follow a uniform
	// GALACTIC_ROUTER_* prefix pattern, so AutomaticEnv alone would not
	// resolve them correctly.
	//nolint:errcheck // keys are controlled, BindEnv cannot fail here
	v.BindEnv("galactic_router.node_name", "NODE_NAME")
	//nolint:errcheck
	v.BindEnv("galactic_router.router_role", "ROUTER_ROLE")
	//nolint:errcheck
	v.BindEnv("galactic_router.bgp_listen_port", "BGP_LISTEN_PORT")
	//nolint:errcheck
	v.BindEnv("galactic_router.bgp_local_address", "BGP_LOCAL_ADDRESS")
	//nolint:errcheck
	v.BindEnv("galactic_router.gobgp_grpc_server_enabled", "GALACTIC_GOBGP_GRPC_SERVER_ENABLED")
	//nolint:errcheck
	v.BindEnv("galactic_router.gobgp_grpc_port", "GALACTIC_GOBGP_GRPC_PORT")
	//nolint:errcheck
	v.BindEnv("galactic_router.metrics_port", "METRICS_PORT")
	//nolint:errcheck
	v.BindEnv("galactic_router.grpc_health_port", "GRPC_HEALTH_PORT")

	return v
}

const (
	roleTenant = "tenant"
	roleFabric = "fabric"
)

// bindFlags registers each viper-configured flag on the command so that
// `viper.BindPFlags` can resolve flag values at runtime.
func bindFlags(cmd *cobra.Command, v *viper.Viper) { //nolint:lll // cobra flag defs are inherently long
	cmd.Flags().StringP("node-name", "n", "", "Kubernetes node name (required)")
	cmd.Flags().StringP("router-role", "r", "",
		"Router role: 'tenant' or 'fabric' (required)")
	cmd.Flags().IntP("bgp-listen-port", "p", v.GetInt("galactic_router.bgp_listen_port"),
		"TCP port GoBGP binds for inbound BGP")
	cmd.Flags().StringP("bgp-local-address", "",
		v.GetString("galactic_router.bgp_local_address"),
		"Source address for outgoing BGP TCP connections")
	cmd.Flags().BoolP("gobgp-grpc-server-enabled", "",
		v.GetBool("galactic_router.gobgp_grpc_server_enabled"),
		"Enable the embedded GoBGP gRPC API server")
	cmd.Flags().IntP("gobgp-grpc-port", "",
		v.GetInt("galactic_router.gobgp_grpc_port"),
		"Port for the GoBGP gRPC API server")
	cmd.Flags().IntP("metrics-port", "",
		v.GetInt("galactic_router.metrics_port"),
		"Port for the controller-runtime metrics server")
	cmd.Flags().IntP("grpc-health-port", "",
		v.GetInt("galactic_router.grpc_health_port"),
		"Port for the gRPC health check server")

	if err := v.BindPFlags(cmd.Flags()); err != nil {
		log.Fatalf("bind flags: %v", err)
	}
}

// validateConfig checks that the configuration values are valid.
func validateConfig(v *viper.Viper) error {
	nodeName := v.GetString("galactic_router.node_name")
	routerRole := v.GetString("galactic_router.router_role")
	bgpListenPort := v.GetInt("galactic_router.bgp_listen_port")
	grpcPort := v.GetInt("galactic_router.gobgp_grpc_port")
	metricsPort := v.GetInt("galactic_router.metrics_port")
	grpcHealthPort := v.GetInt("galactic_router.grpc_health_port")

	if nodeName == "" {
		return fmt.Errorf("--node-name is required")
	}
	if routerRole == "" {
		return fmt.Errorf("--router-role is required")
	}
	if routerRole != roleTenant && routerRole != roleFabric {
		return fmt.Errorf("ROUTER_ROLE must be 'tenant' or 'fabric', got %q", routerRole)
	}
	if bgpListenPort < -1 || bgpListenPort > 65535 {
		return fmt.Errorf("BGP_LISTEN_PORT must be -1 or a valid port number, got %d", bgpListenPort)
	}
	if grpcPort < 1 || grpcPort > 65535 {
		return fmt.Errorf("GALACTIC_GOBGP_GRPC_PORT must be a valid port number (1-65535), got %d", grpcPort)
	}
	if metricsPort < 1 || metricsPort > 65535 {
		return fmt.Errorf("METRICS_PORT must be a valid port number (1-65535), got %d", metricsPort)
	}
	if grpcHealthPort < 1 || grpcHealthPort > 65535 {
		return fmt.Errorf("GRPC_HEALTH_PORT must be a valid port number (1-65535), got %d", grpcHealthPort)
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
	routerRole := v.GetString("galactic_router.router_role")
	bgpListenPort := v.GetInt("galactic_router.bgp_listen_port")
	bgpLocalAddr := v.GetString("galactic_router.bgp_local_address")
	grpcEnabled := v.GetBool("galactic_router.gobgp_grpc_server_enabled")
	grpcPort := v.GetInt("galactic_router.gobgp_grpc_port")
	metricsPort := v.GetInt("galactic_router.metrics_port")
	grpcHealthPort := v.GetInt("galactic_router.grpc_health_port")

	// Construct gRPC listen address.
	var grpcListenAddress string
	if grpcEnabled {
		grpcListenAddress = fmt.Sprintf(":%d", grpcPort)
	}

	var factory galacticruntime.RuntimeFactory
	switch routerRole {
	case "tenant":
		factory = gobgp.NewRuntimeFactory(int32(bgpListenPort), bgpLocalAddr, grpcListenAddress)
	case roleFabric:
		factory = frr.NewRuntimeFactory()
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
		return fmt.Errorf("create manager: %v", err)
	}

	ctx := ctrl.SetupSignalHandler()

	// Start gRPC health server.
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", grpcHealthPort))
	if err != nil {
		return fmt.Errorf("listen on gRPC health port %d: %v", grpcHealthPort, err)
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
		return fmt.Errorf("register field indexes: %v", err)
	}

	// Create runtime manager.
	runtimeMgr := galacticruntime.NewRuntimeManager(factory)

	// Create reconciler.
	rec := reconcile.New(mgr.GetClient(), nodeName, routerRole)

	// Register BGPRouter controller.
	if err := (&controller.BGPRouterReconciler{
		Client:         mgr.GetClient(),
		Scheme:         mgr.GetScheme(),
		Reconciler:     rec,
		RuntimeManager: runtimeMgr,
		Hasher:         hash.DesiredRouter,
		NodeName:       nodeName,
		RouterRole:     routerRole,
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("setup BGPRouter controller: %v", err)
	}

	// Register BGPPeer controller.
	if err := (&controller.BGPPeerReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("setup BGPPeer controller: %v", err)
	}

	// Register BGPAdvertisement controller.
	if err := (&controller.BGPAdvertisementReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("setup BGPAdvertisement controller: %v", err)
	}

	// Register BGPVRFInstance controller.
	if err := (&controller.BGPVRFInstanceReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("setup BGPVRFInstance controller: %v", err)
	}

	// Register BGPPolicy controller.
	if err := (&controller.BGPPolicyReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("setup BGPPolicy controller: %v", err)
	}

	// Register Secret controller.
	if err := (&controller.SecretReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("setup Secret controller: %v", err)
	}

	// Register Node controller.
	if err := (&controller.NodeReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("setup Node controller: %v", err)
	}

	if err := mgr.Start(ctx); err != nil {
		return fmt.Errorf("manager exited: %v", err)
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
		RunE: func(cmd *cobra.Command, args []string) error {
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
