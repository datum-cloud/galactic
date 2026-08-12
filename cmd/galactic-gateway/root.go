// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"log"
	"net"
	"strings"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	grpchealth "google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"go.datum.net/galactic/internal/config"
	"go.datum.net/galactic/internal/controller"
	"go.datum.net/galactic/internal/gateway"
	"go.datum.net/galactic/internal/metadata"
	bgpv1alpha1 "go.datum.net/network/api/v1alpha1"
)

const (
	appName = "galactic-gateway"

	appDesc = `Galactic edge XDP NAT+LB gateway

 Find more information at: https://www.datum.net/docs`
)

// runCmd contains the application startup logic: it loads and attaches the
// edge NAT+LB eBPF datapath to this node's public interface and registers
// the NetworkGateway/NetworkRule reconcilers that drive it. Unlike
// cmd/galactic-router's runCmd, there is no BGP runtime, RuntimeManager, or
// BGP-family reconciler here at all: NetworkGatewayReconciler/
// NetworkRuleReconciler need no BGP client of their own — they only
// create/update/delete BGPAdvertisement CRDs, which the co-located
// galactic-router (tenant role) picks up via its own
// BGPAdvertisementReconciler.
func runCmd(cfg *config.GatewayConfig) error {
	nodeName := cfg.NodeName
	metricsPort := cfg.MetricsPort
	grpcHealthPort := cfg.GRPCHealthPort

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

	// Load and attach the edge NAT+LB eBPF datapath. Always loads a real
	// gateway.KernelDatapath -- unlike cmd/galactic-router's removed
	// setupGatewayDatapath, there is no gateway.NoopDatapath{} case here:
	// config.GatewayConfig.Validate already rejects an empty
	// PublicInterface/SRv6Address before runCmd is ever reached.
	gwDatapath, err := setupGatewayDatapath(cfg.PublicInterface, cfg.SRv6Address, ctrlmetrics.Registry)
	if err != nil {
		return fmt.Errorf("setup edge gateway eBPF datapath: %w", err)
	}

	// Real (not stubbed) QuotaEnforcer/TelemetryEmitter — see
	// internal/gateway/quota.go and telemetry.go's doc comments for what
	// each does and does not cover.
	gwQuota := gateway.NewNodeQuotaEnforcer(gateway.DefaultMaxRulesPerTenant, gateway.DefaultMaxRuleTableEntries)
	gwTelemetry := gateway.NewPrometheusTelemetryEmitter()
	gwTelemetry.MustRegister(ctrlmetrics.Registry)
	gwEngine := gateway.NewEngine(gwDatapath, gwQuota, gwTelemetry)

	// Register NetworkGateway controller (edge XDP NAT+LB gateway engine).
	if err := (&controller.NetworkGatewayReconciler{
		Client:      mgr.GetClient(),
		Scheme:      mgr.GetScheme(),
		Engine:      gwEngine,
		NodeName:    nodeName,
		SRv6Address: cfg.SRv6Address,
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("setup NetworkGateway controller: %w", err)
	}

	// Register NetworkRule controller (finalizer-guarded teardown ordering
	// and one-time primary_node assignment; see
	// internal/controller/networkrule_controller.go).
	if err := (&controller.NetworkRuleReconciler{
		Client:   mgr.GetClient(),
		Scheme:   mgr.GetScheme(),
		NodeName: nodeName,
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("setup NetworkRule controller: %w", err)
	}

	if err := mgr.Start(ctx); err != nil {
		return fmt.Errorf("manager exited: %w", err)
	}

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
				fmt.Printf("galactic-gateway version %s\n", metadata.Version)
				return nil
			}

			cfg := config.NewGatewayConfig()
			cfg.BindFlags(cmd.Flags())
			if err := cfg.Validate(); err != nil {
				return err
			}
			return runCmd(cfg)
		},
	}

	cmd.Flags().StringP("node-name", "n", "", "Kubernetes node name (required)")
	cmd.Flags().IntP("metrics-port", "",
		config.DefaultGatewayMetricsPort,
		"Metrics listen port")
	cmd.Flags().IntP("grpc-health-port", "",
		config.DefaultGatewayGRPCHealthPort,
		"gRPC health check port")
	cmd.Flags().StringP("gateway-public-interface", "", "",
		"Public/underlay-facing uplink interface for the edge NAT+LB gateway datapath (required)")
	cmd.Flags().StringP("gateway-srv6-address", "", "",
		"This gateway node's own SRv6-reachable address, used as the Full-NAT SNAT source (required)")
	cmd.Flags().Bool("build-info", false, "Print build information and exit")
	cmd.Flags().BoolP("version", "V", false, "Print version and exit")
	return cmd
}
