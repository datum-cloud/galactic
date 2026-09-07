// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"fmt"
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

// runCmd is the application startup: it loads and attaches the edge eBPF
// datapath to this node's public interface and registers the reconcilers that
// drive it. There is no BGP runtime here at all; the reconcilers only create
// and delete BGPAdvertisement CRDs, which the co-located router picks up.
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

	// The cause distinguishes a normal signal-triggered shutdown from the
	// health server's own Serve failure below. See the cause check after the
	// manager returns.
	ctx, cancel := context.WithCancelCause(ctrl.SetupSignalHandler())
	defer cancel(nil)

	// The health server defaults its overall service to serving, which must be
	// overridden to not-serving here, immediately: otherwise a probe sees
	// healthy for the whole window before the datapath is even attached. It
	// flips to serving further down, once the datapath is attached and the
	// rule table is reachable.
	lis, err := (&net.ListenConfig{}).Listen(ctx, "tcp", fmt.Sprintf(":%d", grpcHealthPort))
	if err != nil {
		return fmt.Errorf("listen on gRPC health port %d: %w", grpcHealthPort, err)
	}
	grpcSrv := grpc.NewServer()
	healthSrv := grpchealth.NewServer()
	grpc_health_v1.RegisterHealthServer(grpcSrv, healthSrv)
	healthSrv.SetServingStatus("", grpc_health_v1.HealthCheckResponse_NOT_SERVING)
	go func() {
		// A Serve failure is fatal rather than merely logged: with no health
		// server left and nothing to notice, the process would carry on
		// with no health signal at all. Cancelling with this as the cause
		// carries it out through the manager below, like any other fatal
		// startup error.
		if serveErr := grpcSrv.Serve(lis); serveErr != nil {
			cancel(fmt.Errorf("gRPC health server: %w", serveErr))
		}
	}()
	go func() {
		<-ctx.Done()
		grpcSrv.GracefulStop()
	}()

	// Register the field index the gateway reconciler queries. It is an index
	// rather than a real API field, so it resolves only if this process's own
	// manager registered it: every reconcile here fails outright without this,
	// even though another binary registers the same index on its own manager.
	//
	// Only this one index, not the full set. This binary's reconcilers query no
	// other, and registering the rest starts live informers for kinds this
	// binary's role grants no access to, which wedges the manager permanently
	// with every controller blocked on cache sync behind forbidden reflector
	// errors.
	if err := controller.RegisterBGPRouterTargetIndex(ctx, mgr); err != nil {
		return fmt.Errorf("register field indexes: %w", err)
	}

	// Pre-flight RBAC check.
	checkWatchPermissions(mgr)

	// Load and attach the edge eBPF datapath. Always a real datapath, never a
	// no-op: configuration validation rejects an empty public interface or SRv6
	// address before this is reached.
	gwDatapath, err := setupGatewayDatapath(cfg.PublicInterface, cfg.SRv6Address, ctrlmetrics.Registry)
	if err != nil {
		return fmt.Errorf("setup edge gateway eBPF datapath: %w", err)
	}
	// Only now is the datapath attached and its rule table reachable. Report
	// serving from here on, not from process start.
	healthSrv.SetServingStatus("", grpc_health_v1.HealthCheckResponse_SERVING)

	// Real quota and telemetry implementations, not stubs. See their own doc
	// comments for what each does and does not cover.
	gwQuota := gateway.NewNodeQuotaEnforcer(gateway.DefaultMaxRulesPerTenant, gateway.DefaultMaxRuleTableEntries)
	gwTelemetry := gateway.NewPrometheusTelemetryEmitter()
	gwTelemetry.MustRegister(ctrlmetrics.Registry)
	gwEngine := gateway.NewEngine(gwDatapath, gwQuota, gwTelemetry)

	// The gateway engine reconciler. No SRv6 address is passed: this datapath
	// rewrites nothing, so a gateway node has no translation source of its own
	// to publish.
	if err := (&controller.NetworkGatewayReconciler{
		Client:   mgr.GetClient(),
		Scheme:   mgr.GetScheme(),
		Engine:   gwEngine,
		NodeName: nodeName,
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("setup NetworkGateway controller: %w", err)
	}

	// The rule reconciler: finalizer-guarded teardown ordering and the Accepted
	// condition.
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
	// The manager returns nil only once the context is done, and by then it
	// always has a cause: cancellation for an ordinary shutdown, or the health
	// server's fatal error above. Only the latter should fail the process.
	if cause := context.Cause(ctx); cause != nil && !errors.Is(cause, context.Canceled) {
		return cause
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
		"This gateway node's own SRv6-reachable address, used as the Maglev/DSR encap source (required)")
	cmd.Flags().Bool("build-info", false, "Print build information and exit")
	cmd.Flags().BoolP("version", "V", false, "Print version and exit")
	return cmd
}
