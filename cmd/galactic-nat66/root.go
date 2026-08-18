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
	"go.datum.net/galactic/internal/metadata"
	bgpv1alpha1 "go.datum.net/network/api/v1alpha1"
)

const (
	appName = "galactic-nat66"

	appDesc = `Galactic sharded NAT66 egress datapath

 Find more information at: https://www.datum.net/docs`
)

// runCmd contains the application startup logic: it loads and attaches
// this shard's NAT66 egress eBPF datapath to its fabric-facing uplink
// interface and registers the NAT66ShardReconciler that publishes this
// shard's identity/health. Mirrors cmd/galactic-gateway/root.go's runCmd
// closely -- see that file's own doc comment for the gRPC health server's
// NOT_SERVING-until-datapath-attached rationale (#360), which applies
// unchanged here.
func runCmd(cfg *config.NAT66Config) error {
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

	// ctx's cause distinguishes a normal signal-triggered shutdown from the
	// health server's own Serve failure below (#360) -- see the cause check
	// after mgr.Start.
	ctx, cancel := context.WithCancelCause(ctrl.SetupSignalHandler())
	defer cancel(nil)

	// Start gRPC health server. grpchealth.NewServer() defaults the ""
	// overall-health service to SERVING, so that must be overridden to
	// NOT_SERVING here, explicitly and immediately: otherwise a probe could
	// see "healthy" for the entire window before the datapath below is even
	// attached. Only once the datapath is attached does this flip to
	// SERVING, further down.
	lis, err := (&net.ListenConfig{}).Listen(ctx, "tcp", fmt.Sprintf(":%d", grpcHealthPort))
	if err != nil {
		return fmt.Errorf("listen on gRPC health port %d: %w", grpcHealthPort, err)
	}
	grpcSrv := grpc.NewServer()
	healthSrv := grpchealth.NewServer()
	grpc_health_v1.RegisterHealthServer(grpcSrv, healthSrv)
	healthSrv.SetServingStatus("", grpc_health_v1.HealthCheckResponse_NOT_SERVING)
	go func() {
		// A Serve failure here is fatal, not merely logged: with no health
		// server left running and nothing to notice, the process would
		// otherwise carry on with no health signal at all. Canceling ctx
		// with this error as its cause carries it out through mgr.Start
		// below, the same way any other fatal startup error does.
		if serveErr := grpcSrv.Serve(lis); serveErr != nil {
			cancel(fmt.Errorf("gRPC health server: %w", serveErr))
		}
	}()
	go func() {
		<-ctx.Done()
		grpcSrv.GracefulStop()
	}()

	// Pre-flight RBAC check.
	checkWatchPermissions(mgr)

	// Load and attach the NAT66 egress eBPF datapath. Always loads a real
	// datapath -- config.NAT66Config.Validate already rejects an empty
	// UplinkInterface/ShardSID/ShardPubAddr before runCmd is ever reached,
	// since this binary only exists to run a NAT66 shard.
	datapathHealth, err := setupNat66Datapath(cfg.UplinkInterface, cfg.ShardSID, cfg.ShardPubAddr, ctrlmetrics.Registry)
	if err != nil {
		return fmt.Errorf("setup NAT66 egress eBPF datapath: %w", err)
	}
	// Only now is the datapath attached -- report serving from here on, not
	// from process start (#360).
	healthSrv.SetServingStatus("", grpc_health_v1.HealthCheckResponse_SERVING)

	// Register NAT66Shard controller.
	if err := (&controller.NAT66ShardReconciler{
		Client:       mgr.GetClient(),
		Scheme:       mgr.GetScheme(),
		NodeName:     nodeName,
		ShardAddress: cfg.ShardPubAddr,
		ShardSID:     cfg.ShardSID,
		Datapath:     datapathHealth,
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("setup NAT66Shard controller: %w", err)
	}

	if err := mgr.Start(ctx); err != nil {
		return fmt.Errorf("manager exited: %w", err)
	}
	// mgr.Start only returns nil once ctx is Done, and by then ctx always
	// has a cause: either context.Canceled (an ordinary signal-triggered
	// shutdown) or the gRPC health server's own fatal Serve error from
	// above. Only the latter should fail the process.
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
				fmt.Printf("galactic-nat66 version %s\n", metadata.Version)
				return nil
			}

			cfg := config.NewNAT66Config()
			cfg.BindFlags(cmd.Flags())
			if err := cfg.Validate(); err != nil {
				return err
			}
			return runCmd(cfg)
		},
	}

	cmd.Flags().StringP("node-name", "n", "", "Kubernetes node name (required)")
	cmd.Flags().IntP("metrics-port", "",
		config.DefaultNAT66MetricsPort,
		"Metrics listen port")
	cmd.Flags().IntP("grpc-health-port", "",
		config.DefaultNAT66GRPCHealthPort,
		"gRPC health check port")
	cmd.Flags().StringP("nat66-uplink-interface", "", "",
		"Fabric-facing uplink interface this NAT66 shard's XDP datapath attaches to (required)")
	cmd.Flags().StringP("nat66-shard-sid", "", "",
		"This shard's own SRv6 uSID, encapsulation target for tenant egress traffic (required)")
	cmd.Flags().StringP("nat66-shard-pub-addr", "", "",
		"This shard's own publicly-routable masquerade source address (required)")
	cmd.Flags().Bool("build-info", false, "Print build information and exit")
	cmd.Flags().BoolP("version", "V", false, "Print version and exit")
	return cmd
}
