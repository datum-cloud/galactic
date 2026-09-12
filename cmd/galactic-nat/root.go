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
	appName = "galactic-nat"

	appDesc = `Galactic sharded egress translation datapath (NAT66 and NAT64)

 Find more information at: https://www.datum.net/docs`
)

// runCmd is the application startup: it loads and attaches this shard's NAT66
// egress datapath to its fabric-facing uplink and registers the reconciler that
// publishes this shard's identity and health.
func runCmd(cfg *config.NATConfig) error {
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
	// health server's own Serve failure below.
	ctx, cancel := context.WithCancelCause(ctrl.SetupSignalHandler())
	defer cancel(nil)

	// The health server defaults its overall service to serving, which must be
	// overridden to not-serving here, immediately: otherwise a probe sees
	// healthy for the whole window before the datapath is attached. It flips to
	// serving further down, once the datapath is attached.
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
		// carries it out through the manager below.
		if serveErr := grpcSrv.Serve(lis); serveErr != nil {
			cancel(fmt.Errorf("gRPC health server: %w", serveErr))
		}
	}()
	go func() {
		<-ctx.Done()
		grpcSrv.GracefulStop()
	}()

	// Register the one field index the shard reconciler needs, to find the
	// BGPRouter it advertises through. It is an index rather than a real API
	// field, so it resolves only if this process's own manager registered it.
	//
	// Only this one, not the full set the other binaries register: the cache
	// starts a live informer for every type any index touches, immediately and
	// regardless of whether this binary ever reads it. Registering them all
	// fails at manager startup against this binary's role, which deliberately
	// grants only what it uses. The narrower call keeps that intact instead of
	// widening the role to match a function this binary does not need in
	// full.
	if err := controller.RegisterBGPRouterTargetIndex(ctx, mgr); err != nil {
		return fmt.Errorf("register field indexes: %w", err)
	}

	// Pre-flight RBAC check.
	checkWatchPermissions(mgr)

	// Load and attach the egress translation datapath. Always a real datapath:
	// configuration validation rejects an empty uplink or SID, and a shard
	// serving neither address family, before this is reached -- this binary
	// exists only to run a shard.
	datapathHealth, err := setupNatDatapath(cfg, ctrlmetrics.Registry)
	if err != nil {
		return fmt.Errorf("setup egress translation eBPF datapath: %w", err)
	}

	// Correct the per-tenant session counts the datapath cannot maintain on its
	// own; see runSessionResync. Tied to ctx, so it stops with the manager.
	go runSessionResync(ctx, natDatapathKeepAlive.objs)
	// Only now is the datapath attached. Report serving from here on, not from
	// process start.
	healthSrv.SetServingStatus("", grpc_health_v1.HealthCheckResponse_SERVING)

	// Register EgressShard controller.
	if err := (&controller.EgressShardReconciler{
		Client:           mgr.GetClient(),
		Scheme:           mgr.GetScheme(),
		NodeName:         nodeName,
		ShardSID:         cfg.ShardSID,
		ShardAddressIPv6: cfg.ShardPubAddr6,
		ShardAddressIPv4: cfg.ShardPubAddr4,
		NAT64Prefix:      cfg.NAT64Prefix,
		Datapath:         datapathHealth,
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("setup EgressShard controller: %w", err)
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
				fmt.Printf("galactic-nat version %s\n", metadata.Version)
				return nil
			}

			cfg := config.NewNATConfig()
			cfg.BindFlags(cmd.Flags())
			if err := cfg.Validate(); err != nil {
				return err
			}
			return runCmd(cfg)
		},
	}

	cmd.Flags().StringP("node-name", "n", "", "Kubernetes node name (required)")
	cmd.Flags().IntP("metrics-port", "",
		config.DefaultNATMetricsPort,
		"Metrics listen port")
	cmd.Flags().IntP("grpc-health-port", "",
		config.DefaultNATGRPCHealthPort,
		"gRPC health check port")
	cmd.Flags().StringP("nat-uplink-interface", "", "",
		"Fabric-facing uplink interface this shard's XDP datapath attaches to (required)")
	cmd.Flags().StringP("nat-shard-sid", "", "",
		"This shard's own SRv6 uSID, encapsulation target for tenant egress traffic (required)")
	cmd.Flags().StringP("nat-shard-pub-addr6", "", "",
		"This shard's own publicly-routable IPv6 masquerade source address, enabling NAT66")
	cmd.Flags().StringP("nat-shard-pub-addr4", "", "",
		"This shard's own publicly-routable IPv4 masquerade source address, enabling NAT64 "+
			"together with --nat64-prefix")
	cmd.Flags().StringP("nat64-prefix", "", "",
		"Fabric-wide NAT64 /96 this shard translates for; must match what DNS64 synthesizes into")
	cmd.Flags().IntP("nat-session-limit", "",
		config.DefaultNATSessionLimit,
		"Per-tenant translated-session ceiling across both address families (0 means unlimited)")
	cmd.Flags().Bool("build-info", false, "Print build information and exit")
	cmd.Flags().BoolP("version", "V", false, "Print version and exit")
	return cmd
}
