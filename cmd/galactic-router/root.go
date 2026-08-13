// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	grpchealth "google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	"go.datum.net/galactic/internal/config"
	"go.datum.net/galactic/internal/controller"
	"go.datum.net/galactic/internal/hash"
	"go.datum.net/galactic/internal/metadata"
	"go.datum.net/galactic/internal/plumbing/loaddr"
	"go.datum.net/galactic/internal/reconcile"
	galacticruntime "go.datum.net/galactic/internal/runtime"
	"go.datum.net/galactic/internal/runtime/frr"
	"go.datum.net/galactic/internal/runtime/gobgp"
	networkwebhook "go.datum.net/galactic/internal/webhook"
	bgpv1alpha1 "go.datum.net/network/api/v1alpha1"
)

const (
	appName = "galactic-router"

	appDesc = `Galactic SRv6 data plane router

 Find more information at: https://www.datum.net/docs`
)

// resolveBGPLocalAddress returns explicit if non-empty. Otherwise it calls
// detect to read the BGP local address from the host's lo interface,
// returning an error if detection fails — there is no silent fallback to an
// unset address.
func resolveBGPLocalAddress(explicit string, detect func() (string, error)) (string, error) {
	if explicit != "" {
		return explicit, nil
	}
	addr, err := detect()
	if err != nil {
		return "", fmt.Errorf(
			"GALACTIC_ROUTER_BGP_LOCAL_ADDRESS not set and no address could be detected on lo: %w", err)
	}
	return addr, nil
}

// runCmd contains the application startup logic. It reads configuration from
// the provided config and initializes the BGP runtime.
func runCmd(cfg *config.RouterConfig) error {
	nodeName := cfg.NodeName
	mode := cfg.Mode
	bgpListenPort := cfg.BGPListenPort
	metricsPort := cfg.MetricsPort
	grpcHealthPort := cfg.GRPCHealthPort

	bgpLocalAddr, err := resolveBGPLocalAddress(cfg.BGPLocalAddr, loaddr.Detect)
	if err != nil {
		return err
	}

	var factory galacticruntime.RuntimeFactory
	switch mode {
	case config.ModeTenant:
		factory = gobgp.NewRuntimeFactory(int32(bgpListenPort), bgpLocalAddr)
	case config.ModeFabric:
		factory = frr.NewRuntimeFactory()
	case config.ModeTransit:
		return errors.New("mode=transit is not yet supported")
	}

	ctrl.SetLogger(zap.New(zap.UseDevMode(true)))

	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(bgpv1alpha1.AddToScheme(scheme))

	mgrOptions := ctrl.Options{
		Scheme:                 scheme,
		HealthProbeBindAddress: "0",
		Metrics: metricsserver.Options{
			BindAddress: fmt.Sprintf(":%d", metricsPort),
		},
	}
	// The NetworkRule admission webhook (internal/webhook) is opt-in: it is
	// the first webhook in this codebase, and enabling it requires TLS cert
	// material (config/webhook/'s kustomization.yaml documents the
	// cert-manager-or-equivalent prerequisite) plus the
	// ValidatingWebhookConfiguration/Service manifests to actually be
	// applied — see config.RouterConfig.WebhookEnabled's doc comment.
	if cfg.WebhookEnabled {
		mgrOptions.WebhookServer = webhook.NewServer(webhook.Options{
			Port:    cfg.WebhookPort,
			CertDir: cfg.WebhookCertDir,
		})
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), mgrOptions)
	if err != nil {
		return fmt.Errorf("create manager: %w", err)
	}

	// ctx carries a cause so that an ordinary signal-triggered shutdown can
	// be told apart from the health server's own Serve failure below (#372),
	// which cmd/galactic-gateway already treats as fatal -- see the cause
	// check after mgr.Start.
	ctx, cancel := context.WithCancelCause(ctrl.SetupSignalHandler())
	defer cancel(nil)

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
		// Serve returning non-nil means this node has lost its health
		// signal for good: logging it and continuing would leave the
		// router running unprobeable, with nothing to restart it and
		// nothing to report it. Cancelling ctx with the failure as its
		// cause routes it out through mgr.Start below, so it surfaces
		// like any other fatal startup error. The GracefulStop path
		// below is unaffected: Serve returns nil there.
		if serveErr := grpcSrv.Serve(lis); serveErr != nil {
			cancel(fmt.Errorf("gRPC health server: %w", serveErr))
		}
	}()
	go func() {
		<-ctx.Done()
		grpcSrv.GracefulStop()
	}()

	if cfg.WebhookEnabled {
		// TODO(edge-gateway): AllowAllAuthorizer is a placeholder — see
		// its doc comment. Wire a real Authorizer here once the companion
		// operator integration exists. Shared between both validators
		// below: they pose the identical vpc/vpcattachment ownership
		// question (internal/webhook.Authorizer's own doc comment).
		authorizer := networkwebhook.AllowAllAuthorizer{}

		ruleValidator := &networkwebhook.NetworkRuleValidator{Authorizer: authorizer}
		if err := ruleValidator.SetupWebhookWithManager(mgr); err != nil {
			return fmt.Errorf("setup NetworkRule webhook: %w", err)
		}

		// NetworkEgressPolicy (datum-cloud/enhancements#865) requires the
		// same ownership-verification admission webhook NetworkRule
		// already does (design plan §4.1).
		egressPolicyValidator := &networkwebhook.NetworkEgressPolicyValidator{Authorizer: authorizer}
		if err := egressPolicyValidator.SetupWebhookWithManager(mgr); err != nil {
			return fmt.Errorf("setup NetworkEgressPolicy webhook: %w", err)
		}
	}

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
	gcRec := &controller.GCReconciler{
		Client:    mgr.GetClient(),
		Scheme:    mgr.GetScheme(),
		Namespace: cfg.GCNamespace,
		NodeName:  nodeName,
		Interval:  cfg.GCInterval,
	}
	if err := gcRec.SetupWithManager(mgr); err != nil {
		return fmt.Errorf("setup GC controller: %w", err)
	}

	// Start the GC ticker goroutine. It runs until the manager's context
	// is cancelled. The initial GC pass waits for informer caches to sync
	// so it doesn't see an empty BGPAdvertisement list and delete live VRFs.
	go func() {
		ticker := time.NewTicker(cfg.GCInterval)
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

	// Register EgressRoute controller and start its ticker goroutine
	// (datum-cloud/enhancements#865, design plan §4.4/§7.1) -- extracted
	// to its own function to keep this function's own cyclomatic
	// complexity down (gocyclo), not for any reuse reason.
	if err := startEgressRouteController(ctx, mgr, cfg, nodeName); err != nil {
		return err
	}

	if err := mgr.Start(ctx); err != nil {
		return fmt.Errorf("manager exited: %w", err)
	}
	// A nil return from mgr.Start means ctx is Done, so it always has a
	// cause by now: context.Canceled for a signal-triggered shutdown, or
	// the health server's fatal Serve error from above. Only the second
	// should fail the process.
	if cause := context.Cause(ctx); cause != nil && !errors.Is(cause, context.Canceled) {
		return cause
	}

	return nil
}

// startEgressRouteController registers controller.EgressRouteReconciler and
// starts its ticker goroutine, reconciling tenant VRF ::/0 default routes
// toward each VPC's assigned gateway egress_sid (datum-cloud/
// enhancements#865, design plan §4.4/§7.1). Mirrors the GC ticker in
// runCmd exactly (including waiting for cache sync first, so the initial
// pass doesn't see an empty NetworkEgressPolicy list and remove every live
// egress route) -- reuses cfg.GCNamespace (both scan the same namespace's
// CRDs) but its own separate interval, see DefaultRouterEgressRouteInterval's
// doc comment for why.
func startEgressRouteController(
	ctx context.Context, mgr ctrl.Manager, cfg *config.RouterConfig, nodeName string,
) error {
	rec := &controller.EgressRouteReconciler{
		Client:    mgr.GetClient(),
		Scheme:    mgr.GetScheme(),
		Namespace: cfg.GCNamespace,
		NodeName:  nodeName,
		Interval:  cfg.EgressRouteInterval,
	}
	if err := rec.SetupWithManager(mgr); err != nil {
		return fmt.Errorf("setup EgressRoute controller: %w", err)
	}

	go func() {
		ticker := time.NewTicker(cfg.EgressRouteInterval)
		defer ticker.Stop()

		if !mgr.GetCache().WaitForCacheSync(ctx) {
			log.Printf("EgressRoute: cache sync failed, skipping initial pass")
			return
		}
		rec.RunOnce(ctx)

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				rec.RunOnce(ctx)
			}
		}
	}()

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
				fmt.Printf("galactic-router version %s\n", metadata.Version)
				return nil
			}

			cfg := config.NewRouterConfig()
			cfg.BindFlags(cmd.Flags())
			if err := cfg.Validate(); err != nil {
				return err
			}
			return runCmd(cfg)
		},
	}

	cmd.Flags().StringP("node-name", "n", "", "Kubernetes node name (required)")
	cmd.Flags().StringP("mode", "m", "",
		"Operating mode: '"+config.ModeTransit+"', '"+config.ModeFabric+"', or '"+config.ModeTenant+"' (required)")
	cmd.Flags().Bool("reflector", false,
		"Enable route reflector mode (requires --mode="+config.ModeFabric+" or --mode="+config.ModeTenant+")")
	cmd.Flags().IntP("bgp-listen-port", "p", config.DefaultRouterBGPListenPort,
		"BGP listen port")
	cmd.Flags().StringP("bgp-local-address", "",
		"",
		"Source address for outgoing BGP connections; auto-detected from lo if unset")
	cmd.Flags().IntP("metrics-port", "",
		config.DefaultRouterMetricsPort,
		"Metrics listen port")
	cmd.Flags().IntP("grpc-health-port", "",
		config.DefaultRouterGRPCHealthPort,
		"gRPC health check port")
	cmd.Flags().StringP("gc-namespace", "",
		config.DefaultRouterGCNamespace,
		"Namespace for orphaned CRD cleanup")
	cmd.Flags().DurationP("gc-interval", "",
		config.DefaultRouterGCInterval,
		"Cleanup interval")
	cmd.Flags().DurationP("egress-route-interval", "",
		config.DefaultRouterEgressRouteInterval,
		"Egress default-route reconcile interval (datum-cloud/enhancements#865)")
	cmd.Flags().Bool("webhook-enabled", false,
		"Enable the NetworkRule admission webhook (requires TLS cert material; see config/webhook/)")
	cmd.Flags().IntP("webhook-port", "",
		config.DefaultRouterWebhookPort,
		"Webhook server listen port")
	cmd.Flags().StringP("webhook-cert-dir", "", "",
		"Directory containing the webhook server's TLS cert/key; defaults to controller-runtime's own default")
	cmd.Flags().Bool("build-info", false, "Print build information and exit")
	cmd.Flags().BoolP("version", "V", false, "Print version and exit")
	return cmd
}
