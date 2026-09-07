// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"fmt"
	"log"
	"net"
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

// runCmd is the application startup: it registers the ingress sidecar's
// reconciler against a cluster-scoped EndpointSlice watch, then seeds the store
// from live API state and runs its startup inventory and periodic sweep.
//
// There is no BGP runtime here. The BGP types are on the scheme solely so the
// optional gateway publisher below can read routers and instances and write
// advertisements, which stays off while no node name is configured.
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

	// Return-path gateway advertisement is opt-in on the node name alone,
	// and leaving it unset is fully inert. The cached client is fine here:
	// unlike the reconcile hot path, publishing runs once per VRF
	// lifetime.
	if cfg.NodeName != "" {
		store.SetGatewayPublisher(
			ingresssidecar.NewK8sGatewayPublisher(mgr.GetClient(), cfg.NodeName, cfg.Namespace),
			ingresssidecar.NetlinkGatewayAddressResolver{},
		)

		// This node's real, globally routable underlay source address. The
		// default local auto-detection resolves to the wrong address from
		// inside Envoy's pod namespace, which is where this sidecar always
		// runs. Gated on the node name like the publisher above, both needing
		// this node's identity, and the cached client is fine for the same
		// reason.
		ingresssidecar.SetNodeSourceAddressResolver(
			ingresssidecar.NewK8sNodeSourceAddressResolver(mgr.GetClient(), cfg.NodeName, cfg.Namespace),
		)

		// Gateway address provisioning is a second, independent opt-in on
		// top of the publisher: it needs its own explicit platform
		// addressing decision rather than a default. Without it the
		// publisher stays idle, the resolver having nothing to find.
		if cfg.GatewayPrefix != "" {
			_, network, err := net.ParseCIDR(cfg.GatewayPrefix)
			if err != nil {
				// Validation already checked this parses, so a failure here
				// means the two disagree. Fail loudly rather than run
				// silently with no provisioning.
				return fmt.Errorf("parse gateway prefix %q: %w", cfg.GatewayPrefix, err)
			}
			ingresssidecar.SetGatewayAddressAssignment(network, cfg.NodeName)
		} else {
			log.Printf("no gateway prefix configured (%s) -- "+
				"return-path gateway address provisioning is disabled; PublishGateway will never fire",
				config.EnvVRFGatewayPrefix)
		}
	} else {
		log.Printf("no node name configured (%s / legacy NODE_NAME) -- "+
			"return-path gateway advertisement publishing is disabled", config.EnvVRFNodeName)
	}

	if err := (&ingresssidecar.Reconciler{Store: store}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("setup EndpointSlice controller: %w", err)
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

	// The manager returns nil only once the context is done, which here means
	// a signal-triggered shutdown; there is no other source of cancellation.
	//
	// No proactive teardown on exit: kernel state is left for the next instance
	// to reconcile from scratch, since a live Envoy container beside a dying
	// sidecar mid-rollout would otherwise blackhole in-flight connections.
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
	cmd.Flags().StringP("gateway-prefix", "", "",
		"Reserved, byte-aligned IPv6 CIDR (e.g. a /80 or /96) this sidecar derives its own per-VPC "+
			"return-path gateway address from -- must be address space no tenant IPAM (this repo's own or "+
			"external) ever allocates from; only takes effect when --node-name is also set (env "+
			config.EnvVRFGatewayPrefix+")")
	cmd.Flags().Bool("build-info", false, "Print build information and exit")
	cmd.Flags().BoolP("version", "V", false, "Print version and exit")
	return cmd
}
