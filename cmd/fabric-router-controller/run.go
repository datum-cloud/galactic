// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"

	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	networkv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	"go.datum.net/galactic/internal/fabric/routing/controller"
	routingmetrics "go.datum.net/galactic/internal/fabric/routing/metrics"
	"go.datum.net/galactic/internal/fabric/routing/rollout"
	"go.datum.net/galactic/internal/fabric/routing/topology"
)

// leaderElectionID is the lease the controller's replicas share.
const leaderElectionID = "fabric-router-controller.galactic.datumapis.com"

func newRunCommand() *cobra.Command {
	var (
		metricsAddress, healthAddress, namespace string
		leaderElect, rolloutEnabled              bool
		topologyEnabled                          bool
		topologyNamespace                        string
	)
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Compile fabric routers into revisions and roll them out",
		Long: `Watches the BGPRouters whose class names this controller and every object
their configuration reads, and creates an immutable FabricRouterRevision
for each router's current inputs. It reports Accepted and ResolvedRefs on
the router and keeps its newest revisions and every revision a deployment
uses.

With --rollout it also gives each compiled router a FabricRouterDeployment, keeps its
candidate on the newest revision, and runs FabricReleaseAuthorizations:
one release per routing domain at a time, promoting within each router's
FabricRolloutPolicy. It never writes FRR; the node agents do.

With --topology it also generates BGPPeers from the FabricTopologies of
--topology-namespace and the FabricEndpoint records of their routing
domain, and reports on each endpoint whether topologies may peer over it. Generated peers are compiled
like any other.

The leader exports each router's compile result and, with --rollout, each
deployment's and outstanding release's state as galactic_fabric_routing_*
metrics on the metrics address.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctrl.SetLogger(zap.New())
			scheme := runtime.NewScheme()
			utilruntime.Must(corev1.AddToScheme(scheme))
			utilruntime.Must(networkv1alpha1.AddToScheme(scheme))
			mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
				Scheme:                        scheme,
				Metrics:                       metricsserver.Options{BindAddress: metricsAddress},
				HealthProbeBindAddress:        healthAddress,
				LeaderElection:                leaderElect,
				LeaderElectionID:              leaderElectionID,
				LeaderElectionNamespace:       namespace,
				LeaderElectionReleaseOnCancel: true,
			})
			if err != nil {
				return fmt.Errorf("create manager: %w", err)
			}
			if err := (&controller.Reconciler{Client: mgr.GetClient()}).SetupWithManager(mgr); err != nil {
				return fmt.Errorf("set up revision controller: %w", err)
			}
			if rolloutEnabled {
				recorder := mgr.GetEventRecorder("fabric-router-controller")
				deployments := &rollout.DeploymentReconciler{Client: mgr.GetClient(), Recorder: recorder}
				if err := deployments.SetupWithManager(mgr); err != nil {
					return fmt.Errorf("set up deployment controller: %w", err)
				}
				releases := &rollout.ReleaseReconciler{Client: mgr.GetClient(), Recorder: recorder}
				if err := releases.SetupWithManager(mgr); err != nil {
					return fmt.Errorf("set up release controller: %w", err)
				}
			}
			if topologyEnabled {
				topologies := &topology.Reconciler{Client: mgr.GetClient(), Namespace: topologyNamespace}
				if err := topologies.SetupWithManager(mgr); err != nil {
					return fmt.Errorf("set up topology controller: %w", err)
				}
				endpoints := &topology.EndpointReconciler{Client: mgr.GetClient(), Namespace: topologyNamespace}
				if err := endpoints.SetupWithManager(mgr); err != nil {
					return fmt.Errorf("set up endpoint controller: %w", err)
				}
			}
			// The leader exports the fleet's state from its cache beside
			// controller-runtime's own metrics.
			fleet := &routingmetrics.Collector{Reader: mgr.GetClient(), Rollout: rolloutEnabled}
			if err := ctrlmetrics.Registry.Register(fleet); err != nil {
				return fmt.Errorf("register fleet metrics: %w", err)
			}
			if err := mgr.Add(fleet); err != nil {
				return fmt.Errorf("add fleet metrics: %w", err)
			}
			if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
				return err
			}
			if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
				return err
			}
			return mgr.Start(cmd.Context())
		},
	}
	cmd.Flags().StringVar(&metricsAddress, "metrics-bind-address", ":8080", "Metrics endpoint address")
	cmd.Flags().StringVar(&healthAddress, "health-probe-bind-address", ":8081", "Health probe address")
	cmd.Flags().BoolVar(&leaderElect, "leader-elect", true, "Run one active replica, elected through a lease")
	cmd.Flags().BoolVar(&rolloutEnabled, "rollout", false,
		"Give compiled routers FabricRouterDeployments and run FabricReleaseAuthorizations")
	cmd.Flags().BoolVar(&topologyEnabled, "topology", false,
		"Generate BGPPeers from FabricTopologies and FabricEndpoints")
	cmd.Flags().StringVar(&topologyNamespace, "topology-namespace", "galactic-system",
		"The only namespace whose FabricTopologies and FabricEndpoints --topology serves")
	cmd.Flags().StringVar(&namespace, "leader-election-namespace", "galactic-system", "Namespace of the lease")
	return cmd
}
