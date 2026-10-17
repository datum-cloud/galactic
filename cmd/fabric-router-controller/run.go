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
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	networkv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	"go.datum.net/galactic/internal/fabric/routing/controller"
	"go.datum.net/galactic/internal/fabric/routing/rollout"
)

// leaderElectionID is the lease the controller's replicas share.
const leaderElectionID = "fabric-router-controller.galactic.datumapis.com"

func newRunCommand() *cobra.Command {
	var (
		metricsAddress, healthAddress, namespace string
		leaderElect                              bool
	)
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Compile fabric routers into revisions and roll them out",
		Long: `Watches the BGPRouters whose class names this controller and every object
their configuration reads, and creates an immutable FabricRouterRevision
for each router's current inputs. It reports Accepted and ResolvedRefs on
the router and keeps its newest revisions and every revision a deployment
uses.

It also gives each compiled router a FabricRouterDeployment, keeps its
candidate on the newest revision, and runs FabricReleaseAuthorizations:
one release per routing domain at a time, promoting within each router's
FabricRolloutPolicy. It never writes FRR; the node agents do.`,
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
			recorder := mgr.GetEventRecorder("fabric-router-controller")
			if err := (&rollout.DeploymentReconciler{Client: mgr.GetClient(),
				Recorder: recorder}).SetupWithManager(mgr); err != nil {
				return fmt.Errorf("set up deployment controller: %w", err)
			}
			if err := (&rollout.ReleaseReconciler{Client: mgr.GetClient(),
				Recorder: recorder}).SetupWithManager(mgr); err != nil {
				return fmt.Errorf("set up release controller: %w", err)
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
	cmd.Flags().StringVar(&namespace, "leader-election-namespace", "galactic-system", "Namespace of the lease")
	return cmd
}
