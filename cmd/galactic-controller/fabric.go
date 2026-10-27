// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os/signal"
	"syscall"

	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/clientcmd"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cluster"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	cloudv1alpha1 "go.datum.net/galactic/api/cloud/v1alpha1"
	cloudcontroller "go.datum.net/galactic/internal/cloud/controller"
	"go.datum.net/galactic/internal/cloud/ipam"
	"go.datum.net/galactic/internal/cloud/leaderelection"
	networkingv1alpha "go.datum.net/network-services-operator/api/v1alpha"
)

// runFabric runs the central identity allocator using the same Galactic
// controller binary. Its manager lease remains local while its data is on the
// federation hub, so it needs a separate deployment from the cell role.
func runFabric(parent context.Context, o *options) error {
	if o.identityClass == "" || o.platformProject == "" || o.ipamKubeconfig == "" || o.hubKubeconfig == "" {
		return errors.New("fabric role requires --identity-class, --platform-project, --ipam-kubeconfig and --hub-kubeconfig")
	}
	if parent == nil {
		parent = context.Background()
	}
	ctx, stop := signal.NotifyContext(parent, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	scheme := runtime.NewScheme()
	for _, register := range []func(*runtime.Scheme) error{
		clientgoscheme.AddToScheme, cloudv1alpha1.AddToScheme, networkingv1alpha.AddToScheme,
	} {
		if err := register(scheme); err != nil {
			return fmt.Errorf("register fabric API: %w", err)
		}
	}
	hubConfig, err := clientcmd.BuildConfigFromFlags("", o.hubKubeconfig)
	if err != nil {
		return fmt.Errorf("load federation hub kubeconfig: %w", err)
	}
	localConfig := ctrl.GetConfigOrDie()
	mgr, err := ctrl.NewManager(localConfig, ctrl.Options{
		Scheme:                        scheme,
		Metrics:                       metricsserver.Options{BindAddress: o.metricsAddress},
		HealthProbeBindAddress:        o.healthAddress,
		LeaderElection:                o.leaderElect,
		LeaderElectionID:              "galactic-controller-fabric",
		LeaderElectionNamespace:       o.namespace,
		LeaderElectionConfig:          leaderelection.RestConfig(localConfig),
		LeaderElectionReleaseOnCancel: true,
	})
	if err != nil {
		return fmt.Errorf("create fabric manager: %w", err)
	}
	ipamConfig, err := clientcmd.BuildConfigFromFlags("", o.ipamKubeconfig)
	if err != nil {
		return fmt.Errorf("load IPAM kubeconfig: %w", err)
	}
	ipamScheme, err := ipam.Scheme()
	if err != nil {
		return fmt.Errorf("build IPAM scheme: %w", err)
	}
	ipamClients, err := ipam.NewClientFactory(ipamConfig, ipamScheme, o.platformProject)
	if err != nil {
		return fmt.Errorf("build IPAM client factory: %w", err)
	}
	hub, err := cluster.New(hubConfig, func(options *cluster.Options) { options.Scheme = scheme })
	if err != nil {
		return fmt.Errorf("create federation hub client: %w", err)
	}
	if err := mgr.Add(hub); err != nil {
		return fmt.Errorf("add federation hub cache: %w", err)
	}
	if err := (&cloudcontroller.NetworkFabricIdentityReconciler{
		Networks: hub.GetClient(), Hub: hub.GetClient(), HubCluster: hub,
		IPAM: ipamClients, IdentityClass: o.identityClass, IdentityNamespace: o.identityNamespace,
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("set up fabric identity controller: %w", err)
	}
	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		return err
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		return err
	}
	slog.Info("starting galactic-controller", "role", RoleFabric)
	return mgr.Start(ctx)
}
