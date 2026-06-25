// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Command galactic-router is the BGP control-plane reconciler for the Galactic
// data plane. It watches Cosmos BGP CRDs and drives a BGP runtime backend
// (GoBGP for tenant role, FRR stub for fabric role).
package main

import (
	"context"
	"log"
	"net"
	"os"
	"strconv"
	"time"

	bgpv1alpha1 "go.miloapis.com/cosmos/api/bgp/v1alpha1"
	"google.golang.org/grpc"
	grpchealth "google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"go.datum.net/galactic/internal/controller"
	"go.datum.net/galactic/internal/hash"
	"go.datum.net/galactic/internal/reconcile"
	galacticruntime "go.datum.net/galactic/internal/runtime"
	"go.datum.net/galactic/internal/runtime/frr"
	"go.datum.net/galactic/internal/runtime/gobgp"
)

func main() {
	nodeName := os.Getenv("NODE_NAME")
	routerRole := os.Getenv("ROUTER_ROLE")
	if nodeName == "" {
		log.Fatal("NODE_NAME environment variable is required")
	}
	if routerRole == "" {
		log.Fatal("ROUTER_ROLE environment variable is required")
	}

	bgpListenPort := int32(179)
	if v := os.Getenv("BGP_LISTEN_PORT"); v != "" {
		p, err := strconv.ParseInt(v, 10, 32)
		if err != nil || p < -1 || p > 65535 {
			log.Fatalf("BGP_LISTEN_PORT must be -1 or a valid port number, got %q", v)
		}
		bgpListenPort = int32(p)
	}

	bgpLocalAddr := os.Getenv("BGP_LOCAL_ADDRESS")

	var factory galacticruntime.RuntimeFactory
	switch routerRole {
	case "tenant":
		factory = gobgp.NewRuntimeFactory(bgpListenPort, bgpLocalAddr)
	case "fabric":
		factory = frr.NewRuntimeFactory()
	default:
		log.Fatalf("ROUTER_ROLE must be 'tenant' or 'fabric', got %q", routerRole)
	}

	ctrl.SetLogger(zap.New(zap.UseDevMode(true)))

	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(bgpv1alpha1.AddToScheme(scheme))

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		HealthProbeBindAddress: "0",
		Metrics: metricsserver.Options{
			BindAddress: ":8080",
		},
	})
	if err != nil {
		log.Fatalf("create manager: %v", err)
	}

	ctx := ctrl.SetupSignalHandler()

	// Start gRPC health server on :5000.
	lis, err := net.Listen("tcp", ":5000")
	if err != nil {
		log.Fatalf("listen on :5000: %v", err)
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

	// Pre-flight RBAC check: verify list+watch permission for every type the
	// manager will watch. A missing permission silently blocks cache sync and
	// prevents all reconcilers from starting.
	checkWatchPermissions(mgr)

	// Register field indexes.
	if err := controller.RegisterIndexes(ctx, mgr); err != nil {
		log.Fatalf("register field indexes: %v", err)
	}

	// Create runtime manager.
	runtimeMgr := galacticruntime.NewRuntimeManager(factory)

	// Create reconciler.
	rec := reconcile.New(mgr.GetClient(), nodeName, routerRole)

	// Register BGPRouter controller (main reconcile loop).
	if err := (&controller.BGPRouterReconciler{
		Client:         mgr.GetClient(),
		Scheme:         mgr.GetScheme(),
		Reconciler:     rec,
		RuntimeManager: runtimeMgr,
		Hasher:         hash.DesiredRouter,
		NodeName:       nodeName,
		RouterRole:     routerRole,
	}).SetupWithManager(mgr); err != nil {
		log.Fatalf("setup BGPRouter controller: %v", err)
	}

	// Register BGPPeer controller (enqueues owning router).
	if err := (&controller.BGPPeerReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		log.Fatalf("setup BGPPeer controller: %v", err)
	}

	// Register BGPAdvertisement controller.
	if err := (&controller.BGPAdvertisementReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		log.Fatalf("setup BGPAdvertisement controller: %v", err)
	}

	// Register BGPVRFInstance controller.
	if err := (&controller.BGPVRFInstanceReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		log.Fatalf("setup BGPVRFInstance controller: %v", err)
	}

	// Register BGPPolicy controller.
	if err := (&controller.BGPPolicyReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		log.Fatalf("setup BGPPolicy controller: %v", err)
	}

	// Register Secret controller.
	if err := (&controller.SecretReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		log.Fatalf("setup Secret controller: %v", err)
	}

	// Register Node controller.
	if err := (&controller.NodeReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		log.Fatalf("setup Node controller: %v", err)
	}

	if err := mgr.Start(ctx); err != nil {
		log.Fatalf("manager exited: %v", err)
	}
}

// checkWatchPermissions issues a list request for each resource type the
// manager watches. If any return a Forbidden error the informer cache will
// never sync and all reconcilers will be silently blocked; this logs a
// clear, actionable message at startup so the problem is immediately obvious.
func checkWatchPermissions(mgr ctrl.Manager) {
	c, err := client.New(mgr.GetConfig(), client.Options{Scheme: mgr.GetScheme()})
	if err != nil {
		ctrl.Log.Error(err, "RBAC pre-flight: cannot create client, skipping check")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	logger := ctrl.Log.WithName("rbac-preflight")

	watched := []client.ObjectList{
		&bgpv1alpha1.BGPRouterList{},
		&bgpv1alpha1.BGPPeerList{},
		&bgpv1alpha1.BGPAdvertisementList{},
		&bgpv1alpha1.BGPPolicyList{},
		&bgpv1alpha1.BGPVRFInstanceList{},
		&corev1.SecretList{},
		&corev1.NodeList{},
	}

	for _, objList := range watched {
		if err := c.List(ctx, objList, client.Limit(1)); err != nil {
			if apierrors.IsForbidden(err) {
				logger.Error(err, "missing list+watch RBAC",
					"detail", "informer cache will not sync; add resource to ServiceAccount ClusterRole and restart")
			}
		}
	}
}
