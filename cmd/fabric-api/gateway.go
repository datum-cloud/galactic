// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"time"

	"github.com/go-logr/logr"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	fabricv1 "go.datum.net/galactic/api/fabric/v1"
	fabricapi "go.datum.net/galactic/internal/fabric/api/v1alpha1"
	"go.datum.net/galactic/internal/fabric/gateway"
	"go.datum.net/galactic/internal/fabric/identity"
	"go.datum.net/galactic/internal/fabric/node"
	"go.datum.net/galactic/internal/fabric/query"
	"go.datum.net/galactic/internal/metadata"
)

type gatewayOptions struct {
	site, clusterName, cell       string
	namespace, podName, podIP     string
	podSelector, certsSelector    string
	leaseName                     string
	debugPort                     int
	metricsAddress, healthAddress string
	tls                           tlsFlags
	slots, expensiveSlots, queue  int
	maxNodes, maxObjectBytes      int
	maxNodeResponseBytes          int
	maxInFlight                   int
	retention, cleanupGrace       time.Duration
}

func newGatewayCommand() *cobra.Command {
	o := &gatewayOptions{}
	cmd := &cobra.Command{
		Use:   "gateway",
		Short: "Execute this cell's FabricQuery objects and serve the operator debug service",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runGateway(cmd.Context(), o)
		},
	}
	f := cmd.Flags()
	f.StringVar(&o.site, "site", envOr("SITE", ""), "Site this cell serves (required; env SITE)")
	f.StringVar(&o.clusterName, "cluster-name", envOr("CLUSTER_NAME", ""),
		"This cell's Karmada member cluster name (required; env CLUSTER_NAME)")
	f.StringVar(&o.cell, "cell", envOr("CELL", ""), "Cell name in the mTLS identities (required; env CELL)")
	f.StringVar(&o.namespace, "namespace", envOr("POD_NAMESPACE", gateway.DefaultNamespace),
		"Namespace of the fabric-router pods, the election lease and this pod (env POD_NAMESPACE)")
	f.StringVar(&o.podName, "pod-name", envOr("POD_NAME", ""), "This pod's name (required; env POD_NAME)")
	f.StringVar(&o.podIP, "debug-bind-address", "",
		"Address the debug service binds to; empty binds every address in the pod's network namespace, which "+
			"kubectl port-forward (via the pod's loopback) and the Service both need")
	f.StringVar(&o.podSelector, "pod-selector", gateway.DefaultPodSelector, "Label selector of fabric-router pods")
	f.StringVar(&o.certsSelector, "certs-selector", gateway.DefaultCertsSelector,
		"Label selector of the per-node fabric-api-certs pods whose identity each sidecar presents")
	f.StringVar(&o.leaseName, "lease-name", "fabric-api-gateway", "Leader election lease name")
	f.IntVar(&o.debugPort, "debug-port", 9346, "Operator debug gRPC port")
	f.StringVar(&o.metricsAddress, "metrics-bind-address", ":9347", "Address serving /metrics")
	f.StringVar(&o.healthAddress, "health-probe-bind-address", ":8081", "Address serving /healthz and /readyz")
	o.tls.register(cmd, defaultTLSDir)
	f.IntVar(&o.slots, "cell-slots", 8, "Node RPCs running at once across all queries")
	f.IntVar(&o.expensiveSlots, "cell-expensive-slots", 2, "Of those, expensive searches")
	f.IntVar(&o.queue, "cell-queue", 256, "Node RPCs that may wait for a slot")
	f.IntVar(&o.maxNodes, "max-nodes", query.Ceilings.MaxNodes, "Nodes one query executes on in this cell")
	f.IntVar(&o.maxObjectBytes, "max-object-bytes", query.Ceilings.MaxObjectBytes, "Serialized FabricQuery size ceiling")
	f.IntVar(&o.maxNodeResponseBytes, "max-node-response-bytes", query.Ceilings.MaxNodeResponseBytes,
		"Node response ceiling")
	f.IntVar(&o.maxInFlight, "max-in-flight", 256, "Queries executing at once")
	f.DurationVar(&o.retention, "retention", gateway.DefaultRetention,
		"Retention the stale-object count assumes; keep equal to the janitor's --retention")
	f.DurationVar(&o.cleanupGrace, "cleanup-grace", gateway.DefaultCleanupGrace,
		"Cleanup grace the stale-object count assumes; keep equal to the janitor's --grace")
	return cmd
}

func runGateway(parent context.Context, o *gatewayOptions) error {
	required := map[string]string{
		"site":         o.site,
		"cluster-name": o.clusterName,
		"cell":         o.cell,
		"pod-name":     o.podName,
	}
	for name, v := range required {
		if v == "" {
			return fmt.Errorf("--%s is required", name)
		}
	}
	sel, err := labels.Parse(o.podSelector)
	if err != nil {
		return fmt.Errorf("--pod-selector: %w", err)
	}
	certsSel, err := labels.Parse(o.certsSelector)
	if err != nil {
		return fmt.Errorf("--certs-selector: %w", err)
	}
	ctx, stop := signalContext(parent)
	defer stop()
	defer setupTracing(ctx, "gateway")()
	ctrl.SetLogger(logr.FromSlogHandler(slog.Default().Handler()))

	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(fabricapi.AddToScheme(scheme))

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                        scheme,
		Metrics:                       metricsserver.Options{BindAddress: o.metricsAddress},
		HealthProbeBindAddress:        o.healthAddress,
		LeaderElection:                true,
		LeaderElectionID:              o.leaseName,
		LeaderElectionNamespace:       o.namespace,
		LeaderElectionReleaseOnCancel: true,
		// Pods are cached only in the fabric-router namespace; FabricQuery
		// is cached cluster-wide since NSO writes it into each project's
		// mapped namespace.
		Cache: cache.Options{ByObject: map[client.Object]cache.ByObject{
			&corev1.Pod{}: {Namespaces: map[string]cache.Config{o.namespace: {}}},
		}},
	})
	if err != nil {
		return fmt.Errorf("create manager: %w", err)
	}
	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		return err
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		return err
	}

	executor := gateway.NewExecutor(o.slots, o.expensiveSlots, o.queue)
	metrics := gateway.NewMetrics(ctrlmetrics.Registry, func() float64 { return float64(executor.Depth()) })
	executor.ObserveWait = func(d time.Duration) { metrics.QueueWait(d.Seconds()) }
	creds := o.tls.credentials(identity.Gateway(o.cell))
	creds.OnLoad(func(leaf *x509.Certificate) { metrics.CertificateExpiry(float64(leaf.NotAfter.Unix())) })
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			if err := creds.Reload(); err != nil {
				slog.Warn("fabric-api credentials unavailable", "error", err)
			}
			metrics.CredentialsLoaded(creds.Err() == nil)
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	}()

	pool := &gateway.Pool{
		Credentials: creds,
		Cell:        o.cell,
		Namespace:   o.namespace,
		DialOptions: []grpc.DialOption{clientStats()},
	}
	defer pool.Close()
	ceilings := query.Budgets{
		MaxNodes:             o.maxNodes,
		MaxObjectBytes:       o.maxObjectBytes,
		MaxNodeResponseBytes: o.maxNodeResponseBytes,
	}.Clamp()
	discoverer := &gateway.Discoverer{
		Reader: mgr.GetClient(), Namespace: o.namespace, Selector: sel, CertsSelector: certsSel,
	}
	runner := &gateway.Runner{Clients: pool, Executor: executor, Metrics: metrics}
	rec := &gateway.Reconciler{
		Client:      mgr.GetClient(),
		APIReader:   mgr.GetAPIReader(),
		Site:        o.site,
		ClusterName: o.clusterName,
		Discoverer: &gateway.Discoverer{
			Reader:        discoveryReader{cached: mgr.GetClient(), api: mgr.GetAPIReader()},
			Namespace:     o.namespace,
			Selector:      sel,
			CertsSelector: certsSel,
		},
		Runner:      runner,
		Pool:        pool,
		Ceilings:    ceilings,
		MaxInFlight: o.maxInFlight,
		Metrics:     metrics,
	}
	if err := mgr.Add(&gateway.StaleCounter{Reader: mgr.GetClient(), Metrics: metrics,
		Retention: o.retention, Grace: o.cleanupGrace}); err != nil {
		return err
	}
	if err := rec.SetupWithManager(mgr); err != nil {
		return fmt.Errorf("set up reconciler: %w", err)
	}

	debug := &gateway.Debug{
		Discoverer:  discoverer,
		Runner:      runner,
		Ceilings:    ceilings,
		Elected:     electedFunc(mgr.Elected()),
		Reader:      mgr.GetAPIReader(),
		Namespace:   o.namespace,
		LeaseName:   o.leaseName,
		PodName:     o.podName,
		Port:        o.debugPort,
		Credentials: creds,
		Cell:        o.cell,
		DialOptions: []grpc.DialOption{clientStats()},
	}
	gs := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(creds.ServerConfig(gateway.AllowedDebugCaller))),
		grpc.ChainUnaryInterceptor(node.AuthInterceptor(gateway.DebugMethods)),
		grpc.MaxRecvMsgSize(64<<10),
		serverStats(),
	)
	fabricv1.RegisterFabricGatewayServiceServer(gs, debug)
	debugAddr := fmt.Sprintf(":%d", o.debugPort)
	if o.podIP != "" {
		debugAddr = net.JoinHostPort(o.podIP, strconv.Itoa(o.debugPort))
	}
	lis, err := (&net.ListenConfig{}).Listen(ctx, "tcp", debugAddr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", debugAddr, err)
	}
	go func() {
		if err := gs.Serve(lis); err != nil {
			slog.Error("debug server exited", "error", err)
		}
	}()
	defer gs.Stop()

	slog.Info("starting fabric-api gateway", "version", metadata.Version, "site", o.site, "cluster", o.clusterName,
		"cell", o.cell, "debug", debugAddr)
	return mgr.Start(ctx)
}

// electedFunc reports whether the elected channel has closed.
func electedFunc(elected <-chan struct{}) func() bool {
	return func() bool {
		select {
		case <-elected:
			return true
		default:
			return false
		}
	}
}

// discoveryReader reads pods from the cache and nodes from the API server,
// so the gateway never caches every Node in the cluster for a selector that
// is rarely set.
type discoveryReader struct {
	cached client.Reader
	api    client.Reader
}

func (d discoveryReader) Get(
	ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption,
) error {
	if _, ok := obj.(*corev1.Node); ok {
		return d.api.Get(ctx, key, obj, opts...)
	}
	return d.cached.Get(ctx, key, obj, opts...)
}

func (d discoveryReader) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	return d.cached.List(ctx, list, opts...)
}
