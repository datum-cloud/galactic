// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"time"

	"github.com/go-logr/logr"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"google.golang.org/grpc"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/uuid"
	"k8s.io/client-go/kubernetes"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	fabricapi "go.datum.net/galactic/internal/fabric/api/v1alpha1"
	"go.datum.net/galactic/internal/fabric/gateway"
	"go.datum.net/galactic/internal/fabric/gateway/limit"
	"go.datum.net/galactic/internal/fabric/identity"
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
	serviceIdentities             []string
	serviceConfigMap              string
	aggregateBudgets              bool
	limits                        limit.Limits
}

func newGatewayCommand() *cobra.Command {
	o := &gatewayOptions{}
	cmd := &cobra.Command{
		Use:   "gateway",
		Short: "Execute this cell's FabricQuery objects and serve the operator debug service",
		RunE: func(cmd *cobra.Command, _ []string) error {
			limits, err := gatewayLimits(cmd.Flags(), o)
			if err != nil {
				return err
			}
			o.limits = limits
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
	f.StringSliceVar(&o.serviceIdentities, "service-identities", nil,
		"Names of the Looking Glass service identities (spiffe://fabric-api.datumapis.com/cell/<cell>/service/<name>) "+
			"allowed to call this cell's gateway; empty allows none")
	f.StringVar(&o.serviceConfigMap, "service-config-map", "",
		"ConfigMap in --namespace whose key \"service\" turns Looking Glass execution on (\"enabled\") or off "+
			"(\"disabled\") while the gateway runs, read every second; empty, missing, unreadable or any other "+
			"value keeps it off. Execution also needs --aggregate-budgets")
	f.BoolVar(&o.aggregateBudgets, "aggregate-budgets", false,
		"Enforce the cell's aggregate admission and probe packet budgets on every caller, issue probe permits to "+
			"nodes, and bound each principal's share of --cell-slots and --cell-queue; every node must run with "+
			"--probe-permits first")
	registerLimitFlags(f, &o.limits)
	return cmd
}

// limitFlags are the aggregate limits an operator may lower, each
// defaulting to the contract's qualified value, which is also its ceiling.
var limitFlags = []string{
	"request-cell-rate", "request-cell-burst", "request-project-rate", "request-project-burst",
	"packet-cell-rate", "packet-cell-burst", "packet-principal-rate", "packet-principal-burst",
	"packet-host-rate", "packet-host-burst", "packet-prefix-rate", "packet-prefix-burst",
	"principal-slots", "principal-queue", "service-streams", "project-streams", "queue-wait",
}

func registerLimitFlags(f *pflag.FlagSet, l *limit.Limits) {
	*l = limit.Defaults()
	rate := func(name, what string, r *limit.Rate) {
		f.Float64Var(&r.PerSecond, name+"-rate", r.PerSecond, what+" tokens per second; may only be lowered")
		f.Float64Var(&r.Burst, name+"-burst", r.Burst, what+" bucket size; may only be lowered")
	}
	rate("request-cell", "Looking Glass requests admitted in the cell:", &l.RequestCell)
	rate("request-project", "Looking Glass requests admitted per project:", &l.RequestProject)
	rate("packet-cell", "Worst-case probe packets charged in the cell:", &l.PacketCell)
	rate("packet-principal", "Worst-case probe packets charged per project, FabricQuery source or operator:",
		&l.PacketPrincipal)
	rate("packet-host", "Worst-case probe packets charged per destination address:", &l.PacketHost)
	rate("packet-prefix", "Worst-case probe packets charged per destination IPv4 /24 or IPv6 /64:", &l.PacketPrefix)
	f.IntVar(&l.PrincipalSlots, "principal-slots", l.PrincipalSlots,
		"Of --cell-slots, node jobs one principal may run at once; may only be lowered")
	f.IntVar(&l.PrincipalQueue, "principal-queue", l.PrincipalQueue,
		"Of --cell-queue, node jobs one principal may queue; may only be lowered")
	f.IntVar(&l.Streams, "service-streams", l.Streams,
		"Live Looking Glass streams in the cell, queued and draining ones included; may only be lowered")
	f.IntVar(&l.ProjectStreams, "project-streams", l.ProjectStreams,
		"Live Looking Glass streams per project; may only be lowered")
	f.DurationVar(&l.QueueWait, "queue-wait", l.QueueWait,
		"How long a Looking Glass router job or a direct operator's permit may wait for a slot; may only be lowered")
}

// gatewayLimits returns the aggregate limits the flags select, refusing
// limit flags or --service-config-map without --aggregate-budgets, a limit
// above its qualified ceiling and limits that break a cross-field rule. A
// principal's slots, queue and streams default to at most the cell's.
func gatewayLimits(f *pflag.FlagSet, o *gatewayOptions) (limit.Limits, error) {
	if !o.aggregateBudgets {
		if o.serviceConfigMap != "" {
			return limit.Limits{}, errors.New("--service-config-map needs --aggregate-budgets: the service " +
				"executes only under the cell's aggregate budgets")
		}
		for _, name := range limitFlags {
			if f.Changed(name) {
				return limit.Limits{}, fmt.Errorf("--%s needs --aggregate-budgets", name)
			}
		}
		return limit.Limits{}, nil
	}
	l := o.limits
	l.Slots, l.Queue = o.slots, o.queue
	if !f.Changed("principal-slots") {
		l.PrincipalSlots = min(l.PrincipalSlots, o.slots)
	}
	if !f.Changed("principal-queue") {
		l.PrincipalQueue = min(l.PrincipalQueue, o.queue)
	}
	if !f.Changed("project-streams") {
		l.ProjectStreams = min(l.ProjectStreams, l.Streams)
	}
	if err := errors.Join(l.Qualified(), l.Validate()); err != nil {
		return limit.Limits{}, fmt.Errorf("--aggregate-budgets: %w", err)
	}
	return l, nil
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
	allowlist, err := gateway.ParseAllowlist(o.serviceIdentities)
	if err != nil {
		return fmt.Errorf("--service-identities: %w", err)
	}
	ctx, stop := signalContext(parent)
	defer stop()
	defer setupTracing(ctx, "gateway")()
	ctrl.SetLogger(logr.FromSlogHandler(slog.Default().Handler()))

	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(fabricapi.AddToScheme(scheme))

	restConfig := ctrl.GetConfigOrDie()
	// The election identity is this process's own, "<pod>_<uuid>", so the
	// limiter can recognise the Lease as its own and no later process
	// reuses it.
	holder := o.podName + "_" + string(uuid.NewUUID())
	kc, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		return fmt.Errorf("kubernetes client: %w", err)
	}
	lock, err := resourcelock.New(resourcelock.LeasesResourceLock, o.namespace, o.leaseName, kc.CoreV1(),
		kc.CoordinationV1(), resourcelock.ResourceLockConfig{Identity: holder})
	if err != nil {
		return fmt.Errorf("election lock: %w", err)
	}
	mgr, err := ctrl.NewManager(restConfig, ctrl.Options{
		Scheme:                              scheme,
		Metrics:                             metricsserver.Options{BindAddress: o.metricsAddress},
		HealthProbeBindAddress:              o.healthAddress,
		LeaderElection:                      true,
		LeaderElectionID:                    o.leaseName,
		LeaderElectionNamespace:             o.namespace,
		LeaderElectionReleaseOnCancel:       true,
		LeaderElectionResourceLockInterface: lock,
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
	var admission *gateway.Admission
	if o.aggregateBudgets {
		admission, err = gateway.NewAdmission(o.limits, &limit.Authority{
			Reader: mgr.GetAPIReader(), Namespace: o.namespace, Name: o.leaseName, Identity: holder,
			Clock: limit.KernelClock,
		})
		if err != nil {
			return fmt.Errorf("--aggregate-budgets: %w", err)
		}
		executor.PrincipalSlots, executor.PrincipalQueue = o.limits.PrincipalSlots, o.limits.PrincipalQueue
		go admission.Authority.Watch(ctx, limit.WatchInterval)
	}
	serviceSwitch := &gateway.ServiceSwitch{}
	if o.serviceConfigMap != "" {
		go serviceSwitch.Watch(ctx, mgr.GetAPIReader(), o.namespace, o.serviceConfigMap, gateway.ServiceSwitchInterval)
	}
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
	runner := &gateway.Runner{Clients: pool, Executor: executor, Metrics: metrics, Admission: admission,
		QueueWait: o.limits.QueueWait}
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
	// The service executes only while serviceSwitch is on and admission
	// enforces the aggregate budgets; otherwise it authenticates, validates
	// and reports capabilities, and refuses execution with ServiceDisabled.
	service := &gateway.Service{
		Cell:      o.cell,
		Switch:    serviceSwitch,
		Allowlist: allowlist,
		Elected:   debug.Elected,
		Leader:    debug,
		Discoverer: &gateway.Discoverer{
			Reader: mgr.GetAPIReader(), Namespace: o.namespace, Selector: sel, CertsSelector: certsSel,
		},
		Runner:    runner,
		Admission: admission,
		Revision:  metadata.GitCommit,
	}
	permits := &gateway.Permits{
		Admission: admission, Executor: executor, Discoverer: discoverer, Elected: debug.Elected, Leader: debug,
	}
	gs := gateway.NewServer(creds, allowlist, debug, service, permits, grpc.MaxRecvMsgSize(64<<10), serverStats())
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
	// A shutdown signal closes every connection at once, so a service
	// stream's routers stop within 2 s rather than running on while the
	// manager shuts down.
	defer context.AfterFunc(ctx, gs.Stop)()

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
