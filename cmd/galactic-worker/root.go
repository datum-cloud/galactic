// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
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
	"sigs.k8s.io/controller-runtime/pkg/client"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	workerv1alpha1 "go.datum.net/galactic/api/galactic/worker/v1alpha1"
	"go.datum.net/galactic/internal/config"
	"go.datum.net/galactic/internal/edge/maintenance"
	"go.datum.net/galactic/internal/gc"
	"go.datum.net/galactic/internal/logging"
	"go.datum.net/galactic/internal/metadata"
	"go.datum.net/galactic/internal/nodelocator"
	"go.datum.net/galactic/internal/ownership"
	"go.datum.net/galactic/internal/plumbing/ebpf/attach"
	"go.datum.net/galactic/internal/plumbing/ebpf/localprog"
	"go.datum.net/galactic/internal/plumbing/ebpf/xdpdispatch"
	"go.datum.net/galactic/internal/worker"
	"go.datum.net/galactic/internal/worker/auth"
	"go.datum.net/galactic/internal/worker/diag"
	"go.datum.net/galactic/internal/worker/fabric"
	"go.datum.net/galactic/internal/worker/hostscope"
	"go.datum.net/galactic/internal/worker/local"
	"go.datum.net/galactic/internal/worker/module"
	"go.datum.net/galactic/internal/worker/routes"
	"go.datum.net/galactic/internal/worker/sources"
	"go.datum.net/galactic/internal/worker/store"
)

const (
	appName = "galactic-worker"
	appDesc = `Galactic Worker: node-local delivery API for tenant services

 Find more information at: https://www.datum.net/docs`

	defaultMetricsPort    = 9104
	defaultHealthPort     = 9105
	cacheSyncTimeout      = 2 * time.Minute
	envNodeName           = "NODE_NAME"
	socketGroupNoneOption = -1
)

// options are the command's flags.
type options struct {
	nodeName       string
	namespace      string
	gatewayNS      string
	socket         string
	socketGroup    int
	stateDir       string
	ownershipDir   string
	allowlist      string
	procRoot       string
	metricsPort    int
	healthPort     int
	lease          time.Duration
	renewInterval  time.Duration
	claimLimit     int
	resyncInterval time.Duration
	pinDir         string
	localPinDir    string
	dispatchDir    string
	hostGrace      time.Duration
	statusFile     string
}

func (o *options) validate() error {
	var errs []error
	if o.nodeName == "" {
		errs = append(errs, fmt.Errorf("--node-name (or %s) is required", envNodeName))
	}
	if o.gatewayNS == "" {
		errs = append(errs, errors.New("--gateway-namespace must not be empty"))
	}
	if o.allowlist == "" {
		errs = append(errs, errors.New("--allowlist is required"))
	}
	if o.hostGrace <= 0 {
		errs = append(errs, errors.New("--host-grace must be positive"))
	}
	if o.claimLimit < 1 {
		errs = append(errs, errors.New("--claim-limit must be at least 1"))
	}
	if o.renewInterval <= 0 || o.lease <= o.renewInterval {
		errs = append(errs, errors.New("--lease must be longer than --renew-interval, which must be positive"))
	}
	return errors.Join(errs...)
}

func run(o *options) error {
	allow, err := auth.LoadAllowlist(o.allowlist)
	if err != nil {
		return err
	}
	st, err := store.Open(o.stateDir)
	if err != nil {
		return err
	}
	// The fence directory is shared with every other writer on the node,
	// so it must already exist rather than be created privately here.
	fence, err := ownership.Open(o.ownershipDir)
	if err != nil {
		return err
	}
	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(sources.AddToScheme(scheme))
	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		HealthProbeBindAddress: "0",
		Metrics:                metricsserver.Options{BindAddress: fmt.Sprintf(":%d", o.metricsPort)},
	})
	if err != nil {
		return fmt.Errorf("create manager: %w", err)
	}
	worker.InitMetrics()

	ctx, cancel := context.WithCancelCause(ctrl.SetupSignalHandler())
	defer cancel(nil)

	healthLis, err := (&net.ListenConfig{}).Listen(ctx, "tcp", fmt.Sprintf(":%d", o.healthPort))
	if err != nil {
		return fmt.Errorf("listen on gRPC health port %d: %w", o.healthPort, err)
	}
	healthGRPC := grpc.NewServer()
	health := grpchealth.NewServer()
	grpc_health_v1.RegisterHealthServer(healthGRPC, health)
	health.SetServingStatus("", grpc_health_v1.HealthCheckResponse_NOT_SERVING)
	health.SetServingStatus(config.GRPCReadinessService, grpc_health_v1.HealthCheckResponse_NOT_SERVING)
	go func() {
		if err := healthGRPC.Serve(healthLis); err != nil {
			cancel(fmt.Errorf("gRPC health server: %w", err))
		}
	}()
	defer healthGRPC.GracefulStop()

	if err := sources.RegisterIndexes(ctx, mgr.GetFieldIndexer()); err != nil {
		return err
	}
	// TokenReview is a create, which the cache never serves.
	direct, err := client.New(mgr.GetConfig(), client.Options{Scheme: scheme})
	if err != nil {
		return fmt.Errorf("create API client: %w", err)
	}
	// Edge attachments keep their VPC's host state; without the guard Worker
	// knows of none, so it reclaims nothing (gc.EdgeUsers).
	var edge gc.EdgeUsers
	if guard, err := maintenance.NewGuard(direct, o.nodeName, o.ownershipDir); err != nil {
		slog.Error("edge attachment guard unavailable: Worker will reclaim no VPC host state", "error", err)
		edge = maintenance.Unavailable{Err: err}
	} else {
		edge = guard
	}
	// The tenant routes galactic-router hands Worker, which the Fabric
	// module writes.
	tenantRoutes := routes.New()
	fabricDatapath := &fabric.Kernel{PinDir: o.pinDir, K8s: direct, Namespace: o.namespace, Node: o.nodeName}
	defer func() { _ = fabricDatapath.Close() }()
	fab, err := fabric.New(fabric.Config{
		Routes:   tenantRoutes,
		Datapath: fabricDatapath,
		OwnLocator: func(ctx context.Context) (netip.Prefix, error) {
			return nodelocator.Prefix(ctx, mgr.GetClient(), o.namespace, o.nodeName)
		},
		Log: slog.Default(),
	})
	if err != nil {
		return err
	}
	fabric.InitMetrics()
	pods := &local.ProcPods{ProcRoot: o.procRoot, Pods: auth.CgroupPodResolver{ProcRoot: o.procRoot}}
	shards := &local.PinnedShards{PinDir: o.pinDir}
	defer func() { _ = shards.Close() }()
	localKernel := &local.Kernel{PinDir: o.pinDir, LocalPinDir: o.localPinDir, DispatchDir: o.dispatchDir,
		Shards: shards,
		Pods:   pods}
	defer func() { _ = localKernel.Close() }()
	// Routed links and sockets need capabilities only a placement that
	// enables them grants; without them those capabilities report why.
	podAccess := local.PodAccess()
	if podAccess != nil {
		slog.Info("local.routed_link and local.socket are unavailable", "reason", podAccess.Error())
	}
	loc, err := local.New(local.Config{Kernel: localKernel, Node: o.nodeName, Log: slog.Default(),
		PodAccess: podAccess})
	if err != nil {
		return err
	}
	// The delivery modules this build runs.
	reg, err := module.NewRegistry(fab, loc)
	if err != nil {
		return err
	}
	w, err := worker.New(worker.Config{
		Node: o.nodeName, Lease: o.lease, RenewInterval: o.renewInterval,
		ClaimLimit: o.claimLimit, ResyncInterval: o.resyncInterval, HostGrace: o.hostGrace,
		StatusFile: o.statusFile,
	}, worker.Deps{
		Store:   st,
		Fence:   fence,
		Sources: sources.Kube{Reader: mgr.GetClient(), Namespace: o.namespace, GatewayNamespace: o.gatewayNS},
		Modules: reg,
		Host: &hostscope.Kernel{
			K8s: direct, Namespace: o.namespace, Node: o.nodeName, PinDir: o.pinDir, Edge: edge,
		},
		Auth: &auth.Authenticator{
			Reviewer:  auth.KubeTokenReviewer{Client: direct},
			Pods:      auth.CgroupPodResolver{ProcRoot: o.procRoot},
			Allowlist: allow,
			Node:      o.nodeName,
		},
		Routes:   tenantRoutes,
		Log:      slog.Default(),
		PodAlive: pods.Alive,
	})
	if err != nil {
		return err
	}
	if err := sources.Watch(ctx, mgr.GetCache(), w.Changed); err != nil {
		return err
	}
	// A CNI attachment's link joining or leaving a VPC's VRF requeues that
	// VPC; the periodic resync covers a lost subscription.
	if err := hostscope.Watch(ctx, w.HostChanged, func(err error) {
		slog.Error("link event subscription failed; relying on periodic resync", "error", err)
	}); err != nil {
		return err
	}
	// An underlay route or neighbor change requeues only the VPCs whose
	// tenant routes it touches; the periodic resync covers a lost
	// subscription.
	if err := fab.Watch(ctx, w.RoutesChanged, func(err error) {
		slog.Error("route and neighbor event subscription failed; relying on periodic resync", "error", err)
	}); err != nil {
		return err
	}
	// A receiving device, a pair's NAT end or a failed tenant neighbor
	// changing requeues the VPCs whose Local handoffs it touches.
	if err := loc.Watch(ctx, w.HostChanged, func(err error) {
		slog.Error("Local link and neighbor event subscription failed; relying on periodic resync", "error", err)
	}); err != nil {
		return err
	}

	mgrErr := make(chan error, 1)
	go func() { mgrErr <- mgr.Start(ctx) }()
	syncCtx, syncCancel := context.WithTimeout(ctx, cacheSyncTimeout)
	synced := mgr.GetCache().WaitForCacheSync(syncCtx)
	syncCancel()
	if !synced {
		cancel(errors.New("trusted-source cache did not sync"))
		return errors.Join(context.Cause(ctx), <-mgrErr)
	}

	// Desired state loads and reconciliation starts only once trusted
	// sources are readable, so a restart never revokes a claim against an
	// empty cache.
	if err := w.Start(ctx); err != nil {
		return err
	}
	lis, err := worker.Listen(ctx, o.socket, o.socketGroup)
	if err != nil {
		return err
	}
	srv := w.NewServer()
	go func() {
		if err := srv.Serve(lis); err != nil {
			cancel(fmt.Errorf("worker API server: %w", err))
		}
	}()
	health.SetServingStatus("", grpc_health_v1.HealthCheckResponse_SERVING)
	health.SetServingStatus(config.GRPCReadinessService, grpc_health_v1.HealthCheckResponse_SERVING)
	slog.Info("serving the Worker API", "socket", o.socket, "node", o.nodeName, "owner", w.Owner())

	err = <-mgrErr
	w.Shutdown()
	health.Shutdown()
	srv.GracefulStop()
	if cause := context.Cause(ctx); cause != nil && !errors.Is(cause, context.Canceled) {
		return errors.Join(cause, err)
	}
	return err
}

func newRootCommand() *cobra.Command {
	var logOpts logging.Options
	o := &options{}
	cmd := &cobra.Command{
		Use:   appName,
		Short: strings.Split(appDesc, "\n")[0],
		Long:  appDesc,
		PersistentPreRunE: func(*cobra.Command, []string) error {
			return logOpts.Setup()
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			if ok, _ := cmd.Flags().GetBool("build-info"); ok {
				fmt.Println(metadata.BuildInfo(appName))
				return nil
			}
			if ok, _ := cmd.Flags().GetBool("version"); ok {
				fmt.Printf("%s version %s\n", appName, metadata.Version)
				return nil
			}
			if o.nodeName == "" {
				o.nodeName = os.Getenv(envNodeName)
			}
			if err := o.validate(); err != nil {
				return err
			}
			return run(o)
		},
	}
	f := cmd.Flags()
	f.StringVar(&o.nodeName, "node-name", "", "This node's name (env "+envNodeName+")")
	f.StringVar(&o.namespace, "namespace", config.DefaultNamespace, "Namespace of the BGPRouters that carry node locators")
	f.StringVar(&o.gatewayNS, "gateway-namespace", config.DefaultNamespace,
		"Gateway namespace, whose ServiceVIPBindings resolve backend destinations (galactic-gateway's "+
			config.EnvGatewayNamespace+")")
	f.StringVar(&o.socket, "socket", workerv1alpha1.DefaultSocketPath, "Unix socket serving the Worker API")
	f.IntVar(&o.socketGroup, "socket-group", socketGroupNoneOption,
		"Numeric group that owns the socket; clients join it. -1 keeps the process's group")
	f.StringVar(&o.stateDir, "state-dir", store.DefaultDir, "Directory of durable desired state")
	f.StringVar(&o.ownershipDir, "ownership-dir", ownership.DefaultDir,
		"Ownership fence directory shared with every writer on the node; must exist")
	f.StringVar(&o.allowlist, "allowlist", "", "YAML file mapping ServiceAccounts to the capabilities they may use")
	f.StringVar(&o.procRoot, "proc-root", "/proc", "The host's /proc, for mapping a peer process to its pod")
	f.IntVar(&o.metricsPort, "metrics-port", defaultMetricsPort, "Metrics listen port")
	f.IntVar(&o.healthPort, "grpc-health-port", defaultHealthPort, "gRPC health listen port")
	f.DurationVar(&o.lease, "lease", worker.DefaultLease, "Session lease")
	f.DurationVar(&o.renewInterval, "renew-interval", worker.DefaultRenewInterval, "Session renewal interval clients use")
	f.IntVar(&o.claimLimit, "claim-limit", worker.DefaultClaimLimit, "Claims one caller may hold")
	f.DurationVar(&o.resyncInterval, "resync-interval", worker.DefaultResyncInterval,
		"How often every VPC scope is reconciled again")
	f.StringVar(&o.pinDir, "pin-dir", attach.PinDir, "bpffs directory of the pinned uSID maps")
	f.StringVar(&o.localPinDir, "local-pin-dir", localprog.PinDir, "bpffs directory of the Local handoff maps")
	f.StringVar(&o.dispatchDir, "xdp-dispatch-dir", xdpdispatch.PinDir,
		"bpffs directory of the shared XDP dispatcher, read to find public receiving devices")
	f.DurationVar(&o.hostGrace, "host-grace", worker.DefaultHostGrace,
		"How long a VPC's host state must go unused before Worker reclaims it")
	f.StringVar(&o.statusFile, "status-file", diag.DefaultPath,
		"Root-only status snapshot that galactic-worker inspect prints; empty writes none")
	f.Bool("build-info", false, "Print build information and exit")
	f.BoolP("version", "V", false, "Print version and exit")
	logOpts.BindFlags(cmd.PersistentFlags())
	cmd.AddCommand(newInspectCommand(), newHandbackCommand())
	return cmd
}
