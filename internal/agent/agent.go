// Package agent implements the galactic-agent startup and run loop.
package agent

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	providerv1alpha1 "go.miloapis.com/cosmos/api/proto/bgp/provider/v1alpha1"
	providersv1alpha1 "go.miloapis.com/cosmos/api/providers/v1alpha1"

	"go.datum.net/galactic/internal/bootstrap"
	"go.datum.net/galactic/internal/gobgp"
	"go.datum.net/galactic/internal/metrics"
)

var scheme = runtime.NewScheme()

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(providersv1alpha1.AddToScheme(scheme))
}

// Options holds agent configuration.
type Options struct {
	MetricsAddr    string
	HealthAddr     string
	NodeName       string
	Plane          string
	GoBGPEnabled   bool
	GoBGPLogLevel  string
	GRPCHealthPort int
}

// Run starts galactic-agent and blocks until ctx is cancelled or a signal arrives.
func Run(ctx context.Context, opts Options) error {
	ctx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if opts.NodeName == "" {
		opts.NodeName = os.Getenv("NODE_NAME")
	}

	metrics.MustRegister()
	ctrl.SetLogger(zap.New(zap.UseDevMode(false)))

	if !opts.GoBGPEnabled {
		slog.Warn("no providers enabled; agent is running but will not configure any BGP daemons")
	}

	restCfg, err := ctrl.GetConfig()
	if err != nil {
		return fmt.Errorf("get k8s config: %w", err)
	}

	mgr, err := ctrl.NewManager(restCfg, ctrl.Options{
		Scheme:                 scheme,
		HealthProbeBindAddress: opts.HealthAddr,
		Metrics:                metricsserver.Options{BindAddress: opts.MetricsAddr},
	})
	if err != nil {
		return fmt.Errorf("new manager: %w", err)
	}

	// gRPC server — serves both the health check and the BGPProviderService for cosmos.
	healthSrv := health.NewServer()
	healthSrv.SetServingStatus("", grpc_health_v1.HealthCheckResponse_NOT_SERVING)

	grpcSrv := grpc.NewServer()
	grpc_health_v1.RegisterHealthServer(grpcSrv, healthSrv)

	grpcAddr := fmt.Sprintf("localhost:%d", opts.GRPCHealthPort)
	grpcLis, err := net.Listen("tcp", grpcAddr)
	if err != nil {
		return fmt.Errorf("listen grpc port %d: %w", opts.GRPCHealthPort, err)
	}

	go func() {
		if err := grpcSrv.Serve(grpcLis); err != nil {
			slog.Error("grpc server stopped", "err", err)
		}
	}()
	defer grpcSrv.GracefulStop()

	if opts.GoBGPEnabled {
		gobgpSrv := gobgp.New(gobgp.Config{
			LogLevel: opts.GoBGPLogLevel,
		})

		// Register BGPProviderService so cosmos can configure GoBGP via gRPC.
		providerv1alpha1.RegisterBGPProviderServiceServer(grpcSrv, gobgp.NewProviderServer(gobgpSrv))

		go func() {
			if err := gobgpSrv.Start(ctx); err != nil {
				slog.Error("gobgp server stopped", "err", err)
			}
		}()

		// Wait for GoBGP to initialize, then mark health SERVING.
		go func() {
			waitCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()
			if err := gobgpSrv.WaitReady(waitCtx); err != nil {
				slog.Error("gobgp did not become ready", "err", err)
				return
			}
			healthSrv.SetServingStatus("", grpc_health_v1.HealthCheckResponse_SERVING)
			slog.Info("gobgp ready", "provider-addr", grpcAddr)
		}()

		// Bootstrap BGPProvider before starting the manager.
		directClient, err := client.New(restCfg, client.Options{Scheme: scheme})
		if err != nil {
			return fmt.Errorf("create bootstrap client: %w", err)
		}
		if opts.NodeName != "" {
			if err := bootstrap.EnsureGoBGPProvider(ctx, directClient, opts.NodeName, opts.Plane, grpcAddr); err != nil {
				return fmt.Errorf("bootstrap gobgp provider: %w", err)
			}
		}

		defer healthSrv.SetServingStatus("", grpc_health_v1.HealthCheckResponse_NOT_SERVING)

		// Readyz check: probe the gRPC health service we expose.
		if err := mgr.AddReadyzCheck("gobgp", func(_ *http.Request) error {
			conn, err := grpc.NewClient(
				fmt.Sprintf("localhost:%d", opts.GRPCHealthPort),
				grpc.WithTransportCredentials(insecure.NewCredentials()),
			)
			if err != nil {
				return err
			}
			defer func() { _ = conn.Close() }()
			hc := grpc_health_v1.NewHealthClient(conn)
			probeCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			resp, err := hc.Check(probeCtx, &grpc_health_v1.HealthCheckRequest{})
			if err != nil {
				return err
			}
			if resp.Status != grpc_health_v1.HealthCheckResponse_SERVING {
				return fmt.Errorf("gobgp not serving: %s", resp.Status)
			}
			return nil
		}); err != nil {
			return fmt.Errorf("add gobgp readyz check: %w", err)
		}
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		return fmt.Errorf("add healthz check: %w", err)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		return fmt.Errorf("add readyz check: %w", err)
	}

	return mgr.Start(ctx)
}
