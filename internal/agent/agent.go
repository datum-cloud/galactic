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
	GoBGPAPIPort   int
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

	// gRPC health server — always started; reports NOT_SERVING until GoBGP is ready.
	healthSrv := health.NewServer()
	healthSrv.SetServingStatus("", grpc_health_v1.HealthCheckResponse_NOT_SERVING)

	grpcSrv := grpc.NewServer()
	grpc_health_v1.RegisterHealthServer(grpcSrv, healthSrv)

	grpcLis, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", opts.GRPCHealthPort))
	if err != nil {
		return fmt.Errorf("listen grpc health port %d: %w", opts.GRPCHealthPort, err)
	}

	go func() {
		if err := grpcSrv.Serve(grpcLis); err != nil {
			slog.Error("grpc health server stopped", "err", err)
		}
	}()
	defer grpcSrv.GracefulStop()

	if opts.GoBGPEnabled {
		gobgpSrv := gobgp.New(gobgp.Config{
			APIPort:  opts.GoBGPAPIPort,
			LogLevel: opts.GoBGPLogLevel,
		})

		go func() {
			if err := gobgpSrv.Start(ctx); err != nil {
				slog.Error("gobgp server stopped", "err", err)
			}
		}()

		// Wait for GoBGP gRPC API to accept connections, then mark health SERVING.
		go func() {
			waitCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()
			if err := gobgpSrv.WaitReady(waitCtx); err != nil {
				slog.Error("gobgp did not become ready", "err", err)
				return
			}
			healthSrv.SetServingStatus("", grpc_health_v1.HealthCheckResponse_SERVING)
			slog.Info("gobgp ready", "addr", gobgpSrv.Addr())
		}()

		// Bootstrap BGPProvider before starting the manager.
		directClient, err := client.New(restCfg, client.Options{Scheme: scheme})
		if err != nil {
			return fmt.Errorf("create bootstrap client: %w", err)
		}
		if opts.NodeName != "" {
			if err := bootstrap.EnsureGoBGPProvider(ctx, directClient, opts.NodeName, opts.Plane, gobgpSrv.Addr()); err != nil {
				return fmt.Errorf("bootstrap gobgp provider: %w", err)
			}
		}

		// Delete BGPProvider on clean shutdown using a fresh context.
		defer func() {
			deleteCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if opts.NodeName != "" {
				if err := bootstrap.DeleteGoBGPProvider(deleteCtx, directClient, opts.NodeName, opts.Plane); err != nil {
					slog.Error("failed to delete BGPProvider on shutdown", "err", err)
				}
			}
			healthSrv.SetServingStatus("", grpc_health_v1.HealthCheckResponse_NOT_SERVING)
		}()

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
