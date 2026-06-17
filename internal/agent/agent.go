// Package agent implements the galactic-agent startup and run loop.
package agent

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	providerv1alpha1 "go.miloapis.com/cosmos/api/proto/bgp/provider/v1alpha1"
	providersv1alpha1 "go.miloapis.com/cosmos/api/providers/v1alpha1"

	"go.datum.net/galactic/internal/bootstrap"
	"go.datum.net/galactic/internal/gobgp"
)

var scheme = runtime.NewScheme()

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(providersv1alpha1.AddToScheme(scheme))
}

// Options holds agent configuration.
type Options struct {
	NodeName   string
	Role       string
	HealthPort int
	Port       int
}

// Run starts galactic-agent and blocks until ctx is cancelled or a signal arrives.
func Run(ctx context.Context, opts Options) error {
	ctx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if opts.NodeName == "" {
		opts.NodeName = os.Getenv("NODE_NAME")
	}

	if opts.Role != "overlay" && opts.Role != "overlay-rr" {
		return fmt.Errorf("invalid --role %q: must be overlay or overlay-rr", opts.Role)
	}

	restCfg, err := ctrl.GetConfig()
	if err != nil {
		return fmt.Errorf("get k8s config: %w", err)
	}

	// Health gRPC server: Kubernetes probes connect here directly.
	// "" (liveness) is SERVING immediately; "readyz" becomes SERVING once GoBGP is ready.
	healthSrv := health.NewServer()
	healthSrv.SetServingStatus("", grpc_health_v1.HealthCheckResponse_SERVING)
	healthSrv.SetServingStatus("readyz", grpc_health_v1.HealthCheckResponse_NOT_SERVING)

	healthGRPCSrv := grpc.NewServer()
	grpc_health_v1.RegisterHealthServer(healthGRPCSrv, healthSrv)

	healthLis, err := net.Listen("tcp", fmt.Sprintf(":%d", opts.HealthPort))
	if err != nil {
		return fmt.Errorf("listen health port %d: %w", opts.HealthPort, err)
	}

	go func() {
		if err := healthGRPCSrv.Serve(healthLis); err != nil {
			slog.Error("health grpc server stopped", "err", err)
		}
	}()
	defer healthGRPCSrv.GracefulStop()

	// Provider gRPC server: BGPProviderService only (cosmos connects here).
	providerSrv := grpc.NewServer()

	providerAddr := fmt.Sprintf("localhost:%d", opts.Port)
	providerLis, err := net.Listen("tcp", providerAddr)
	if err != nil {
		return fmt.Errorf("listen provider port %d: %w", opts.Port, err)
	}

	go func() {
		if err := providerSrv.Serve(providerLis); err != nil {
			slog.Error("provider grpc server stopped", "err", err)
		}
	}()
	defer providerSrv.GracefulStop()

	gobgpSrv := gobgp.New(gobgp.Config{})

	// Register BGPProviderService so cosmos can configure GoBGP via gRPC.
	providerv1alpha1.RegisterBGPProviderServiceServer(providerSrv, gobgp.NewProviderServer(gobgpSrv))

	go func() {
		if err := gobgpSrv.Start(ctx); err != nil {
			slog.Error("gobgp server stopped", "err", err)
		}
	}()

	// Wait for GoBGP to initialize, then mark readyz SERVING.
	go func() {
		waitCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		if err := gobgpSrv.WaitReady(waitCtx); err != nil {
			slog.Error("gobgp did not become ready", "err", err)
			return
		}
		healthSrv.SetServingStatus("readyz", grpc_health_v1.HealthCheckResponse_SERVING)
		slog.Info("gobgp ready", "provider-addr", providerAddr)
	}()

	directClient, err := client.New(restCfg, client.Options{Scheme: scheme})
	if err != nil {
		return fmt.Errorf("create bootstrap client: %w", err)
	}
	if opts.NodeName != "" {
		if err := bootstrap.EnsureGoBGPProvider(ctx, directClient, opts.NodeName, opts.Role, providerAddr); err != nil {
			return fmt.Errorf("bootstrap gobgp provider: %w", err)
		}
	}

	defer healthSrv.SetServingStatus("readyz", grpc_health_v1.HealthCheckResponse_NOT_SERVING)

	<-ctx.Done()
	return nil
}
