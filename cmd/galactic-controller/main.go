// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Command galactic-controller runs Galactic's cluster-scoped controllers.
// Its cell role serves the TrafficPolicy validating webhook, provisions the
// reserved default policy in each tenant namespace, and resolves
// TrafficPolicyBinding references. The per-node datapath state is
// galactic-router's, not this binary's.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/go-logr/logr"
	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	ctrlwebhook "sigs.k8s.io/controller-runtime/pkg/webhook"

	cloudv1alpha1 "go.datum.net/cloud/api/v1alpha1"
	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
	"go.datum.net/galactic/internal/metadata"
	"go.datum.net/galactic/internal/trafficpolicy/cell"
	"go.datum.net/galactic/internal/trafficpolicy/webhook"
)

// RoleCell is the only role so far: the controllers that run once per edge
// cell.
const RoleCell = "cell"

type options struct {
	role               string
	namespace          string
	metricsAddress     string
	healthAddress      string
	webhookPort        int
	webhookCertDir     string
	leaderElect        bool
	controllerUsername string
}

func main() {
	if err := newRootCommand().Execute(); err != nil {
		os.Exit(1)
	}
}

func newRootCommand() *cobra.Command {
	o := &options{}
	cmd := &cobra.Command{
		Use:          "galactic-controller",
		Short:        "Run Galactic's cluster-scoped controllers",
		Version:      metadata.Version,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return run(cmd.Context(), o)
		},
	}
	f := cmd.Flags()
	f.StringVar(&o.role, "role", "", "Controllers to run; only \"cell\" exists so far (required)")
	f.StringVar(&o.namespace, "namespace", envOr("POD_NAMESPACE", "galactic-system"),
		"Namespace of this pod and its leader election lease (env POD_NAMESPACE)")
	f.StringVar(&o.metricsAddress, "metrics-bind-address", ":9184", "Address serving /metrics")
	f.StringVar(&o.healthAddress, "health-probe-bind-address", ":8081", "Address serving /healthz and /readyz")
	f.IntVar(&o.webhookPort, "webhook-port", 9443, "Port the admission webhook serves on")
	f.StringVar(&o.webhookCertDir, "webhook-cert-dir", "/tmp/k8s-webhook-server/serving-certs",
		"Directory holding the webhook's tls.crt and tls.key")
	f.BoolVar(&o.leaderElect, "leader-elect", true, "Elect one active replica; the webhook serves on every replica")
	f.StringVar(&o.controllerUsername, "controller-username", "",
		"Authenticated username this controller runs as, the only one allowed to write the reserved "+
			"default policy (default system:serviceaccount:<namespace>:galactic-controller)")
	return cmd
}

func run(parent context.Context, o *options) error {
	if o.role != RoleCell {
		return fmt.Errorf("--role must be %q, got %q", RoleCell, o.role)
	}
	if o.controllerUsername == "" {
		o.controllerUsername = "system:serviceaccount:" + o.namespace + ":galactic-controller"
	}
	if parent == nil {
		parent = context.Background()
	}
	ctx, stop := signal.NotifyContext(parent, syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	ctrl.SetLogger(logr.FromSlogHandler(slog.Default().Handler()))

	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(galacticv1alpha1.AddToScheme(scheme))
	utilruntime.Must(cloudv1alpha1.AddToScheme(scheme))

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                        scheme,
		Metrics:                       metricsserver.Options{BindAddress: o.metricsAddress},
		HealthProbeBindAddress:        o.healthAddress,
		LeaderElection:                o.leaderElect,
		LeaderElectionID:              "galactic-controller-cell",
		LeaderElectionNamespace:       o.namespace,
		LeaderElectionReleaseOnCancel: true,
		WebhookServer: ctrlwebhook.NewServer(ctrlwebhook.Options{
			Port: o.webhookPort, CertDir: o.webhookCertDir,
		}),
	})
	if err != nil {
		return fmt.Errorf("create manager: %w", err)
	}
	if err := Setup(mgr, o.controllerUsername); err != nil {
		return err
	}
	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		return err
	}
	if err := mgr.AddReadyzCheck("webhook", mgr.GetWebhookServer().StartedChecker()); err != nil {
		return err
	}
	slog.Info("starting galactic-controller", "role", o.role, "version", metadata.Version)
	return mgr.Start(ctx)
}

// Setup registers the cell role's webhook and reconcilers with mgr.
func Setup(mgr ctrl.Manager, controllerUsername string) error {
	mgr.GetWebhookServer().Register(webhook.Path, &ctrlwebhook.Admission{Handler: &webhook.PolicyValidator{
		ControllerUsername: controllerUsername,
		Reader:             mgr.GetAPIReader(),
	}})
	if err := (&cell.PolicyReconciler{Client: mgr.GetClient()}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("set up TrafficPolicy reconciler: %w", err)
	}
	if err := (&cell.DefaultPolicyReconciler{
		Client: mgr.GetClient(), Recorder: mgr.GetEventRecorder("galactic-controller"),
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("set up default policy reconciler: %w", err)
	}
	if err := (&cell.BindingReconciler{Client: mgr.GetClient()}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("set up TrafficPolicyBinding reconciler: %w", err)
	}
	return nil
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
