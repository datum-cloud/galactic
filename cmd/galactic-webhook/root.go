// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/spf13/cobra"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"go.datum.net/galactic/internal/config"
	"go.datum.net/galactic/internal/metadata"
	galacticwebhook "go.datum.net/galactic/internal/webhook"
)

const (
	appName = "galactic-webhook"

	appDesc = `Galactic VPC-attachment mutating admission webhook

 Find more information at: https://www.datum.net/docs`

	// mutatePodPath is the path the MutatingWebhookConfiguration in
	// config/webhook/ targets.
	mutatePodPath = "/mutate-v1-pod-vpc-attachment"
)

// runCmd contains the application startup logic.
func runCmd(cfg *config.WebhookConfig) error {
	ctrl.SetLogger(zap.New(zap.UseDevMode(true)))

	scheme := galacticwebhook.NewScheme()

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme: scheme,
		Metrics: metricsserver.Options{
			BindAddress: fmt.Sprintf(":%d", cfg.MetricsPort),
		},
		HealthProbeBindAddress: fmt.Sprintf(":%d", cfg.HealthPort),
		WebhookServer: webhook.NewServer(webhook.Options{
			Port:    cfg.Port,
			CertDir: cfg.CertDir,
		}),
	})
	if err != nil {
		return fmt.Errorf("create manager: %w", err)
	}

	// Cache-sync-gated readiness: a cold cache means the ID allocator can't
	// see existing NADs and would double-allocate IDs — see this repo's
	// design plan, "Client: cache-backed reads, direct writes."
	if err := mgr.AddReadyzCheck("informer-sync", func(req *http.Request) error {
		if !mgr.GetCache().WaitForCacheSync(req.Context()) {
			return errors.New("informer cache not yet synced")
		}
		return nil
	}); err != nil {
		return fmt.Errorf("add readyz check: %w", err)
	}
	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		return fmt.Errorf("add healthz check: %w", err)
	}

	mutator := &galacticwebhook.PodMutator{
		Client:  mgr.GetClient(),
		Decoder: admission.NewDecoder(scheme),
		NADDefaults: galacticwebhook.NADDefaults{
			MTU:           cfg.MTU,
			InterfaceType: cfg.InterfaceType,
		},
	}
	mgr.GetWebhookServer().Register(mutatePodPath, &webhook.Admission{Handler: mutator})

	ctx := ctrl.SetupSignalHandler()
	if err := mgr.Start(ctx); err != nil {
		return fmt.Errorf("manager exited: %w", err)
	}
	return nil
}

// newRootCommand builds the root cobra command with all flags and the
// application startup logic.
func newRootCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   appName,
		Short: strings.Split(appDesc, "\n")[0],
		Long:  appDesc,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if ok, _ := cmd.Flags().GetBool("build-info"); ok {
				fmt.Println(metadata.BuildInfo(appName))
				return nil
			}
			if ok, _ := cmd.Flags().GetBool("version"); ok {
				fmt.Printf("galactic-webhook version %s\n", metadata.Version)
				return nil
			}

			cfg := config.NewWebhookConfig()
			cfg.BindFlags(cmd.Flags())
			if err := cfg.Validate(); err != nil {
				return err
			}
			return runCmd(cfg)
		},
	}

	cmd.Flags().IntP("port", "p", config.DefaultWebhookPort, "Webhook server listen port")
	cmd.Flags().IntP("metrics-port", "", config.DefaultWebhookMetricsPort, "Metrics listen port")
	cmd.Flags().IntP("health-port", "", config.DefaultWebhookHealthPort, "Health/readiness probe listen port")
	cmd.Flags().StringP("cert-dir", "", config.DefaultWebhookCertDir, "Directory containing tls.crt/tls.key")
	cmd.Flags().IntP("mtu", "", config.DefaultWebhookMTU, "MTU baked into every NAD's CNI conflist")
	cmd.Flags().StringP("interface-type", "", config.DefaultWebhookInterfaceType,
		"Interface type baked into every NAD's CNI conflist (\"veth\" or \"tap\")")
	cmd.Flags().Bool("build-info", false, "Print build information and exit")
	cmd.Flags().BoolP("version", "V", false, "Print version and exit")
	return cmd
}
