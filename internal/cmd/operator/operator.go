/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package operator

import (
	"crypto/tls"
	"os"

	"github.com/spf13/cobra"
	nadv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	"go.datum.net/galactic/internal/operator/controller"
	"go.datum.net/galactic/internal/operator/identifier"
	webhookv1 "go.datum.net/galactic/internal/operator/webhook/v1"
	galacticv1alpha "go.datum.net/galactic/pkg/apis/v1alpha"
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(galacticv1alpha.AddToScheme(scheme))
	utilruntime.Must(nadv1.SchemeBuilder.AddToScheme(scheme))
}

type operatorFlags struct {
	metricsAddr          string
	enableLeaderElection bool
	probeAddr            string
	secureMetrics        bool
	enableHTTP2          bool
	webhookCertPath      string
	tlsOpts              []func(*tls.Config)
}

func NewCommand() *cobra.Command {
	flags := &operatorFlags{}

	cmd := &cobra.Command{
		Use:   "operator",
		Short: "Run the Galactic Kubernetes operator",
		Long: `The operator manages VPC and VPCAttachment custom resources in Kubernetes.
It reconciles resource state, assigns identifiers, and configures pod network attachments
via mutation webhooks.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runOperator(flags)
		},
	}

	cmd.Flags().StringVar(&flags.metricsAddr, "metrics-bind-address", "0", "The address the metrics endpoint binds to. "+
		"Use :8443 for HTTPS or :8080 for HTTP, or leave as 0 to disable the metrics service.")
	cmd.Flags().StringVar(&flags.probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	cmd.Flags().BoolVar(&flags.enableLeaderElection, "leader-elect", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	cmd.Flags().BoolVar(&flags.secureMetrics, "metrics-secure", true,
		"If set, the metrics endpoint is served securely via HTTPS. Use --metrics-secure=false to use HTTP instead.")
	cmd.Flags().BoolVar(&flags.enableHTTP2, "enable-http2", false,
		"If set, HTTP/2 will be enabled for the metrics and webhook servers")
	cmd.Flags().StringVar(&flags.webhookCertPath, "webhook-cert-path", "/tmp/k8s-webhook-server/serving-certs",
		"The path to the directory containing the webhook server TLS certificate and key.")

	return cmd
}

func runOperator(flags *operatorFlags) error {
	opts := zap.Options{
		Development: true,
	}
	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	// if the enable-http2 flag is false (the default), http/2 should be disabled
	// due to its vulnerabilities. More specifically, disabling http/2 will
	// prevent from being vulnerable to the HTTP/2 Stream Cancellation and
	// Rapid Reset CVEs. For more information see:
	// - https://github.com/advisories/GHSA-qppj-fm5r-hxr3
	// - https://github.com/advisories/GHSA-4374-p667-p6c8
	disableHTTP2 := func(c *tls.Config) {
		setupLog.Info("disabling http/2")
		c.NextProtos = []string{"http/1.1"}
	}

	if !flags.enableHTTP2 {
		flags.tlsOpts = append(flags.tlsOpts, disableHTTP2)
	}

	webhookServer := webhook.NewServer(webhook.Options{
		TLSOpts:  flags.tlsOpts,
		CertDir:  flags.webhookCertPath,
	})

	// Metrics endpoint is enabled in 'config/default/kustomization.yaml'. The Metrics options configure the server.
	// More info:
	// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.19.1/pkg/metrics/server
	// - https://book.kubebuilder.io/reference/metrics.html
	metricsServerOptions := metricsserver.Options{
		BindAddress:   flags.metricsAddr,
		SecureServing: flags.secureMetrics,
		TLSOpts:       flags.tlsOpts,
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsServerOptions,
		WebhookServer:          webhookServer,
		HealthProbeBindAddress: flags.probeAddr,
		LeaderElection:         flags.enableLeaderElection,
		LeaderElectionID:       "galactic.datumapis.com",
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		return err
	}

	// Create identifier generator for VPC and VPCAttachment
	identifierGen := identifier.New()

	// Register VPC controller
	if err = (&controller.VPCReconciler{
		Client:     mgr.GetClient(),
		Scheme:     mgr.GetScheme(),
		Identifier: identifierGen,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "VPC")
		return err
	}

	// Register VPCAttachment controller
	if err = (&controller.VPCAttachmentReconciler{
		Client:     mgr.GetClient(),
		Scheme:     mgr.GetScheme(),
		Identifier: identifierGen,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "VPCAttachment")
		return err
	}

	// Register Pod mutation webhook
	if os.Getenv("ENABLE_WEBHOOKS") != "false" {
		if err = webhookv1.SetupPodWebhookWithManager(mgr); err != nil {
			setupLog.Error(err, "unable to create webhook", "webhook", "Pod")
			return err
		}
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		return err
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		return err
	}

	setupLog.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		return err
	}

	return nil
}
