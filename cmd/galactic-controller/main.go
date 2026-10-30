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
	"time"

	nadv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	"github.com/spf13/cobra"
	"go.miloapis.com/instrumentation/metrics"
	_ "golang.org/x/crypto/x509roots/fallback"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	ctrlwebhook "sigs.k8s.io/controller-runtime/pkg/webhook"

	computev1alpha "go.datum.net/compute/api/v1alpha"
	cloudv1alpha1 "go.datum.net/galactic/api/cloud/v1alpha1"
	networkv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
	cloudcontroller "go.datum.net/galactic/internal/cloud/controller"
	"go.datum.net/galactic/internal/cloud/galactic"
	cloudwebhook "go.datum.net/galactic/internal/cloud/webhook"
	"go.datum.net/galactic/internal/edge/admission"
	edgeattachment "go.datum.net/galactic/internal/edge/attachment"
	edgediag "go.datum.net/galactic/internal/edge/diag"
	edgeroute "go.datum.net/galactic/internal/edge/route"
	"go.datum.net/galactic/internal/edge/timing"
	"go.datum.net/galactic/internal/logging"
	"go.datum.net/galactic/internal/metadata"
	"go.datum.net/galactic/internal/trafficpolicy/cell"
	"go.datum.net/galactic/internal/trafficpolicy/webhook"
	networkingv1alpha "go.datum.net/network-services-operator/api/v1alpha"
)

const (
	RoleCell   = "cell"
	RoleFabric = "fabric"
)

type options struct {
	role               string
	namespace          string
	metricsAddress     string
	healthAddress      string
	webhookPort        int
	webhookCertDir     string
	leaderElect        bool
	controllerUsername string
	identityClass      string
	identityNamespace  string
	platformProject    string
	ipamKubeconfig     string
	hubKubeconfig      string
	edge               bool
	edgeMaxSkew        time.Duration
}

func main() {
	if err := newRootCommand().Execute(); err != nil {
		os.Exit(1)
	}
}

func newRootCommand() *cobra.Command {
	o := &options{}
	var logOpts logging.Options
	cmd := &cobra.Command{
		Use:          "galactic-controller",
		Short:        "Run Galactic's cell or fabric controllers",
		Version:      metadata.Version,
		SilenceUsage: true,
		PersistentPreRunE: func(*cobra.Command, []string) error {
			return logOpts.Setup()
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			return run(cmd.Context(), o)
		},
	}
	f := cmd.Flags()
	f.StringVar(&o.role, "role", "", "Controllers to run: cell or fabric (required)")
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
	f.StringVar(&o.identityClass, "identity-class", "", "Fabric role: IPClass for globally unique fabric identities")
	f.StringVar(&o.identityNamespace, "identity-namespace", "default", "Fabric role: namespace for platform IP claims")
	f.StringVar(&o.platformProject, "platform-project", "", "Fabric role: platform project for IPAM")
	f.StringVar(&o.ipamKubeconfig, "ipam-kubeconfig", "", "Fabric role: IPAM cluster kubeconfig")
	f.StringVar(&o.hubKubeconfig, "hub-kubeconfig", "", "Fabric role: federation hub kubeconfig")
	f.BoolVar(&o.edge, "edge", false, "Cell role: admit, allocate and drain Galactic Edge attachments, and "+
		"accept and revoke their route claims (requires the edge CRDs and config/galactic-edge applied first; "+
		"a deleted attachment is held until galactic-edge on its node reports it released, or the node is removed)")
	f.DurationVar(&o.edgeMaxSkew, "edge-max-skew", 2*time.Second,
		"Cell role: maximum wall-clock error of any node; an EdgeService stops admitting this long before its "+
			"validUntil. It must equal galactic-edge's --max-skew")
	logOpts.BindFlags(cmd.PersistentFlags())
	return cmd
}

func run(parent context.Context, o *options) error {
	if o.role == RoleFabric {
		return runFabric(parent, o)
	}
	if o.role != RoleCell {
		return fmt.Errorf("--role must be %q or %q, got %q", RoleCell, RoleFabric, o.role)
	}
	if o.controllerUsername == "" {
		o.controllerUsername = "system:serviceaccount:" + o.namespace + ":galactic-controller"
	}
	if parent == nil {
		parent = context.Background()
	}
	ctx, stop := signal.NotifyContext(parent, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(galacticv1alpha1.AddToScheme(scheme))
	utilruntime.Must(cloudv1alpha1.AddToScheme(scheme))
	utilruntime.Must(networkv1alpha1.AddToScheme(scheme))
	utilruntime.Must(networkingv1alpha.AddToScheme(scheme))
	utilruntime.Must(nadv1.AddToScheme(scheme))
	utilruntime.Must(computev1alpha.AddToScheme(scheme))

	// The Edge controllers watch every Pod. Without them, only the instance
	// attachment collector reads Pods, so the cache holds just the ones it
	// lists.
	cacheOpts := cache.Options{ByObject: cloudcontroller.InjectedPodCache()}
	if o.edge {
		cacheOpts.ByObject = edgeroute.LeaseCache()
	}
	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                        scheme,
		Cache:                         cacheOpts,
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
	if err := SetupCloud(mgr); err != nil {
		return err
	}
	if o.edge {
		rec := &edgediag.Recorder{
			Events:  mgr.GetEventRecorder("galactic-controller"),
			Metrics: edgediag.NewMetrics(edgediag.RoleCore),
		}
		metrics.MustRegister(&edgediag.StateCollector{Reader: mgr.GetClient()})
		if err := edgeattachment.Setup(mgr, &edgeattachment.Reconciler{
			Client: mgr.GetClient(), APIReader: mgr.GetAPIReader(),
			Authority: admission.NewAuthority(o.edgeMaxSkew), MaxSkew: o.edgeMaxSkew, Diag: rec,
		}); err != nil {
			return fmt.Errorf("set up edge attachments: %w", err)
		}
		params := timing.Params
		params.MaxSkew = o.edgeMaxSkew
		if err := edgeroute.Setup(mgr, params, timing.BootClock, galactic.SystemNamespace, rec); err != nil {
			return fmt.Errorf("set up edge routes: %w", err)
		}
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

// SetupCloud registers the Galactic data-plane status controller and the
// collector comparing running instances' VPC attachments with that status.
func SetupCloud(mgr ctrl.Manager) error {
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &networkv1alpha1.BGPAdvertisement{},
		cloudcontroller.IndexBGPAdvertisementIdentity, cloudcontroller.BGPAdvertisementIdentity); err != nil {
		return fmt.Errorf("index BGP advertisement identity: %w", err)
	}
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &cloudv1alpha1.VPCAttachment{},
		cloudcontroller.IndexVPCAttachmentIdentity, func(obj client.Object) []string {
			attachment, ok := obj.(*cloudv1alpha1.VPCAttachment)
			if !ok || attachment.Status.VPC == "" || attachment.Status.VPCAttachment == "" {
				return nil
			}
			identity := galactic.AdvertisementName(attachment.Status.VPC, attachment.Status.VPCAttachment)
			if identity == "" {
				return nil
			}
			return []string{identity}
		}); err != nil {
		return fmt.Errorf("index VPC attachment identity: %w", err)
	}
	for name, setup := range map[string]func() error{
		"BGPAdvertisement": func() error {
			reconciler := &cloudcontroller.BGPAdvertisementReconciler{Client: mgr.GetClient(), Scheme: mgr.GetScheme()}
			return reconciler.SetupWithManager(mgr)
		},
	} {
		if err := setup(); err != nil {
			return fmt.Errorf("set up %s controller: %w", name, err)
		}
	}
	(&cloudwebhook.PodInterfaceInjector{Client: mgr.GetClient()}).SetupWithManager(mgr)
	metrics.MustRegister(&cloudcontroller.InstanceAttachmentCollector{Reader: mgr.GetClient()})
	return nil
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
