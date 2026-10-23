// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Command galactic-edge is the Galactic Edge node agent. It runs on each edge
// node, programs the host state of every EdgeAttachment galactic-controller
// has admitted and allocated to the node, and releases it when the attachment
// is deleted. It keeps each attachment's forwarding gate: the prefixes of the
// routes accepted for the attachment, open only until the holder's lease
// deadline. It is the only process that changes host state for an edge
// attachment.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/go-logr/logr"
	"github.com/spf13/cobra"
	_ "golang.org/x/crypto/x509roots/fallback"
	coordinationv1 "k8s.io/api/coordination/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
	"go.datum.net/galactic/internal/edge/agent"
	"go.datum.net/galactic/internal/edge/hostattach"
	"go.datum.net/galactic/internal/edge/ownership"
	"go.datum.net/galactic/internal/edge/route"
	"go.datum.net/galactic/internal/edge/timing"
	"go.datum.net/galactic/internal/metadata"
	"go.datum.net/galactic/internal/plumbing/ebpf/attach"
)

type options struct {
	nodeName       string
	mtu            int
	pinDir         string
	ownershipDir   string
	criEndpoint    string
	procSys        string
	metricsAddress string
	healthAddress  string
	maxSkew        time.Duration
	bootIDPath     string
}

func main() {
	if err := newRootCommand().Execute(); err != nil {
		os.Exit(1)
	}
}

func newRootCommand() *cobra.Command {
	o := &options{}
	cmd := &cobra.Command{
		Use:          "galactic-edge",
		Short:        "Program and release Galactic Edge attachments on this node",
		Version:      metadata.Version,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return run(cmd.Context(), o)
		},
	}
	f := cmd.Flags()
	f.StringVar(&o.nodeName, "node-name", os.Getenv("NODE_NAME"), "This node's name (env NODE_NAME)")
	f.IntVar(&o.mtu, "mtu", 0, "MTU of every attachment link: at least the fabric's tenant MTU (required)")
	f.StringVar(&o.pinDir, "pin-dir", attach.PinDir, "Directory the uSID datapath's maps and programs are pinned in")
	f.StringVar(&o.ownershipDir, "ownership-dir", ownership.DefaultDir,
		"Host directory of the node's write-fence records; it must outlive every writer")
	f.StringVar(&o.criEndpoint, "cri-endpoint", "unix:///run/containerd/containerd.sock",
		"Container runtime (CRI) endpoint used to find provider pods' network namespaces")
	f.StringVar(&o.procSys, "proc-sys-path", "/proc/sys",
		"Writable procfs sysctl directory, for the forwarding sysctl of a packet device's pod")
	f.DurationVar(&o.maxSkew, "max-skew", timing.Params.MaxSkew,
		"Maximum wall-clock error of any node; a gate closes this long before its grant's validUntil. "+
			"It must equal galactic-controller's --edge-max-skew")
	f.StringVar(&o.bootIDPath, "boot-id-path", "/proc/sys/kernel/random/boot_id", "File holding this boot's ID")
	f.StringVar(&o.metricsAddress, "metrics-bind-address", ":9186", "Address serving /metrics")
	f.StringVar(&o.healthAddress, "health-probe-bind-address", ":9187", "Address serving /healthz and /readyz")
	return cmd
}

func run(parent context.Context, o *options) error {
	if o.nodeName == "" {
		return errors.New("--node-name or NODE_NAME is required")
	}
	if o.mtu < hostattach.MinMTU {
		return fmt.Errorf("--mtu must be at least %d", hostattach.MinMTU)
	}
	if parent == nil {
		parent = context.Background()
	}
	ctx, stop := signal.NotifyContext(parent, syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	ctrl.SetLogger(logr.FromSlogHandler(slog.Default().Handler()))
	hostattach.SysctlRoot = o.procSys

	// A new owner ID per process start: a restarted agent must fence its
	// predecessor's scopes, never continue its tickets.
	incarnation := make([]byte, 8)
	if _, err := rand.Read(incarnation); err != nil {
		return err
	}
	auth, err := ownership.New(o.ownershipDir)
	if err != nil {
		return err
	}
	bootID, err := os.ReadFile(o.bootIDPath)
	if err != nil {
		return fmt.Errorf("read boot ID: %w", err)
	}
	params := timing.Params
	params.MaxSkew = o.maxSkew
	if err := params.Validate(); err != nil {
		return err
	}
	// The agent runs in the host network namespace; /proc/self/ns/net is the
	// main thread's, which hostattach never moves.
	host, err := hostattach.OpenNamespace("/proc/self/ns/net")
	if err != nil {
		return err
	}
	defer func() { _ = host.Close() }()
	pods, err := agent.NewCRIResolver(o.criEndpoint)
	if err != nil {
		return err
	}
	defer func() { _ = pods.Close() }()

	scheme := runtime.NewScheme()
	utilruntime.Must(galacticv1alpha1.AddToScheme(scheme))
	utilruntime.Must(coordinationv1.AddToScheme(scheme))
	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		Cache:                  cache.Options{ByObject: route.LeaseCache()},
		Metrics:                metricsserver.Options{BindAddress: o.metricsAddress},
		HealthProbeBindAddress: o.healthAddress,
	})
	if err != nil {
		return fmt.Errorf("create manager: %w", err)
	}
	a := &agent.Agent{
		Client:     mgr.GetClient(),
		NodeName:   o.nodeName,
		Owner:      agent.NewOwner(o.nodeName, time.Now(), hex.EncodeToString(incarnation)),
		Ownership:  auth,
		Host:       host,
		Namespaces: pods,
		Datapath:   agent.PinnedDatapath{PinDir: o.pinDir},
		MTU:        o.mtu,
		APIReader:  mgr.GetAPIReader(),
		Gates:      agent.PinnedGates{PinDir: o.pinDir},
		Params:     params,
		BootID:     strings.TrimSpace(string(bootID)),
	}
	if err := a.SetupWithManager(mgr); err != nil {
		return err
	}
	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		return err
	}
	if err := mgr.AddHealthzCheck("scope-ownership", a.Healthy); err != nil {
		return err
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		return err
	}
	slog.Info("starting galactic-edge", "node", o.nodeName, "owner", a.Owner,
		"version", metadata.Version)
	return mgr.Start(ctx)
}
