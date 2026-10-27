// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Command fabric-config-agent installs and maintains a node's FRR
// configuration for the fabric-router DaemonSet. Its init subcommand runs as
// the pod's init container and installs the node's configuration from its own
// ConfigMap; its watch subcommand runs beside FRR and applies later changes to
// that ConfigMap with frr-reload, without restarting FRR. With the
// activation path on, both act on the node's FabricRouterDeployment, and
// with the ConfigMap path retired neither reads a ConfigMap. watch also
// hard-resets any IPv6 session that comes up announcing an IPv4-mapped next
// hop, and serves metrics on those sessions, on BGP routes zebra failed to
// install, on activations and staging runs, on waits for the node's FRR
// writer lock, and on the source init started FRR from.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/events"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	ctrlconfig "sigs.k8s.io/controller-runtime/pkg/client/config"

	networkv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	"go.datum.net/galactic/internal/fabricconfig"
	"go.datum.net/galactic/internal/fabricconfig/activation"
	"go.datum.net/galactic/internal/logging"
	"go.datum.net/galactic/internal/metadata"
)

const (
	appName = "fabric-config-agent"

	appDesc = `Fabric router configuration agent

 Installs this node's FRR configuration from its own fabric-router.<node>
 ConfigMap, and applies later changes to it without restarting FRR.

 Find more information at: https://www.datum.net/docs`

	// apiTimeout bounds each request the deployment agent makes.
	apiTimeout = 10 * time.Second
)

// options holds the flags shared by every subcommand.
type options struct {
	nodeName        string
	namespace       string
	podName         string
	podUID          string
	legacyConfigMap string
	restCfg         *rest.Config
	configDir       string
	defaultsDir     string
	vtysh           string
	reloader        string

	// activation enables the FabricRouterDeployment path.
	activation bool
	// configMaps is false once the ConfigMap path is retired: the node
	// starts and runs only from the CRD source.
	configMaps    bool
	stateDir      string
	machineIDFile string
	writerLock    string
	bootRecord    string

	// watch only.
	metricsBindAddress string
	nextHopDetectOnly  bool
}

func main() {
	if err := newRootCommand().Execute(); err != nil {
		slog.Error(appName+" failed", "error", err)
		os.Exit(1)
	}
}

// newRootCommand builds the root command and its init and watch subcommands.
func newRootCommand() *cobra.Command {
	opts := &options{}
	var logOpts logging.Options
	cmd := &cobra.Command{
		Use:           appName,
		Short:         strings.Split(appDesc, "\n")[0],
		Long:          appDesc,
		SilenceErrors: true,
		SilenceUsage:  true,
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
			return cmd.Help()
		},
	}

	pf := cmd.PersistentFlags()
	pf.StringVar(&opts.nodeName, "node-name", os.Getenv("NODE_NAME"), "Kubernetes node name (required; env NODE_NAME)")
	pf.StringVar(&opts.namespace, "namespace", os.Getenv("POD_NAMESPACE"),
		"Namespace holding the configuration ConfigMaps (required; env POD_NAMESPACE)")
	pf.StringVar(&opts.podName, "pod-name", os.Getenv("POD_NAME"), "This pod's name, for events (env POD_NAME)")
	pf.StringVar(&opts.podUID, "pod-uid", os.Getenv("POD_UID"), "This pod's UID, for events (env POD_UID)")
	pf.StringVar(&opts.legacyConfigMap, "legacy-configmap", fabricconfig.DefaultLegacyConfigMap,
		"Shared ConfigMap consulted for a frr.conf.<node> key when the node has no ConfigMap of its own; empty disables")
	pf.StringVar(&opts.configDir, "config-dir", "/etc/frr", "FRR configuration directory")
	pf.StringVar(&opts.defaultsDir, "defaults-dir", "/etc/frr-defaults", "Directory holding the image's default FRR files")
	pf.StringVar(&opts.vtysh, "vtysh", "/usr/bin/vtysh", "Path to vtysh")
	pf.StringVar(&opts.reloader, "frr-reload", "/usr/lib/frr/frr-reload.py", "Path to frr-reload.py")
	pf.BoolVar(&opts.activation, "activation", os.Getenv("FABRIC_ACTIVATION") == "true",
		"Act on this node's FabricRouterDeployment: its source mode, candidate and active revisions "+
			"(env FABRIC_ACTIVATION=true)")
	pf.BoolVar(&opts.configMaps, "configmaps", os.Getenv("FABRIC_CONFIGMAPS") != "false",
		"Read this node's configuration ConfigMaps. false retires the ConfigMap path: the node starts and runs "+
			"only from the CRD source and never reads, watches or raises events on a ConfigMap; needs --activation "+
			"(env FABRIC_CONFIGMAPS=false)")
	pf.StringVar(&opts.stateDir, "state-dir", "/var/lib/fabric-router/agent",
		"Host directory holding the activation journal, identity and checkpoint")
	pf.StringVar(&opts.machineIDFile, "machine-id-file", "/etc/machine-id", "The host's machine ID file")
	pf.StringVar(&opts.writerLock, "writer-lock", fabricconfig.DefaultWriterLock,
		"File every FRR writer on the node locks while it changes FRR")
	pf.StringVar(&opts.bootRecord, "boot-record", fabricconfig.DefaultBootRecord,
		"File where init records the source FRR started from, for watch to export")
	cmd.Flags().Bool("build-info", false, "Print build information and exit")
	cmd.Flags().BoolP("version", "V", false, "Print version and exit")

	cmd.AddCommand(&cobra.Command{
		Use:   "init",
		Short: "Install this node's configuration, waiting until it exists and validates",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return run(cmd.Context(), opts, func(a *fabricconfig.Agent, ctx context.Context) error {
				return initNode(ctx, a, opts)
			})
		},
	})
	watch := &cobra.Command{
		Use:   "watch",
		Short: "Apply changes to this node's configuration to the running FRR instance",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return run(cmd.Context(), opts, func(a *fabricconfig.Agent, ctx context.Context) error {
				return watchWithGuard(ctx, a, opts)
			})
		},
	}
	watch.Flags().StringVar(&opts.metricsBindAddress, "metrics-bind-address", ":9343",
		"Address serving the next-hop check's and the activation path's Prometheus metrics at /metrics; "+
			"empty disables them")
	watch.Flags().BoolVar(&opts.nextHopDetectOnly, "detect-only", false,
		"Report IPv6 sessions announcing an IPv4-mapped next hop without resetting them")
	cmd.AddCommand(watch)
	logOpts.BindFlags(pf)
	return cmd
}

// run builds an agent from opts and calls fn with it until fn returns or the
// process is signalled.
func run(parent context.Context, opts *options, fn func(*fabricconfig.Agent, context.Context) error) error {
	if opts.nodeName == "" {
		return errors.New("--node-name (or NODE_NAME) is required")
	}
	if opts.namespace == "" {
		return errors.New("--namespace (or POD_NAMESPACE) is required")
	}
	if !opts.configMaps && !opts.activation {
		return errors.New("--configmaps=false (or FABRIC_CONFIGMAPS=false) needs --activation (or FABRIC_ACTIVATION=true)")
	}
	if parent == nil {
		parent = context.Background()
	}
	ctx, stop := signal.NotifyContext(parent, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	restCfg, err := ctrlconfig.GetConfig()
	if err != nil {
		return fmt.Errorf("load Kubernetes client configuration: %w", err)
	}
	client, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		return fmt.Errorf("create Kubernetes client: %w", err)
	}

	broadcaster := events.NewBroadcaster(&events.EventSinkImpl{Interface: client.EventsV1()})
	if err := broadcaster.StartRecordingToSinkWithContext(ctx); err != nil {
		return fmt.Errorf("start event recording: %w", err)
	}
	defer broadcaster.Shutdown()

	agent := &fabricconfig.Agent{
		Client:            client,
		Recorder:          broadcaster.NewRecorder(clientgoscheme.Scheme, appName),
		FRR:               fabricconfig.ExecFRR{Vtysh: opts.vtysh, Reloader: opts.reloader, ConfigDir: opts.configDir},
		Namespace:         opts.namespace,
		NodeName:          opts.nodeName,
		LegacyConfigMap:   opts.legacyConfigMap,
		ConfigMapsRetired: !opts.configMaps,
		ConfigDir:         opts.configDir,
		DefaultsDir:       opts.defaultsDir,
		Lock:              fabricconfig.FileLock{Path: opts.writerLock},
	}
	if opts.podName != "" {
		agent.Pod = &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
			Name:      opts.podName,
			Namespace: opts.namespace,
			UID:       types.UID(opts.podUID),
		}}
	}

	opts.restCfg = restCfg

	slog.Info("starting "+appName, "version", metadata.Version, "node", opts.nodeName, "namespace", opts.namespace,
		"activation", opts.activation, "configMaps", opts.configMaps)
	return fn(agent, ctx)
}

// initNode installs the node's configuration and records where it came
// from for the watch container, which has the metrics server this
// container lacks. An earlier init's record is removed first, so a record
// that cannot be written leaves none rather than a stale one. Failing to
// remove or write it stops nothing.
func initNode(ctx context.Context, a *fabricconfig.Agent, opts *options) error {
	if err := fabricconfig.ClearBootRecord(opts.bootRecord); err != nil {
		slog.Warn("could not remove an earlier boot record", "error", err)
	}
	rec := fabricconfig.BootRecord{Source: fabricconfig.BootConfigMap}
	if err := installNode(ctx, a, opts, &rec); err != nil {
		return err
	}
	if err := fabricconfig.WriteBootRecord(opts.bootRecord, rec); err != nil {
		slog.Warn("could not record the boot source", "error", err)
	}
	return nil
}

// installNode installs the node's configuration: from the activation state
// when the node is on the CRD source or its ConfigMap path is retired,
// otherwise from its ConfigMap, and sets rec to the source it used. Only a
// node on CRD needs its machine ID and identity, so a fault in either
// never stops a ConfigMap node from starting.
func installNode(ctx context.Context, a *fabricconfig.Agent, opts *options, rec *fabricconfig.BootRecord) error {
	if !opts.activation {
		return a.Init(ctx)
	}
	d, err := newDeploymentAgent(ctx, opts, nil)
	if err != nil {
		// A corrupt journal leaves the source unknown; starting from the
		// ConfigMap could leave CRD without a handoff, so nothing starts
		// until an operator repairs or removes the state.
		return err
	}
	return a.InitActivated(ctx, d, rec)
}

// newDeploymentAgent opens the activation state and builds the deployment
// agent. It reads the node's identity from the API once; when that fails,
// as at an offline boot, the agent resolves it later. A missing machine ID
// or state bound to another Node, cluster or machine is kept as
// IdentityErr: the state is left untouched and nothing is activated. A
// non-nil metrics counts its activations and times its writer locks.
func newDeploymentAgent(
	ctx context.Context, opts *options, metrics *fabricconfig.AgentMetrics,
) (*fabricconfig.DeploymentAgent, error) {
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		return nil, err
	}
	if err := networkv1alpha1.AddToScheme(scheme); err != nil {
		return nil, err
	}
	// Every request is bounded, API discovery included, which ignores the
	// request's context: a node booting without the API waits this long
	// before it restores its checkpoint.
	cfg := rest.CopyConfig(opts.restCfg)
	cfg.Timeout = apiTimeout
	c, err := ctrlclient.New(cfg, ctrlclient.Options{Scheme: scheme})
	if err != nil {
		return nil, fmt.Errorf("create Kubernetes client: %w", err)
	}
	frr := fabricconfig.ExecFRR{Vtysh: opts.vtysh, Reloader: opts.reloader, ConfigDir: opts.configDir}
	if err := os.MkdirAll(opts.stateDir, 0o700); err != nil {
		return nil, err
	}
	act := &activation.Activator{
		Dir: opts.stateDir, FRR: frr, Lock: writerLock(opts, metrics, fabricconfig.WriterActivation),
	}
	if err := act.Open(); err != nil {
		return nil, err
	}
	d := &fabricconfig.DeploymentAgent{
		Client: c, Namespace: opts.namespace, NodeName: opts.nodeName,
		Activator: act, BGP: frr, ConfigDir: opts.configDir, Version: metadata.Version,
		Lock: writerLock(opts, metrics, fabricconfig.WriterDeployment), Metrics: metrics,
		ConfigMapsRetired: !opts.configMaps,
	}
	d.MachineID, err = activation.ReadMachineID(opts.machineIDFile)
	if err != nil {
		d.IdentityErr = fmt.Errorf("%w: %w", activation.ErrIdentityMismatch, err)
	}
	d.Resolve = func(ctx context.Context) error {
		lookup, cancel := context.WithTimeout(ctx, apiTimeout)
		defer cancel()
		nodeUID, clusterID, err := identity(lookup, c, opts.nodeName)
		if err != nil {
			return err
		}
		d.NodeUID, d.ClusterID = nodeUID, clusterID
		if d.IdentityErr != nil {
			return nil
		}
		id := activation.Identity{NodeUID: nodeUID, MachineID: d.MachineID, ClusterID: clusterID}
		if _, err := activation.BindIdentity(opts.stateDir, id); errors.Is(err, activation.ErrIdentityMismatch) {
			// Fail closed: the journal, epoch marks and checkpoint are
			// kept, and nothing is activated until an operator removes
			// the state directory on the host.
			d.IdentityErr = err
			slog.Error("activation state belongs to another Node, cluster or machine; activating nothing",
				"error", err, "stateDir", opts.stateDir)
		} else if err != nil {
			return err
		}
		return nil
	}
	if err := d.Resolve(ctx); err != nil {
		slog.Warn("could not read this node's identity from the API; resolving it later", "error", err)
	}
	return d, nil
}

// identity reads the Node's UID and the cluster's ID, the kube-system
// namespace UID.
func identity(ctx context.Context, c ctrlclient.Client, nodeName string) (nodeUID, clusterID string, err error) {
	var node corev1.Node
	if err := c.Get(ctx, types.NamespacedName{Name: nodeName}, &node); err != nil {
		return "", "", fmt.Errorf("read Node %s: %w", nodeName, err)
	}
	var ns corev1.Namespace
	if err := c.Get(ctx, types.NamespacedName{Name: metav1.NamespaceSystem}, &ns); err != nil {
		return "", "", fmt.Errorf("read the cluster ID: %w", err)
	}
	return string(node.UID), string(ns.UID), nil
}

// writerLock is the node's FRR writer lock for one writer, timed when
// metrics is non-nil.
func writerLock(opts *options, metrics *fabricconfig.AgentMetrics, writer string) fabricconfig.Locker {
	lock := fabricconfig.FileLock{Path: opts.writerLock}
	if metrics == nil {
		return lock
	}
	return fabricconfig.TimedLock{Locker: lock, Metrics: metrics, Writer: writer}
}

// watchWithGuard runs a.Watch alongside a NextHopGuard over the same FRR
// instance, and serves the guard's and the activation path's metrics, and
// the boot source init recorded, when opts asks for them. With the
// ConfigMap path retired it runs only the deployment agent and the guard
// until ctx ends.
func watchWithGuard(ctx context.Context, a *fabricconfig.Agent, opts *options) error {
	metrics := fabricconfig.NewNextHopMetrics()
	agentMetrics := fabricconfig.NewAgentMetrics(metrics.Registry)
	if rec, err := fabricconfig.ReadBootRecord(opts.bootRecord); err == nil {
		agentMetrics.SetBoot(rec.Source)
	} else {
		slog.Warn("could not read the boot source init recorded", "error", err)
	}
	a.Lock = writerLock(opts, agentMetrics, fabricconfig.WriterConfigMap)
	guard := &fabricconfig.NextHopGuard{
		BGP:        fabricconfig.ExecFRR{Vtysh: opts.vtysh, Reloader: opts.reloader, ConfigDir: opts.configDir},
		Metrics:    metrics,
		Recorder:   a.Recorder,
		Pod:        a.Pod,
		NodeName:   a.NodeName,
		DetectOnly: opts.nextHopDetectOnly,
		Lock:       writerLock(opts, agentMetrics, fabricconfig.WriterNextHop),
	}
	if opts.activation {
		d, err := newDeploymentAgent(ctx, opts, agentMetrics)
		if err != nil {
			// The source is unknown: hold the ConfigMap path off FRR, as on
			// CRD, while the guard keeps running.
			slog.Error("could not open the activation state; no configuration will be applied", "error", err)
			a.Gate = fabricconfig.NewSourceGate(networkv1alpha1.FabricConfigSourceCRD)
		} else {
			gate := fabricconfig.NewSourceGate(fabricconfig.JournalSource(d.Activator.Journal()))
			gate.SetHandoff(d.Activator.Journal().Handoff())
			a.Gate, d.Gate = gate, gate
			go d.Run(ctx)
		}
	}

	if opts.metricsBindAddress != "" {
		mux := http.NewServeMux()
		mux.Handle("/metrics", metrics.Handler())
		srv := &http.Server{
			Addr:              opts.metricsBindAddress,
			Handler:           mux,
			ReadHeaderTimeout: 5 * time.Second,
		}
		go func() {
			if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				slog.Error("metrics server exited with error", "error", err)
			}
		}()
		defer func() {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := srv.Shutdown(shutdownCtx); err != nil {
				slog.Warn("could not shut down metrics server", "error", err)
			}
		}()
	}

	go guard.Run(ctx)
	if !opts.configMaps {
		<-ctx.Done()
		return nil
	}
	return a.Watch(ctx)
}
