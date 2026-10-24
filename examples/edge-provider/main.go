// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Command edge-provider is a reference Galactic Edge provider. It uses only
// the provider contract: the galactic.datumapis.com/v1alpha1 resources, its
// own ServiceAccount, and the attachment galactic-edge programs into its
// pod. It needs no host access, no NET_ADMIN and no BPF.
//
// It answers UDP on each attachment's address and, for a PacketAccess
// attachment, ICMPv6 echo and UDP for every address in the prefixes it
// claims, replying with "<provider>/<pod>/<service>" so a client can tell
// which instance served it.
//
// SIGTERM stops forwarding and releases its claims, attachments and lease.
// SIGUSR1 freezes it: it stops renewing its lease and writing to the API,
// while its data planes keep answering, even past the lease's deadline, as
// a provider that hung and ignores its lease would. Conformance tests use
// it to show galactic-edge stops forwarding on its own.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/datum-cloud/galactic/examples/edge-provider/internal/config"
	"github.com/datum-cloud/galactic/examples/edge-provider/internal/lease"
	"github.com/datum-cloud/galactic/examples/edge-provider/internal/provider"
	coordinationv1 "k8s.io/api/coordination/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "edge-provider:", err)
		os.Exit(1)
	}
}

func run() error {
	configPath := flag.String("config", "/etc/edge-provider/config.yaml", "configuration file")
	debug := flag.Bool("debug", false, "log at debug level")
	flag.Parse()

	level := slog.LevelInfo
	if *debug {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	pod, err := podFromEnv()
	if err != nil {
		return err
	}
	scheme := runtime.NewScheme()
	if err := galacticv1alpha1.AddToScheme(scheme); err != nil {
		return err
	}
	if err := coordinationv1.AddToScheme(scheme); err != nil {
		return err
	}
	rest, err := ctrl.GetConfig()
	if err != nil {
		return err
	}
	// Every API request gives up well before the next renewal is due, so
	// a hung request never holds up a renewal for long.
	rest.Timeout = 3 * time.Second
	c, err := client.New(rest, client.Options{Scheme: scheme})
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	freeze := make(chan struct{})
	usr1 := make(chan os.Signal, 1)
	signal.Notify(usr1, syscall.SIGUSR1)
	go func() {
		<-usr1
		close(freeze)
	}()

	p := &provider.Provider{
		Client: c, Log: log.With("pod", pod.Name), Config: cfg, Pod: pod,
		Clock: lease.BootTime, Params: lease.Contract, Tick: time.Second, RetryAfter: 10 * time.Second,
	}
	shutdown := func() (context.Context, context.CancelFunc) {
		return context.WithTimeout(context.Background(), 20*time.Second)
	}
	return p.Run(ctx, shutdown, freeze)
}

// podFromEnv reads the pod's identity from the downward API variables the
// Deployment sets, and the node's boot ID.
func podFromEnv() (provider.Pod, error) {
	p := provider.Pod{
		Namespace: os.Getenv("POD_NAMESPACE"), Name: os.Getenv("POD_NAME"), UID: os.Getenv("POD_UID"),
		Node: os.Getenv("NODE_NAME"), RunAsUser: int64(os.Getuid()), RunAsGroup: int64(os.Getgid()),
	}
	if p.Namespace == "" || p.Name == "" || p.UID == "" || p.Node == "" {
		return p, errors.New("POD_NAMESPACE, POD_NAME, POD_UID and NODE_NAME must be set")
	}
	b, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return p, fmt.Errorf("read boot ID: %w", err)
	}
	p.BootID = strings.TrimSpace(string(b))
	return p, nil
}
