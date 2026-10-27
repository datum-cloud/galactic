// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

// Command masqueprovider is the Galactic Edge conformance suite's MASQUE
// fixture: a CONNECT-IP (RFC 9484) server over HTTP/3 that runs as an
// unprivileged Galactic Edge provider. It uses only the provider contract
// and its helpers in internal/edge/provider: it holds its EdgeInstance's
// lease, requests one PacketAccess attachment per configured EdgeService,
// claims one EdgeRoute per connector /96, and carries each admitted
// connector's packets through internal/edge/connectip's TUN backend on the
// packet device galactic-edge creates in its pod. It needs no host
// namespace, hostPath, NET_ADMIN or BPF.
//
// Admission is a test fixture, not a product authority: each connector is a
// static bearer credential bound to one service's VPC and one /96, admitted
// only while the instance holds its lease and core has accepted the
// connector's route on a programmed attachment. Expiry or loss of any of
// them ends the connector's session.
//
// SIGTERM ends every session, then releases the routes, deletes the
// attachments and releases the lease.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	coordinationv1 "k8s.io/api/coordination/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
	"go.datum.net/galactic/internal/edge/claim"
	"go.datum.net/galactic/internal/edge/connectip"
	"go.datum.net/galactic/internal/edge/provider"
	"go.datum.net/galactic/internal/edge/timing"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "masqueprovider:", err)
		os.Exit(1)
	}
}

func run() error {
	configPath := flag.String("config", "/etc/masque/config.yaml", "configuration file")
	certPath := flag.String("tls-cert", "/etc/masque/tls/tls.crt", "server certificate")
	keyPath := flag.String("tls-key", "/etc/masque/tls/tls.key", "server key")
	flag.Parse()
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	cfg, err := LoadConfig(*configPath)
	if err != nil {
		return err
	}
	cert, err := tls.LoadX509KeyPair(*certPath, *keyPath)
	if err != nil {
		return err
	}
	pod, err := podFromEnv()
	if err != nil {
		return err
	}
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{galacticv1alpha1.AddToScheme, coordinationv1.AddToScheme} {
		if err := add(scheme); err != nil {
			return err
		}
	}
	rest, err := ctrl.GetConfig()
	if err != nil {
		return err
	}
	// Every request gives up well before the next renewal is due.
	rest.Timeout = 3 * time.Second
	c, err := client.New(rest, client.Options{Scheme: scheme})
	if err != nil {
		return err
	}

	p := &Provider{
		Client: c, Log: log.With("pod", pod.Name), Config: cfg, Pod: pod, Clock: timing.BootClock,
		Renew: timing.RenewInterval, OpenTUN: openTUN,
		Claims: &claim.Instance{
			ID: newHolderID(), Clock: timing.BootClock, Params: timing.Params,
			Store: provider.InstanceStore{Client: c, Namespace: pod.Namespace, Duration: timing.Params.Duration},
		},
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	if err := p.Start(ctx); err != nil {
		return err
	}

	srv, err := connectip.NewServer(connectip.Config{
		Authority: cfg.Authority,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13},
		Admission: p, Backend: p, Logger: log,
	})
	if err != nil {
		return err
	}
	pc, err := (&net.ListenConfig{}).ListenPacket(ctx, "udp", cfg.Listen)
	if err != nil {
		return err
	}
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(pc) }()

	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		if err := p.Reconcile(ctx); err != nil {
			_ = srv.Close()
			return err
		}
		select {
		case <-ctx.Done():
			// Sessions end before the routes are released.
			_ = srv.Close()
			sctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			return p.Shutdown(sctx)
		case err := <-serveErr:
			sctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			return errors.Join(fmt.Errorf("HTTP/3 server stopped: %w", err), p.Shutdown(sctx))
		case <-t.C:
		}
	}
}

// podFromEnv reads the pod's identity from the downward API variables the
// Deployment sets, and the node's boot ID.
func podFromEnv() (Pod, error) {
	p := Pod{
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

// openTUN attaches to the existing TUN device name as its owner, which
// needs no capability, and returns a nonblocking descriptor without
// packet-information headers.
func openTUN(name string) (*os.File, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open /dev/net/tun: %w", err)
	}
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)
	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("attach to TUN %s: %w", name, err)
	}
	return os.NewFile(uintptr(fd), name), nil
}
