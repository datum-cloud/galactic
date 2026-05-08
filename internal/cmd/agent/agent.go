// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"context"
	"fmt"
	"log"
	"net"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/sync/errgroup"
	ctrl "sigs.k8s.io/controller-runtime"

	agentbgp "go.datum.net/galactic/internal/agent/bgp"
	agentcache "go.datum.net/galactic/internal/agent/cache"
	"go.datum.net/galactic/internal/agent/health"
	"go.datum.net/galactic/internal/agent/program"
	"go.datum.net/galactic/internal/agent/reconciler"
	"go.datum.net/galactic/internal/agent/srv6/routeingress"
	"go.datum.net/galactic/pkg/common/util"
	"go.datum.net/galactic/pkg/proto/local"
)

type agentFlags struct {
	configFile string
}

func NewCommand() *cobra.Command {
	flags := &agentFlags{}

	cmd := &cobra.Command{
		Use:   "agent",
		Short: "Run the Galactic network agent",
		Long: `The agent runs on each node and manages local SRv6 routes and VRF configurations.
It communicates with the CNI plugin via a local gRPC socket and with a BGP route
reflector via embedded GoBGP.`,
		PreRun: func(cmd *cobra.Command, args []string) {
			initConfig(flags.configFile)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAgent()
		},
	}

	cmd.Flags().StringVar(&flags.configFile, "config", "", "Config file path")
	cmd.Flags().String("srv6-net", "fc00::/56",
		"SRv6 service-SID locator (POP-locator). Same value as the operator's --pop-locator.")
	cmd.Flags().String("socket-path", "/var/run/galactic/agent.sock",
		"Unix socket path for CNI communication")

	cmd.Flags().String("node-locator", "",
		"IPv6 address advertised as BGP next-hop for routes this node originates. Required.")
	cmd.Flags().String("bgp-router-id", "",
		"IPv4-formatted BGP router-id. Required.")
	cmd.Flags().Uint32("bgp-asn", 0,
		"Local ASN. Must match the operator's --asn. Required.")
	cmd.Flags().StringSlice("bgp-rr-peer", nil,
		"Route reflector address(es), repeatable. At least one required.")
	cmd.Flags().String("bgp-rr-password", "",
		"Optional MD5/TCP-AO secret shared with the RR.")
	cmd.Flags().Int32("bgp-listen-port", 179,
		"Local TCP port for inbound BGP connections.")
	cmd.Flags().String("bgp-srv6-encoding", "tunnel-encap",
		"SRv6 service-SID wire format. tunnel-encap (default) or prefix-sid. Cluster-wide.")
	cmd.Flags().String("health-bind-address", ":8081",
		"Address for the /healthz and /metrics HTTP server.")

	for _, k := range []struct{ flag, key string }{
		{"srv6-net", "srv6_net"},
		{"socket-path", "socket_path"},
		{"node-locator", "node_locator"},
		{"bgp-router-id", "bgp_router_id"},
		{"bgp-asn", "bgp_asn"},
		{"bgp-rr-peer", "bgp_rr_peer"},
		{"bgp-rr-password", "bgp_rr_password"},
		{"bgp-listen-port", "bgp_listen_port"},
		{"bgp-srv6-encoding", "bgp_srv6_encoding"},
		{"health-bind-address", "health_bind_address"},
	} {
		_ = viper.BindPFlag(k.key, cmd.Flags().Lookup(k.flag))
	}

	return cmd
}

func initConfig(configFile string) {
	viper.SetDefault("srv6_net", "fc00::/56")
	viper.SetDefault("socket_path", "/var/run/galactic/agent.sock")
	viper.SetDefault("bgp_listen_port", 179)
	viper.SetDefault("bgp_srv6_encoding", "tunnel-encap")
	viper.SetDefault("health_bind_address", ":8081")

	if configFile != "" {
		viper.SetConfigFile(configFile)
	}

	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err == nil {
		log.Printf("Using config file: %s\n", viper.ConfigFileUsed())
	} else {
		log.Printf("No config file found - using defaults and environment variables")
	}
}

func runAgent() error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if _, err := util.EncodeSRv6Endpoint(viper.GetString("srv6_net"), "ffffffff", "ffff"); err != nil {
		log.Fatalf("srv6_net invalid: %v", err)
	}

	nodeLocator := net.ParseIP(viper.GetString("node_locator"))
	if nodeLocator == nil {
		return fmt.Errorf("--node-locator required")
	}
	asn := viper.GetUint32("bgp_asn")
	if asn == 0 {
		return fmt.Errorf("--bgp-asn required")
	}
	rrPeers := viper.GetStringSlice("bgp_rr_peer")
	if len(rrPeers) == 0 {
		return fmt.Errorf("at least one --bgp-rr-peer required")
	}

	cfg, err := ctrl.GetConfig()
	if err != nil {
		return fmt.Errorf("rest config: %w", err)
	}
	attCache, err := agentcache.New(cfg)
	if err != nil {
		return fmt.Errorf("attachment cache: %w", err)
	}
	if err := attCache.Start(ctx); err != nil {
		return fmt.Errorf("attachment cache start: %w", err)
	}

	bgpCfg := agentbgp.Config{
		LocalASN:    asn,
		RouterID:    viper.GetString("bgp_router_id"),
		ListenPort:  int32(viper.GetInt("bgp_listen_port")),
		NodeLocator: nodeLocator,
		Encoding:    agentbgp.Encoding(viper.GetString("bgp_srv6_encoding")),
	}
	for _, addr := range rrPeers {
		bgpCfg.Peers = append(bgpCfg.Peers, agentbgp.PeerConfig{
			Address:  addr,
			Password: viper.GetString("bgp_rr_password"),
		})
	}
	bgpServer, err := agentbgp.NewServer(bgpCfg)
	if err != nil {
		return fmt.Errorf("bgp server: %w", err)
	}
	if err := bgpServer.Start(ctx); err != nil {
		return fmt.Errorf("bgp start: %w", err)
	}

	g, ctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		<-ctx.Done()
		// Graceful shutdown: send NOTIFICATION Cease before tearing
		// down internal goroutines. Avoids ~3 minutes of RR-side
		// hold-timer expiry.
		shutdownCtx, cancel := context.WithCancel(context.Background())
		defer cancel()
		bgpServer.Stop(shutdownCtx)
		return nil
	})

	rec := reconciler.New(reconciler.Config{
		BGP:      bgpServer,
		Egress:   programEgress{},
		Ingress:  ingressAdapter{},
		Cache:    attCache,
		NodeNext: nodeLocator,
	})

	g.Go(func() error {
		return rec.Run(ctx, attCache.Events(), bgpServer.ReceivedRoutes(), bgpServer.SessionEvents())
	})

	healthSrv := health.New(health.Config{
		ListenAddr: viper.GetString("health_bind_address"),
		SocketPath: viper.GetString("socket_path"),
		BGP:        bgpServer,
		Cache:      attCache,
		Recon:      rec,
	})
	g.Go(func() error { return healthSrv.Run(ctx) })

	l := local.Local{
		SocketPath: viper.GetString("socket_path"),
		RegisterHandler: func(vpcHex, attachHex string) error {
			rec.OnRegister(ctx, vpcHex, attachHex)
			return nil
		},
		DeregisterHandler: func(vpcHex, attachHex string) error {
			rec.OnDeregister(ctx, vpcHex, attachHex)
			return nil
		},
	}
	g.Go(func() error { return l.Serve(ctx) })

	if err := g.Wait(); err != nil {
		log.Printf("Error: %v", err)
		return err
	}
	log.Printf("Shutdown complete")
	return nil
}

// programEgress adapts internal/agent/program to the reconciler interface.
type programEgress struct{}

func (programEgress) Add(vpcHex, attachHex string, prefix *net.IPNet, segments []net.IP) error {
	return program.Add(vpcHex, attachHex, prefix, segments)
}
func (programEgress) Delete(vpcHex, attachHex string, prefix *net.IPNet) error {
	return program.Delete(vpcHex, attachHex, prefix)
}

// ingressAdapter wraps routeingress.Add / .Delete.
type ingressAdapter struct{}

func (ingressAdapter) Add(serviceSID *net.IPNet, vpcB62, attachB62 string) error {
	return routeingress.Add(serviceSID, vpcB62, attachB62)
}
func (ingressAdapter) Delete(serviceSID *net.IPNet, vpcB62, attachB62 string) error {
	return routeingress.Delete(serviceSID, vpcB62, attachB62)
}
