// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"context"
	"log"

	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"go.datum.net/galactic/internal/agent/srv6"
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
It communicates with the CNI plugin via a local gRPC socket.`,
		PreRun: func(cmd *cobra.Command, args []string) {
			initConfig(flags.configFile)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAgent()
		},
	}

	cmd.Flags().StringVar(&flags.configFile, "config", "", "Config file path")
	cmd.Flags().String("srv6-net", "fc00::/56", "SRv6 network CIDR")
	cmd.Flags().String("socket-path", "/var/run/galactic/agent.sock", "Unix socket path for CNI communication")

	_ = viper.BindPFlag("srv6_net", cmd.Flags().Lookup("srv6-net"))
	_ = viper.BindPFlag("socket_path", cmd.Flags().Lookup("socket-path"))

	return cmd
}

func initConfig(configFile string) {
	viper.SetDefault("srv6_net", "fc00::/56")
	viper.SetDefault("socket_path", "/var/run/galactic/agent.sock")

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

	_, err := util.EncodeSRv6Endpoint(viper.GetString("srv6_net"), "ffffffffffff", "ffff")
	if err != nil {
		log.Fatalf("srv6_net invalid: %v", err)
	}

	l := local.Local{
		SocketPath: viper.GetString("socket_path"),
		RegisterHandler: func(vpc, vpcAttachment string, networks []string) error {
			srv6Endpoint, err := util.EncodeSRv6Endpoint(viper.GetString("srv6_net"), vpc, vpcAttachment)
			if err != nil {
				return err
			}
			if err := srv6.RouteIngressAdd(srv6Endpoint); err != nil {
				return err
			}
			for _, n := range networks {
				log.Printf("REGISTER: network='%s', srv6_endpoint='%s'", n, srv6Endpoint)
			}
			return nil
		},
		DeregisterHandler: func(vpc, vpcAttachment string, networks []string) error {
			srv6Endpoint, err := util.EncodeSRv6Endpoint(viper.GetString("srv6_net"), vpc, vpcAttachment)
			if err != nil {
				return err
			}
			if err := srv6.RouteIngressDel(srv6Endpoint); err != nil {
				return err
			}
			for _, n := range networks {
				log.Printf("DEREGISTER: network='%s', srv6_endpoint='%s'", n, srv6Endpoint)
			}
			return nil
		},
	}

	if err := l.Serve(ctx); err != nil {
		log.Printf("Error: %v", err)
		return err
	}

	log.Printf("Shutdown complete")
	return nil
}
