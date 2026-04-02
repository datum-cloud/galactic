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

package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	bgpcontroller "go.miloapis.com/bgp/internal/controller"
	"go.miloapis.com/bgp/internal/routesync"
)

func main() {
	if err := newRootCommand().Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

type options struct {
	gobgpAddr     string
	localEndpoint string
	srv6Net       string
	metricsAddr   string
	healthAddr    string
}

func newRootCommand() *cobra.Command {
	opts := &options{}

	cmd := &cobra.Command{
		Use:   "bgp",
		Short: "BGP operator — reconciles BGP CRDs against a GoBGP sidecar",
		Long: `The BGP operator runs as a DaemonSet alongside a GoBGP sidecar container.
It reconciles BGPConfiguration, BGPSession, BGPPeeringPolicy, BGPAdvertisement,
and BGPRoutePolicy CRDs into GoBGP gRPC calls, and programs netlink routes from
BGP RIB events received from the sidecar.`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return run(cmd.Context(), opts)
		},
	}

	cmd.Flags().StringVar(&opts.gobgpAddr, "gobgp-addr", "127.0.0.1:50051", "GoBGP gRPC address")
	cmd.Flags().StringVar(&opts.localEndpoint, "local-endpoint", os.Getenv("LOCAL_ENDPOINT"), "Name of the local BGPEndpoint resource for this instance (defaults to LOCAL_ENDPOINT env var)")
	cmd.Flags().StringVar(&opts.srv6Net, "srv6-net", os.Getenv("SRV6_NET"), "This node's SRv6 prefix to exclude from route programming (defaults to SRV6_NET env var)")
	cmd.Flags().StringVar(&opts.metricsAddr, "metrics-addr", ":8082", "Address to serve Prometheus metrics on")
	cmd.Flags().StringVar(&opts.healthAddr, "health-addr", ":8083", "Address to serve health/readiness probes on")

	return cmd
}

func run(ctx context.Context, opts *options) error {
	ctx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if opts.localEndpoint == "" {
		return fmt.Errorf("--local-endpoint or LOCAL_ENDPOINT env var is required")
	}

	log.Printf("bgp: starting (endpoint=%s gobgp=%s srv6-net=%q)", opts.localEndpoint, opts.gobgpAddr, opts.srv6Net)

	return bgpcontroller.Run(ctx, bgpcontroller.ControllerOptions{
		LocalEndpoint: opts.localEndpoint,
		SRv6Net:       opts.srv6Net,
		GoBGPAddr:     opts.gobgpAddr,
		MetricsAddr:   opts.metricsAddr,
		HealthAddr:    opts.healthAddr,
	}, routesync.RunRouteWatcher)
}
