// Command galactic-agent is the node-local execution agent for Galactic.
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"go.datum.net/galactic/internal/agent"
)

func main() {
	if err := newRootCommand().ExecuteContext(context.Background()); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func newRootCommand() *cobra.Command {
	opts := &agent.Options{}

	cmd := &cobra.Command{
		Use:          "galactic-agent",
		Short:        "Node-local execution agent for Galactic VPC networking",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return agent.Run(cmd.Context(), *opts)
		},
	}

	cmd.Flags().StringVar(&opts.MetricsAddr, "metrics-addr", ":8082", "Address to serve Prometheus metrics on")
	cmd.Flags().StringVar(&opts.HealthAddr, "health-addr", ":8083", "Address to serve health/readiness probes on")
	cmd.Flags().StringVar(&opts.NodeName, "node-name", "", "Override node name (default: NODE_NAME env var)")
	cmd.Flags().StringVar(&opts.Plane, "plane", "overlay",
		"BGP plane label published on the BGPProvider (e.g. overlay, overlay-rr)")
	cmd.Flags().BoolVar(&opts.GoBGPEnabled, "gobgp-enabled", false,
		"Enable embedded GoBGP and publish BGPProvider")
	cmd.Flags().IntVar(&opts.GoBGPAPIPort, "gobgp-api-port", 50051,
		"Port for the embedded GoBGP gRPC API (cosmos dials this)")
	cmd.Flags().StringVar(&opts.GoBGPLogLevel, "gobgp-log-level", "panic",
		"GoBGP internal log level (debug, info, warn, error, panic)")
	cmd.Flags().IntVar(&opts.GRPCHealthPort, "grpc-health-port", 8084,
		"Port for the gRPC health service (used by Kubernetes readiness probes)")

	return cmd
}
