// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"go.datum.net/galactic/internal/installer"
	"go.datum.net/galactic/internal/metadata"
)

const (
	appName = "galactic-cni"

	appDesc = `Galactic CNI installer

 Bootstraps and maintains the CNI plugin chain on a node: stages every
 chain binary (galactic-veth, galactic-tap, galactic-ipam, galactic-bgp,
 galactic-route, host-device) into /opt/cni/bin, writes the static
 conflist and kubeconfig, and (via "run") keeps credentials fresh and
 drives the eBPF uSID datapath. This binary is never itself a CNI plugin —
 the container runtime never execs it via a NAD's "type" field, only the
 galactic-cni DaemonSet's own init/run containers do.

 Find more information at: https://www.datum.net/docs`
)

func newInitCommand() *cobra.Command {
	var nodeName string

	initCmd := &cobra.Command{
		Use:   "init",
		Short: "One-shot bootstrap of CNI binaries and configuration",
		RunE: func(cmd *cobra.Command, args []string) error {
			if nodeName == "" {
				nodeName = os.Getenv("GALACTIC_CNI_NODE_NAME")
			}
			if nodeName == "" {
				nodeName = os.Getenv("NODE_NAME")
			}
			if nodeName == "" {
				return errors.New("node name is required (use --node-name flag or GALACTIC_CNI_NODE_NAME env var)")
			}
			return installer.Bootstrap(cmd.Context(), nodeName)
		},
	}
	initCmd.Flags().StringVarP(&nodeName, "node-name", "n", "", "Kubernetes node name")
	return initCmd
}

func newRunCommand() *cobra.Command {
	var grpcHealthPort int
	var metricsPort int

	runCmd := &cobra.Command{
		Use:   "run",
		Short: "Lightweight run loop to refresh credentials and run gRPC health server",
		RunE: func(cmd *cobra.Command, args []string) error {
			return installer.Run(cmd.Context(), grpcHealthPort, metricsPort)
		},
	}
	runCmd.Flags().IntVar(&grpcHealthPort, "grpc-health-port", 5180, "gRPC health check port")
	// 8082, not 9091: Prometheus's own default-port-allocations registry
	// reserves 9090-9093 for Prometheus/Pushgateway/Alertmanager and 9100+
	// for named exporters (9100 itself is node_exporter, near-universal on
	// real hosts) -- squatting on either would risk a real collision on a
	// hostNetwork: true node. 8082 continues galactic's own internal
	// metrics-port convention instead (galactic-router: 8080,
	// galactic-gateway: 8081).
	runCmd.Flags().IntVar(&metricsPort, "metrics-port", 8082, "Prometheus metrics HTTP port")
	return runCmd
}

func newRootCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   appName,
		Short: strings.Split(appDesc, "\n")[0],
		Long:  appDesc,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if ok, _ := cmd.Flags().GetBool("build-info"); ok {
				fmt.Println(metadata.BuildInfo(appName))
				return nil
			}
			if ok, _ := cmd.Flags().GetBool("version"); ok {
				fmt.Printf("galactic-cni version %s\n", metadata.Version)
				return nil
			}
			return cmd.Help()
		},
	}

	cmd.Flags().Bool("build-info", false, "Print build information and exit")
	cmd.Flags().BoolP("version", "V", false, "Print version and exit")

	cmd.AddCommand(newInitCommand(), newRunCommand())
	return cmd
}

func main() {
	if err := newRootCommand().Execute(); err != nil {
		log.Fatalf("error: %v", err)
	}
}
