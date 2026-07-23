// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/containernetworking/cni/pkg/version"
	"github.com/spf13/cobra"

	"go.datum.net/galactic/internal/cni"
	"go.datum.net/galactic/internal/installer"
	"go.datum.net/galactic/internal/metadata"
)

const (
	appName = "galactic-cni"

	appDesc = `Galactic CNI Plugin

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

	runCmd := &cobra.Command{
		Use:   "run",
		Short: "Lightweight run loop to refresh credentials and run gRPC health server",
		RunE: func(cmd *cobra.Command, args []string) error {
			return installer.Run(cmd.Context(), grpcHealthPort)
		},
	}
	runCmd.Flags().IntVar(&grpcHealthPort, "grpc-health-port", 5180, "gRPC health check port")
	return runCmd
}

func newRootCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   appName,
		Short: strings.Split(appDesc, "\n")[0],
		Long:  appDesc,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			cni.InitCNIConfig()
			confFile, _ := cmd.Flags().GetString("conf-file")
			if confFile != "" {
				cni.ConfFile = confFile
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			if ok, _ := cmd.Flags().GetBool("build-info"); ok {
				fmt.Println(metadata.BuildInfo(appName))
				return nil
			}
			if ok, _ := cmd.Flags().GetBool("version"); ok {
				fmt.Printf("galactic-cni version %s\n", metadata.Version)
				return nil
			}
			// Handle CNI_COMMAND=VERSION before config validation
			if os.Getenv("CNI_COMMAND") == "VERSION" {
				return version.All.Encode(os.Stdout)
			}

			// Read stdin once so we can inspect the CNI config before the
			// library runs its netns validation. We pipe the buffered bytes
			// back as os.Stdin so the CNI library can still read them.
			stdinData, _ := io.ReadAll(os.Stdin)
			r, w, _ := os.Pipe()
			go func() {
				_, _ = w.Write(stdinData)
				_ = w.Close()
			}()
			oldStdin := os.Stdin
			os.Stdin = r

			// Tap mode never enters a network namespace — all operations are
			// host-side. Set the override so the CNI library skips its same-
			// netns rejection check, which would otherwise reject kraftlet
			// workloads that pass the host netns.
			if isTapMode(stdinData) {
				_ = os.Setenv("CNI_NETNS_OVERRIDE", "true")
			}

			defer func() { os.Stdin = oldStdin }()
			cni.RunPlugin()
			return nil
		},
	}

	cmd.PersistentFlags().String("conf-file", cni.ConfFile, "Path to CNI conflist file")
	cmd.Flags().Bool("build-info", false, "Print build information and exit")
	cmd.Flags().BoolP("version", "V", false, "Print version and exit")

	cmd.AddCommand(newInitCommand(), newRunCommand())
	return cmd
}

// isTapMode returns true when the CNI config requests tap interface type.
// Only a minimal JSON parse is needed — full validation happens later in
// parseConf inside cmdAdd.
func isTapMode(stdinData []byte) bool {
	var cfg struct {
		InterfaceType string `json:"interface_type"`
	}
	_ = json.Unmarshal(stdinData, &cfg)
	return cfg.InterfaceType == "tap"
}

func main() {
	if err := newRootCommand().Execute(); err != nil {
		log.Fatalf("error: %v", err)
	}
}
