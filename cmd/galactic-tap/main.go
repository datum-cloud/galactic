// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/containernetworking/cni/pkg/version"
	"github.com/spf13/cobra"
	"golang.org/x/term"

	"go.datum.net/galactic/internal/cnitap"
	"go.datum.net/galactic/internal/metadata"
)

const (
	appName = "galactic-tap"

	appDesc = `Galactic tap CNI Plugin

 The tap master plugin in the galactic CNI chain, for VM-based workloads
 (Kata, Firecracker, kraftlet/Unikraft) attaching directly to a galactic VPC
 network.

 Find more information at: https://www.datum.net/docs`
)

func newRootCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   appName,
		Short: strings.Split(appDesc, "\n")[0],
		Long:  appDesc,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			cnitap.InitCNIConfig()
			confFile, _ := cmd.Flags().GetString("conf-file")
			if confFile != "" {
				cnitap.ConfFile = confFile
			}
			return nil
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
			if os.Getenv("CNI_COMMAND") == "VERSION" {
				return version.All.Encode(os.Stdout)
			}

			// Real CNI runtimes always pipe the network config on stdin and
			// close it. When stdin is an interactive terminal instead, no
			// config ever arrives and the library's blocking read would hang
			// forever, so print version info instead.
			if term.IsTerminal(int(os.Stdin.Fd())) {
				fmt.Printf("%s version %s\n", appName, metadata.Version)
				fmt.Printf("CNI protocol versions supported: %s\n", strings.Join(version.All.SupportedVersions(), ", "))
				return nil
			}

			// Tap mode never enters a network namespace; every operation is
			// host-side. The override makes the library skip its same-namespace
			// rejection check, which would otherwise reject a workload that
			// passes the host namespace. Unconditional here, unlike the veth
			// binary: every invocation of this one is tap mode, so there is no
			// config to peek at first.
			_ = os.Setenv("CNI_NETNS_OVERRIDE", "true")

			cnitap.RunPlugin()
			return nil
		},
	}

	cmd.PersistentFlags().String("conf-file", cnitap.ConfFile, "Path to CNI conflist file")
	cmd.Flags().Bool("build-info", false, "Print build information and exit")
	cmd.Flags().BoolP("version", "V", false, "Print version and exit")

	return cmd
}

func main() {
	if err := newRootCommand().Execute(); err != nil {
		log.Fatalf("error: %v", err)
	}
}
