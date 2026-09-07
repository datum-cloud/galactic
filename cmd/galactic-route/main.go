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

	"go.datum.net/galactic/internal/cniroute"
	"go.datum.net/galactic/internal/metadata"
)

const (
	appName = "galactic-route"

	appDesc = `Galactic Route CNI Plugin

 The termination-route plugin in the galactic CNI chain — chained after
 galactic-veth/galactic-tap and before galactic-bgp per conflist order,
 never run standalone, and optional (only present for attachments with
 terminations to install). Has no Kubernetes dependency at all: it only
 installs kernel routes into the VRF routing table the master plugin
 already created.

 Find more information at: https://www.datum.net/docs`
)

func newRootCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   appName,
		Short: strings.Split(appDesc, "\n")[0],
		Long:  appDesc,
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			cniroute.InitCNIConfig()
			confFile, _ := cmd.Flags().GetString("conf-file")
			if confFile != "" {
				cniroute.ConfFile = confFile
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

			// This plugin never enters a network namespace; it installs routes
			// into the VRF table the master plugin created. For a tap
			// attachment the namespace given is the host's, which equals this
			// process's own and would trigger the library's same-namespace
			// rejection. The override is set unconditionally, being a no-op
			// for veth where the two differ anyway.
			_ = os.Setenv("CNI_NETNS_OVERRIDE", "true")

			cniroute.RunPlugin()
			return nil
		},
	}

	cmd.PersistentFlags().String("conf-file", cniroute.ConfFile, "Path to CNI conflist file")
	cmd.Flags().Bool("build-info", false, "Print build information and exit")
	cmd.Flags().BoolP("version", "V", false, "Print version and exit")
	return cmd
}

func main() {
	if err := newRootCommand().Execute(); err != nil {
		log.Fatalf("error: %v", err)
	}
}
