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

	"go.datum.net/galactic/internal/cnibgp"
	"go.datum.net/galactic/internal/metadata"
)

const (
	appName = "galactic-bgp"

	appDesc = `Galactic BGP CNI Plugin

 The BGP/SRv6/eBPF publish plugin in the galactic CNI chain — chained after
 galactic-veth/galactic-tap (and, when present, galactic-route) per
 conflist order, never run standalone. Has zero kernel-interface
 dependency: every address it advertises comes from prevResult, not from a
 runtime call into an interface it doesn't own.

 Find more information at: https://www.datum.net/docs`
)

func newRootCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   appName,
		Short: strings.Split(appDesc, "\n")[0],
		Long:  appDesc,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			cnibgp.InitCNIConfig()
			confFile, _ := cmd.Flags().GetString("conf-file")
			if confFile != "" {
				cnibgp.ConfFile = confFile
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

			// This plugin never enters a network namespace; it only makes API
			// calls to publish advertisements. For a tap attachment the
			// namespace given is the host's, which equals this process's own,
			// so the library's same-namespace rejection would fire without the
			// override.
			_ = os.Setenv("CNI_NETNS_OVERRIDE", "true")

			cnibgp.RunPlugin()
			return nil
		},
	}

	cmd.PersistentFlags().String("conf-file", cnibgp.ConfFile, "Path to CNI conflist file")
	cmd.Flags().Bool("build-info", false, "Print build information and exit")
	cmd.Flags().BoolP("version", "V", false, "Print version and exit")
	return cmd
}

func main() {
	if err := newRootCommand().Execute(); err != nil {
		log.Fatalf("error: %v", err)
	}
}
