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
 galactic-cni/galactic-tap-cni (and, when present, galactic-route) per
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

			// Real CNI runtimes always pipe the network config JSON on
			// stdin and close it. If stdin is an interactive terminal
			// instead, no config will ever arrive and skel's blocking
			// stdin read would hang forever — print version info instead.
			if term.IsTerminal(int(os.Stdin.Fd())) {
				fmt.Printf("%s version %s\n", appName, metadata.Version)
				fmt.Printf("CNI protocol versions supported: %s\n", strings.Join(version.All.SupportedVersions(), ", "))
				return nil
			}

			// Unlike galactic-cni/galactic-tap-cni, this plugin never enters
			// any network namespace at all (it only makes k8s API calls),
			// so it needs neither the stdin peek-and-repipe dance nor
			// CNI_NETNS_OVERRIDE those two use to detect and handle
			// tap-mode's host-netns invocation.
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
