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

	"go.datum.net/galactic/internal/cniipam"
	"go.datum.net/galactic/internal/metadata"
)

const (
	appName = "galactic-ipam"

	appDesc = `Galactic IPAM CNI Plugin

 The delegated CNI IPAM plugin in the galactic CNI chain — invoked by
 galactic-cni/galactic-tap-cni's own "ipam" block via the CNI IPAM
 delegation protocol (github.com/containernetworking/cni/pkg/ipam), never
 run directly from a conflist. Has no Kubernetes dependency at all:
 allocation state persists in on-disk marker files under this node's own
 filesystem.

 Find more information at: https://www.datum.net/docs`
)

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
				fmt.Printf("%s version %s\n", appName, metadata.Version)
				return nil
			}
			if os.Getenv("CNI_COMMAND") == "VERSION" {
				return version.All.Encode(os.Stdout)
			}

			// Real CNI runtimes (via IPAM delegation's ExecAdd/ExecDel/
			// ExecCheck) always pipe the netconf JSON on stdin and close
			// it. If stdin is an interactive terminal instead, no config
			// will ever arrive and skel's blocking stdin read would hang
			// forever — print version info instead.
			if term.IsTerminal(int(os.Stdin.Fd())) {
				fmt.Printf("%s version %s\n", appName, metadata.Version)
				fmt.Printf("CNI protocol versions supported: %s\n", strings.Join(version.All.SupportedVersions(), ", "))
				return nil
			}

			// This plugin never enters a network namespace — it only
			// allocates addresses from on-disk marker files. For tap-mode
			// attachments, CNI_NETNS points at the host netns which equals
			// this process's ambient netns, so the CNI library's same-netns
			// rejection check would fire without the override.
			_ = os.Setenv("CNI_NETNS_OVERRIDE", "true")

			cniipam.RunPlugin()
			return nil
		},
	}

	cmd.Flags().Bool("build-info", false, "Print build information and exit")
	cmd.Flags().BoolP("version", "V", false, "Print version and exit")
	return cmd
}

func main() {
	if err := newRootCommand().Execute(); err != nil {
		log.Fatalf("error: %v", err)
	}
}
