// Copyright 2025 Datum Cloud, Inc.
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

	"go.datum.net/galactic/internal/cni"
	"go.datum.net/galactic/internal/metadata"
)

const (
	appName = "galactic-veth"

	appDesc = `Galactic CNI Plugin

 Find more information at: https://www.datum.net/docs`
)

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
				fmt.Printf("galactic-veth version %s\n", metadata.Version)
				return nil
			}
			// Handle CNI_COMMAND=VERSION before config validation
			if os.Getenv("CNI_COMMAND") == "VERSION" {
				return version.All.Encode(os.Stdout)
			}

			// Real CNI runtimes (containerd, CRI-O) always pipe the network
			// config JSON on stdin and close it. If stdin is an interactive
			// terminal instead, no config will ever arrive, and both skel's
			// blocking stdin read and the io.ReadAll below would hang
			// forever. Detect that case up front and print version info
			// rather than hanging.
			if term.IsTerminal(int(os.Stdin.Fd())) {
				fmt.Printf("galactic-veth version %s\n", metadata.Version)
				fmt.Printf("CNI protocol versions supported: %s\n", strings.Join(version.All.SupportedVersions(), ", "))
				return nil
			}

			// galactic-veth is veth-only: it always moves an interface into
			// the container's own netns, so it always needs the CNI
			// library's normal same-netns rejection check — unlike
			// galactic-tap (which unconditionally sets
			// CNI_NETNS_OVERRIDE, since tap workloads never enter a netns
			// at all), there is no stdin-peeking tap-mode detection here
			// anymore. Interface kind is which binary you invoke now, not a
			// config field this process branches on.
			cni.RunPlugin()
			return nil
		},
	}

	cmd.PersistentFlags().String("conf-file", cni.ConfFile, "Path to CNI conflist file")
	cmd.Flags().Bool("build-info", false, "Print build information and exit")
	cmd.Flags().BoolP("version", "V", false, "Print version and exit")

	return cmd
}

func main() {
	if err := newRootCommand().Execute(); err != nil {
		log.Fatalf("error: %v", err)
	}
}
