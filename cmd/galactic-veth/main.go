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

			// Real CNI runtimes always pipe the network config on stdin and
			// close it. When stdin is an interactive terminal instead, no
			// config ever arrives and both the library's blocking read and the
			// read below would hang forever. Detect that up front and print
			// version info instead.
			if term.IsTerminal(int(os.Stdin.Fd())) {
				fmt.Printf("galactic-veth version %s\n", metadata.Version)
				fmt.Printf("CNI protocol versions supported: %s\n", strings.Join(version.All.SupportedVersions(), ", "))
				return nil
			}

			// This binary is veth-only: it always moves an interface into the
			// container's namespace, so it always needs the library's
			// same-namespace rejection check. The tap binary unconditionally
			// overrides that, tap workloads never entering a namespace.
			// Interface kind is which binary you invoke, not a config field
			// this process branches on.
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
