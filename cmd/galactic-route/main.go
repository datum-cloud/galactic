// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"fmt"
	"io"
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
 galactic-cni/galactic-tap-cni and before galactic-bgp per conflist order,
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

			// Real CNI runtimes always pipe the network config JSON on
			// stdin and close it. If stdin is an interactive terminal
			// instead, no config will ever arrive and skel's blocking
			// stdin read would hang forever — print version info instead.
			if term.IsTerminal(int(os.Stdin.Fd())) {
				fmt.Printf("%s version %s\n", appName, metadata.Version)
				fmt.Printf("CNI protocol versions supported: %s\n", strings.Join(version.All.SupportedVersions(), ", "))
				return nil
			}

			// Unlike galactic-cni/galactic-tap-cni, this plugin never talks
			// to the API server. It does, however, run natively in whatever
			// netns CNI_NETNS points at rather than entering it — for a
			// veth-mode attachment CNI_NETNS is the container's netns, which
			// differs from this process's own ambient (host) netns, so the
			// CNI library's same-netns rejection check never fires. For a
			// tap-mode attachment, though, CNI_NETNS is deliberately set to
			// the host's own root netns (there's no per-VM netns to enter),
			// which does equal this process's ambient netns — so the same
			// peek-and-repipe dance and CNI_NETNS_OVERRIDE galactic-cni uses
			// for tap mode are needed here too, or the library rejects every
			// tap-mode ADD/DEL after the route is already installed.
			stdinData, _ := io.ReadAll(os.Stdin)
			r, w, _ := os.Pipe()
			go func() {
				_, _ = w.Write(stdinData)
				_ = w.Close()
			}()
			oldStdin := os.Stdin
			os.Stdin = r
			defer func() { os.Stdin = oldStdin }()

			if isTapMode(stdinData) {
				_ = os.Setenv("CNI_NETNS_OVERRIDE", "true")
			}

			cniroute.RunPlugin()
			return nil
		},
	}

	cmd.PersistentFlags().String("conf-file", cniroute.ConfFile, "Path to CNI conflist file")
	cmd.Flags().Bool("build-info", false, "Print build information and exit")
	cmd.Flags().BoolP("version", "V", false, "Print version and exit")
	return cmd
}

// isTapMode returns true when the CNI config requests tap interface type.
// Only a minimal JSON parse is needed — full validation happens later in
// parseConf inside cmdAdd/cmdDel.
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
