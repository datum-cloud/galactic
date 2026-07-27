// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/containernetworking/cni/pkg/version"
	"github.com/spf13/cobra"
	"golang.org/x/term"

	"go.datum.net/galactic/internal/metadata"
	"go.datum.net/galactic/internal/vmtap"
)

const (
	appName = "vmtap-cni"

	appDesc = `vmtap CNI Plugin

 Chained CNI plugin giving a Unikraft/kraftlet microVM access to the pod's
 real Cilium-assigned identity via a tap device and tc-redirect. Must be
 chained after Cilium's own CNI plugin in the pod's primary conflist.

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

			// Real CNI runtimes always pipe the network config JSON on
			// stdin and close it. If stdin is an interactive terminal
			// instead, no config will ever arrive and skel's blocking
			// stdin read would hang forever — print version info instead.
			if term.IsTerminal(int(os.Stdin.Fd())) {
				fmt.Printf("%s version %s\n", appName, metadata.Version)
				fmt.Printf("CNI protocol versions supported: %s\n", strings.Join(version.All.SupportedVersions(), ", "))
				return nil
			}

			vmtap.RunPlugin()
			return nil
		},
	}

	cmd.Flags().Bool("build-info", false, "Print build information and exit")
	cmd.Flags().BoolP("version", "V", false, "Print version and exit")
	cmd.AddCommand(newPatchConflistCommand())
	return cmd
}

// newPatchConflistCommand runs the conflist-chaining installer step: see
// vmtap.RunPatchLoop for why this loops instead of running once. It is
// meant to run as a long-lived container (not an init container) in the
// vmtap-cni DaemonSet — see config/vmtap/daemonset.yaml.
func newPatchConflistCommand() *cobra.Command {
	var (
		cniNetDir    string
		ciliumGlob   string
		pollInterval time.Duration
	)

	cmd := &cobra.Command{
		Use:   "patch-conflist",
		Short: "Chain vmtap-cni into Cilium's conflist and keep re-patching it",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			vmtap.RunPatchLoop(ctx, cniNetDir, ciliumGlob, pollInterval)
			return nil
		},
	}
	cmd.Flags().StringVar(&cniNetDir, "cni-net-dir", "/host/etc/cni/net.d", "Host CNI conflist directory to patch")
	cmd.Flags().StringVar(&ciliumGlob, "cilium-glob", "*cilium*.conflist",
		"Glob (within --cni-net-dir) matching Cilium's own conflist file")
	cmd.Flags().DurationVar(&pollInterval, "poll-interval", 10*time.Second,
		"How often to re-check the conflist for the vmtap-cni entry")
	return cmd
}

func main() {
	if err := newRootCommand().Execute(); err != nil {
		log.Fatalf("error: %v", err)
	}
}
