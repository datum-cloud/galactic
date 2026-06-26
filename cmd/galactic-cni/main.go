// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"go.datum.net/galactic/internal/cni"
	"go.datum.net/galactic/internal/metadata"
)

const (
	appName = "galactic-cni"

	appDesc = `Galactic CNI Plugin

 Find more information at: https://www.datum.net/docs`
)

// newViper returns a configured viper instance with defaults, env var
// bindings, and automatic fallback for keys not explicitly bound.
func newViper() *viper.Viper {
	v := viper.New()
	v.SetDefault("galactic_cni.node_name", "")
	v.SetDefault("galactic_cni.enable_local_ipam", false)
	v.AutomaticEnv()
	//nolint:errcheck // keys are controlled, BindEnv cannot fail here
	v.BindEnv("galactic_cni.node_name", "GALACTIC_CNI_NODE_NAME", "NODE_NAME")
	//nolint:errcheck // keys are controlled, BindEnv cannot fail here
	v.BindEnv("galactic_cni.enable_local_ipam", "GALACTIC_CNI_ENABLE_LOCAL_IPAM")
	return v
}

// bindFlags registers each viper-configured flag on the command so that
// `viper.BindPFlags` can resolve flag values at runtime.
func bindFlags(cmd *cobra.Command, v *viper.Viper) {
	cmd.Flags().StringP("node-name", "n", v.GetString("galactic_cni.node_name"),
		"Kubernetes node name (required)")
	cmd.Flags().Bool("enable-local-ipam", v.GetBool("galactic_cni.enable_local_ipam"),
		"Enable built-in IPv6 pool IPAM when no explicit ipam block is configured")
	//nolint:errcheck // keys are controlled, BindPFlag cannot fail here
	v.BindPFlag("galactic_cni.node_name", cmd.Flags().Lookup("node-name"))
	//nolint:errcheck // keys are controlled, BindPFlag cannot fail here
	v.BindPFlag("galactic_cni.enable_local_ipam", cmd.Flags().Lookup("enable-local-ipam"))
	//nolint:errcheck // keys are controlled, BindPFlags cannot fail here
	v.BindPFlags(cmd.Flags())
}

// validateConfig checks that the configuration values are valid.
func validateConfig(v *viper.Viper) error {
	if v.GetString("galactic_cni.node_name") == "" {
		return fmt.Errorf("--node-name is required (or set GALACTIC_CNI_NODE_NAME)")
	}
	return nil
}

// newRootCommand builds the root cobra command with all flags and the
// CNI plugin startup logic.
func newRootCommand() *cobra.Command {
	v := newViper()

	cmd := &cobra.Command{
		Use:   appName,
		Short: strings.Split(appDesc, "\n")[0],
		Long:  appDesc,
		RunE: func(cmd *cobra.Command, args []string) error {
			if ok, _ := cmd.Flags().GetBool("build-info"); ok {
				fmt.Println(metadata.BuildInfo(appName))
				return nil
			}
			if ok, _ := cmd.Flags().GetBool("version"); ok {
				fmt.Printf("galactic-cni version %s\n", metadata.Version)
				return nil
			}
			if err := validateConfig(v); err != nil {
				return err
			}
			// Propagate the node name from viper into the env so the
			// existing cni.cmdAdd path continues to read os.Getenv.
			nodeName := v.GetString("galactic_cni.node_name")
			_ = os.Setenv("NODE_NAME", nodeName)
			// Pass the local IPAM flag to the CNI package.
			cni.SetEnableLocalIPAM(v.GetBool("galactic_cni.enable_local_ipam"))
			cni.RunPlugin()
			return nil
		},
	}

	bindFlags(cmd, v)
	cmd.Flags().Bool("build-info", false, "Print build information and exit")
	cmd.Flags().BoolP("version", "V", false, "Print version and exit")
	return cmd
}

func main() {
	if err := newRootCommand().Execute(); err != nil {
		log.Fatalf("error: %v", err)
	}
}
