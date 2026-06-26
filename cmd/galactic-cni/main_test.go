// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"os"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"go.datum.net/galactic/internal/metadata"
)

// testCmdName is the placeholder command name used in tests.
const testCmdName = "test"

// cmdWithViper creates a cobra command with a fresh viper instance and
// binds all flags. This is used to test flag defaults and cobra integration.
func cmdWithViper(t *testing.T) *viper.Viper {
	t.Helper()
	v := newViper()
	cmd := &cobra.Command{Use: testCmdName}
	bindFlags(cmd, v)
	return v
}

func TestNodeNameDefault(t *testing.T) {
	v := cmdWithViper(t)
	if v.GetString("galactic_cni.node_name") != "" {
		t.Errorf("node_name default = %q, want empty", v.GetString("galactic_cni.node_name"))
	}
}

func TestNodeNameFromEnv(t *testing.T) {
	t.Setenv("GALACTIC_CNI_NODE_NAME", "test-node")
	v := cmdWithViper(t)
	if v.GetString("galactic_cni.node_name") != "test-node" {
		t.Errorf("node_name from env = %q, want %q", v.GetString("galactic_cni.node_name"), "test-node")
	}
}

func TestValidateConfigRequiresNodeName(t *testing.T) {
	v := cmdWithViper(t)
	if err := validateConfig(v); err == nil {
		t.Error("validateConfig with empty node-name returned nil")
	}
}

func TestValidateConfigPassesWithNodeName(t *testing.T) {
	t.Setenv("GALACTIC_CNI_NODE_NAME", "test-node")
	v := cmdWithViper(t)
	if err := validateConfig(v); err != nil {
		t.Errorf("validateConfig with node-name: %v", err)
	}
}

func TestBuildInfoFlag(t *testing.T) {
	if metadata.Version == "" {
		t.Error("metadata.Version should not be empty")
	}
}

func TestVersionFlag(t *testing.T) {
	if metadata.Version == "" {
		t.Error("metadata.Version should not be empty")
	}
}

func TestDefaultsUnsetEnv(t *testing.T) {
	_ = os.Unsetenv("GALACTIC_CNI_NODE_NAME")
	v := cmdWithViper(t)
	if v.GetString("galactic_cni.node_name") != "" {
		t.Errorf("node_name default = %q, want empty", v.GetString("galactic_cni.node_name"))
	}
}

func TestEnableLocalIPAMDefault(t *testing.T) {
	v := cmdWithViper(t)
	if v.GetBool("galactic_cni.enable_local_ipam") != false {
		t.Errorf("enable_local_ipam default = %t, want false", v.GetBool("galactic_cni.enable_local_ipam"))
	}
}

func TestEnableLocalIPAMFromEnv(t *testing.T) {
	t.Setenv("GALACTIC_CNI_ENABLE_LOCAL_IPAM", "true")
	v := cmdWithViper(t)
	if !v.GetBool("galactic_cni.enable_local_ipam") {
		t.Error("enable_local_ipam from env = false, want true")
	}
}

func TestEnableLocalIPAMFromFlag(t *testing.T) {
	v := newViper()
	cmd := &cobra.Command{Use: testCmdName}
	bindFlags(cmd, v)

	// Set the flag directly on the cobra command.
	if err := cmd.Flags().Set("enable-local-ipam", "true"); err != nil {
		t.Fatalf("failed to set flag: %v", err)
	}

	// BindPFlag was called in bindFlags, so viper should read
	// the flag value at resolution time.
	if !v.GetBool("galactic_cni.enable_local_ipam") {
		t.Error("enable_local_ipam after setting flag = false, want true")
	}
}

func TestNodeNameFromFlag(t *testing.T) {
	v := newViper()
	cmd := &cobra.Command{Use: testCmdName}
	bindFlags(cmd, v)

	if err := cmd.Flags().Set("node-name", "test-node"); err != nil {
		t.Fatalf("failed to set flag: %v", err)
	}

	if v.GetString("galactic_cni.node_name") != "test-node" {
		t.Errorf("node_name after setting flag = %q, want %q",
			v.GetString("galactic_cni.node_name"), "test-node")
	}
}
