// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package hostconf

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/containernetworking/cni/pkg/types"
)

func TestLoadMissingFile(t *testing.T) {
	tmpDir := t.TempDir()
	_, err := Load(filepath.Join(tmpDir, "does-not-exist.conflist"), PluginType)
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("expected error wrapping os.ErrNotExist, got %v", err)
	}
}

func TestLoadNoMatchingPluginType(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "10-galactic.conflist")
	content := `{"cniVersion":"1.0.0","name":"test","plugins":[{"type":"some-other-plugin"}]}`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("os.WriteFile: %v", err)
	}

	if _, err := Load(path, PluginType); err == nil {
		t.Fatal("expected error for missing plugin type, got nil")
	}
}

func TestLoadMatchingPluginType(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "10-galactic.conflist")
	content := `{
		"cniVersion": "1.0.0",
		"name": "galactic",
		"plugins": [
			{
				"type": "galactic-cni",
				"node_name": "test-worker",
				"kubeconfig": "/etc/custom-kubeconfig",
				"namespace": "custom-namespace",
				"log_file": "/var/log/custom.log",
				"log_level": "debug"
			}
		]
	}`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("os.WriteFile: %v", err)
	}

	conf, err := Load(path, PluginType)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if conf.NodeName != "test-worker" {
		t.Errorf("NodeName = %q, want %q", conf.NodeName, "test-worker")
	}
	if conf.Kubeconfig != "/etc/custom-kubeconfig" {
		t.Errorf("Kubeconfig = %q, want %q", conf.Kubeconfig, "/etc/custom-kubeconfig")
	}
	if conf.Namespace != "custom-namespace" {
		t.Errorf("Namespace = %q, want %q", conf.Namespace, "custom-namespace")
	}
	if conf.LogFile != "/var/log/custom.log" {
		t.Errorf("LogFile = %q, want %q", conf.LogFile, "/var/log/custom.log")
	}
	if conf.LogLevel != "debug" {
		t.Errorf("LogLevel = %q, want %q", conf.LogLevel, "debug")
	}
}

func TestRejectMovedIPAMKeys(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr string
	}{
		{
			name:  "no addressing keys at all",
			input: `{"cniVersion":"1.0.0","type":"galactic-veth","vpc":"abc"}`,
		},
		{
			name:  "keys inside the ipam block",
			input: `{"type":"galactic-veth","ipam":{"type":"galactic-ipam","ipv6_subnet":"fd00::/48","static_ip":"fd00::1"}}`,
		},
		{
			name:    "top-level ipv6_subnet",
			input:   `{"type":"galactic-veth","ipv6_subnet":"fd00::/48"}`,
			wantErr: "addressing field 'ipv6_subnet' belongs inside the 'ipam' block",
		},
		{
			name:    "top-level ipv4_subnet",
			input:   `{"type":"galactic-veth","ipv4_subnet":"172.20.1.0/24"}`,
			wantErr: "addressing field 'ipv4_subnet' belongs inside the 'ipam' block",
		},
		{
			name:    "top-level address_families",
			input:   `{"type":"galactic-veth","address_families":["ipv6"]}`,
			wantErr: "addressing field 'address_families' belongs inside the 'ipam' block",
		},
		{
			name:    "top-level static_ip",
			input:   `{"type":"galactic-veth","static_ip":"fd00::1234"}`,
			wantErr: "addressing field 'static_ip' belongs inside the 'ipam' block",
		},
		{
			name:    "wrong-typed value is still reported as present",
			input:   `{"type":"galactic-veth","ipv6_subnet":42}`,
			wantErr: "addressing field 'ipv6_subnet' belongs inside the 'ipam' block",
		},
		{
			name:  "explicit null carries no addressing intent",
			input: `{"type":"galactic-veth","ipv6_subnet":null,"static_ip":null}`,
		},
		{
			name:    "several keys are all named",
			input:   `{"type":"galactic-veth","ipv4_subnet":"172.20.1.0/24","static_ip":"fd00::1"}`,
			wantErr: "addressing fields 'ipv4_subnet', 'static_ip' belong inside the 'ipam' block",
		},
		{
			name:  "malformed JSON is left to the caller to report",
			input: "not json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := RejectMovedIPAMKeys([]byte(tt.input))
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			var cniErr *types.Error
			if !errors.As(err, &cniErr) {
				t.Fatalf("expected *types.Error, got %T: %v", err, err)
			}
			if cniErr.Code != 7 {
				t.Errorf("Code = %d, want 7", cniErr.Code)
			}
			if !strings.Contains(cniErr.Msg, tt.wantErr) {
				t.Errorf("Msg = %q, want it to contain %q", cniErr.Msg, tt.wantErr)
			}
		})
	}
}

func TestLoadAcceptsAnyOfMultipleTypes(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "10-galactic.conflist")
	content := `{"cniVersion":"1.0.0","name":"test","plugins":[{"type":"galactic-tap","node_name":"tap-node"}]}`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("os.WriteFile: %v", err)
	}

	conf, err := Load(path, "galactic-veth", "galactic-tap")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if conf.NodeName != "tap-node" {
		t.Errorf("NodeName = %q, want %q", conf.NodeName, "tap-node")
	}
}
