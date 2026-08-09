// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package hostconf

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
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

func TestLoadAcceptsAnyOfMultipleTypes(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "10-galactic.conflist")
	content := `{"cniVersion":"1.0.0","name":"test","plugins":[{"type":"galactic-tap-cni","node_name":"tap-node"}]}`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("os.WriteFile: %v", err)
	}

	conf, err := Load(path, "galactic-cni", "galactic-tap-cni")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if conf.NodeName != "tap-node" {
		t.Errorf("NodeName = %q, want %q", conf.NodeName, "tap-node")
	}
}
