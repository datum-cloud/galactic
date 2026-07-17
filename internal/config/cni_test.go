// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import "testing"

const (
	testConflistNode = "conflist-node"
	testConflistKube = "/conflist/kubeconfig"
	testConflistNS   = "conflist-ns"
	testConflistLog  = "/conflist/log.txt"
	testEnvLog       = "/env/log.txt"
	testEnvKube      = "/env/kubeconfig"
	testEnvNS        = "env-ns"
	testEnvNode      = "env-node"
)

func TestCNIConfigDefaults(t *testing.T) {
	cfg := NewCNIConfig()
	cfg.Resolve(&ConflistValues{})

	if cfg.Kubeconfig != DefaultKubeconfig {
		t.Errorf("Kubeconfig = %q, want %q", cfg.Kubeconfig, DefaultKubeconfig)
	}
	if cfg.Namespace != DefaultNamespace {
		t.Errorf("Namespace = %q, want %q", cfg.Namespace, DefaultNamespace)
	}
	if cfg.LogFile != DefaultLogFile {
		t.Errorf("LogFile = %q, want %q", cfg.LogFile, DefaultLogFile)
	}
	if cfg.LogLevel != DefaultLogLevel {
		t.Errorf("LogLevel = %q, want %q", cfg.LogLevel, DefaultLogLevel)
	}
}

func TestCNIConfigConflistValues(t *testing.T) {
	cfg := NewCNIConfig()
	cfg.Resolve(&ConflistValues{
		NodeName:   testConflistNode,
		Kubeconfig: testConflistKube,
		Namespace:  testConflistNS,
		LogFile:    testConflistLog,
		LogLevel:   LogLevelDebug,
	})

	if cfg.NodeName != testConflistNode {
		t.Errorf("NodeName = %q, want %q", cfg.NodeName, testConflistNode)
	}
	if cfg.Kubeconfig != testConflistKube {
		t.Errorf("Kubeconfig = %q, want %q", cfg.Kubeconfig, testConflistKube)
	}
	if cfg.Namespace != testConflistNS {
		t.Errorf("Namespace = %q, want %q", cfg.Namespace, testConflistNS)
	}
	if cfg.LogFile != testConflistLog {
		t.Errorf("LogFile = %q, want %q", cfg.LogFile, testConflistLog)
	}
	if cfg.LogLevel != LogLevelDebug {
		t.Errorf("LogLevel = %q, want %q", cfg.LogLevel, LogLevelDebug)
	}
}

func TestCNIConfigEnvOverride(t *testing.T) {
	t.Setenv(EnvLogLevel, LogLevelDebug)
	t.Setenv(EnvLogFile, testEnvLog)
	t.Setenv(EnvCNIKubeconfig, testEnvKube)
	t.Setenv(EnvNamespace, testEnvNS)
	t.Setenv(EnvCNINodeName, testEnvNode)

	cfg := NewCNIConfig()
	cfg.Resolve(&ConflistValues{
		NodeName:   testConflistNode,
		Kubeconfig: testConflistKube,
		Namespace:  testConflistNS,
		LogFile:    testConflistLog,
		LogLevel:   DefaultLogLevel,
	})

	// Env var takes precedence over conflist value
	if cfg.LogLevel != LogLevelDebug {
		t.Errorf("LogLevel = %q, want %q (env override)", cfg.LogLevel, LogLevelDebug)
	}
	if cfg.LogFile != testEnvLog {
		t.Errorf("LogFile = %q, want %q (env override)", cfg.LogFile, testEnvLog)
	}
	if cfg.Kubeconfig != testEnvKube {
		t.Errorf("Kubeconfig = %q, want %q (env override)", cfg.Kubeconfig, testEnvKube)
	}
	if cfg.Namespace != testEnvNS {
		t.Errorf("Namespace = %q, want %q (env override)", cfg.Namespace, testEnvNS)
	}
	if cfg.NodeName != testEnvNode {
		t.Errorf("NodeName = %q, want %q (env override)", cfg.NodeName, testEnvNode)
	}
}

func TestCNIConfigNodeNameLegacyFallback(t *testing.T) {
	t.Setenv(EnvNodeNameLegacy, "legacy-node")

	cfg := NewCNIConfig()
	cfg.Resolve(&ConflistValues{})

	if cfg.NodeName != "legacy-node" {
		t.Errorf("NodeName = %q, want %q", cfg.NodeName, "legacy-node")
	}
}

func TestCNIGetEnableLocalIPAM(t *testing.T) {
	t.Setenv(EnvCNIEnableLocalIPAM, "true")
	if got := CNIGetEnableLocalIPAM(); !got {
		t.Error("CNIGetEnableLocalIPAM() = false, want true")
	}
}

func TestCNIGetEnableLocalIPAMFalse(t *testing.T) {
	if got := CNIGetEnableLocalIPAM(); got {
		t.Error("CNIGetEnableLocalIPAM() = true, want false (env unset)")
	}
}
