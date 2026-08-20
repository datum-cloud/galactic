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

func TestCNIConfigNAT66ShardSIDs(t *testing.T) {
	const (
		conflistSIDs = "2001:db8:ff01:1:e001::"
		envSIDs      = "2001:db8:ff01:1:e001::,2001:db8:ff03:1:e001::"
	)

	// Default: empty, not an error -- "no shard configured yet" is normal.
	cfg := NewCNIConfig()
	cfg.Resolve(&ConflistValues{})
	if cfg.NAT66ShardSIDs != "" {
		t.Errorf("NAT66ShardSIDs = %q, want empty by default", cfg.NAT66ShardSIDs)
	}

	// Conflist value flows through.
	cfg = NewCNIConfig()
	cfg.Resolve(&ConflistValues{NAT66ShardSIDs: conflistSIDs})
	if cfg.NAT66ShardSIDs != conflistSIDs {
		t.Errorf("NAT66ShardSIDs = %q, want %q (conflist)", cfg.NAT66ShardSIDs, conflistSIDs)
	}

	// Env var overrides the conflist value.
	t.Setenv(EnvCNINAT66ShardSIDs, envSIDs)
	cfg = NewCNIConfig()
	cfg.Resolve(&ConflistValues{NAT66ShardSIDs: conflistSIDs})
	if cfg.NAT66ShardSIDs != envSIDs {
		t.Errorf("NAT66ShardSIDs = %q, want %q (env override)", cfg.NAT66ShardSIDs, envSIDs)
	}
}

func TestCNIConfigEBPFInterfaces(t *testing.T) {
	const (
		conflistIfaces = "eth1"
		envIfaces      = "eth1,eth2"
	)

	// Default: empty, not an error -- "fall back to
	// attach.ResolveInterfaces' own auto-detection" is the pre-existing
	// behavior, same stance as NAT66ShardSIDs' own default above.
	cfg := NewCNIConfig()
	cfg.Resolve(&ConflistValues{})
	if cfg.EBPFInterfaces != "" {
		t.Errorf("EBPFInterfaces = %q, want empty by default", cfg.EBPFInterfaces)
	}

	// Conflist value flows through -- internal/installer.Bootstrap's own
	// resolveEBPFInterfaces writes this, since a CNI plugin's own exec
	// environment never carries GALACTIC_CNI_EBPF_INTERFACES (see
	// hostconf.HostConf.EBPFInterfaces' own doc comment).
	cfg = NewCNIConfig()
	cfg.Resolve(&ConflistValues{EBPFInterfaces: conflistIfaces})
	if cfg.EBPFInterfaces != conflistIfaces {
		t.Errorf("EBPFInterfaces = %q, want %q (conflist)", cfg.EBPFInterfaces, conflistIfaces)
	}

	// Env var overrides the conflist value -- an operator setting
	// GALACTIC_CNI_EBPF_INTERFACES directly on this exec environment
	// (unlike a DaemonSet container's own env, which a CNI plugin never
	// inherits) must still win.
	t.Setenv(EnvCNIEBPFInterfaces, envIfaces)
	cfg = NewCNIConfig()
	cfg.Resolve(&ConflistValues{EBPFInterfaces: conflistIfaces})
	if cfg.EBPFInterfaces != envIfaces {
		t.Errorf("EBPFInterfaces = %q, want %q (env override)", cfg.EBPFInterfaces, envIfaces)
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
