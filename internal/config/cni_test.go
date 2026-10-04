// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"testing"

	"go.datum.net/galactic/internal/plumbing/dan"
)

const (
	testConflistNode = "conflist-node"
	testConflistKube = "/conflist/kubeconfig"
	testConflistNS   = "conflist-ns"
	testConflistLog  = "/conflist/log.txt"
	testEnvLog       = "/env/log.txt"
	testEnvKube      = "/env/kubeconfig"
	testEnvNS        = "env-ns"
	testEnvNode      = "env-node"
	testConflistDAN  = "/run/other/dans"
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

func TestCNIConfigEgressShardSIDs(t *testing.T) {
	const (
		conflistSIDs = "2001:db8:ff01:1:e001::"
		envSIDs      = "2001:db8:ff01:1:e001::,2001:db8:ff03:1:e001::"
	)

	// Default: empty, not an error -- "no shard configured yet" is normal.
	cfg := NewCNIConfig()
	cfg.Resolve(&ConflistValues{})
	if cfg.EgressShardSIDs != "" {
		t.Errorf("EgressShardSIDs = %q, want empty by default", cfg.EgressShardSIDs)
	}

	// Conflist value flows through.
	cfg = NewCNIConfig()
	cfg.Resolve(&ConflistValues{EgressShardSIDs: conflistSIDs})
	if cfg.EgressShardSIDs != conflistSIDs {
		t.Errorf("EgressShardSIDs = %q, want %q (conflist)", cfg.EgressShardSIDs, conflistSIDs)
	}

	// Env var overrides the conflist value.
	t.Setenv(EnvCNIEgressShardSIDs, envSIDs)
	cfg = NewCNIConfig()
	cfg.Resolve(&ConflistValues{EgressShardSIDs: conflistSIDs})
	if cfg.EgressShardSIDs != envSIDs {
		t.Errorf("EgressShardSIDs = %q, want %q (env override)", cfg.EgressShardSIDs, envSIDs)
	}
}

func TestCNIConfigEBPFInterfaces(t *testing.T) {
	const (
		conflistIfaces = "eth1"
		envIfaces      = "eth1,eth2"
	)

	// Default: empty, not an error -- "fall back to
	// attach.ResolveInterfaces' own auto-detection" is the pre-existing
	// behavior, same stance as EgressShardSIDs' own default above.
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

func TestCNIConfigDANDir(t *testing.T) {
	// Default: the runtime-rs directory. Whether anything is written there is
	// decided per attachment, not here.
	cfg := NewCNIConfig()
	cfg.Resolve(&ConflistValues{})
	if cfg.DANDir != dan.DefaultDir {
		t.Errorf("DANDir = %q, want %q", cfg.DANDir, dan.DefaultDir)
	}

	// Conflist value flows through.
	cfg = NewCNIConfig()
	cfg.Resolve(&ConflistValues{DANDir: testConflistDAN})
	if cfg.DANDir != testConflistDAN {
		t.Errorf("DANDir = %q, want the conflist value", cfg.DANDir)
	}

	// Env var overrides the conflist value.
	t.Setenv(EnvCNIDANDir, "/run/env/dans")
	cfg = NewCNIConfig()
	cfg.Resolve(&ConflistValues{DANDir: testConflistDAN})
	if cfg.DANDir != "/run/env/dans" {
		t.Errorf("DANDir = %q, want the env value", cfg.DANDir)
	}
}

func TestParseEgressShardSIDs_Empty(t *testing.T) {
	sids, err := ParseEgressShardSIDs("")
	if err != nil {
		t.Fatalf("ParseEgressShardSIDs(\"\") error = %v, want nil", err)
	}
	if len(sids) != 0 {
		t.Errorf("ParseEgressShardSIDs(\"\") = %v, want empty", sids)
	}
}

func TestParseEgressShardSIDs_TrimsWhitespaceAndSkipsBlankEntries(t *testing.T) {
	sids, err := ParseEgressShardSIDs(" 2001:db8:ff01:1:e001:: , 2001:db8:ff03:1:e001::, ,")
	if err != nil {
		t.Fatalf("ParseEgressShardSIDs() error = %v, want nil", err)
	}
	want := []string{"2001:db8:ff01:1:e001::", "2001:db8:ff03:1:e001::"}
	if len(sids) != len(want) {
		t.Fatalf("ParseEgressShardSIDs() = %v, want %v", sids, want)
	}
	for i, w := range want {
		if sids[i].String() != w {
			t.Errorf("ParseEgressShardSIDs()[%d] = %v, want %s", i, sids[i], w)
		}
	}
}

func TestParseEgressShardSIDs_InvalidEntryFailsLoudly(t *testing.T) {
	if _, err := ParseEgressShardSIDs("2001:db8:ff01:1:e001::,not-an-ip"); err == nil {
		t.Error("ParseEgressShardSIDs() error = nil, want an error for the invalid entry")
	}
}

const (
	testNSP = "2001:db8:64::/96"
	testWKP = "64:ff9b::/96"
)

func TestParseNAT64Prefixes(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    []string
		wantErr bool
	}{
		{name: "empty", raw: "", want: nil},
		{name: "blank entries only", raw: " , ,", want: nil},
		{name: "single", raw: testNSP, want: []string{testNSP}},
		{name: "multiple", raw: testNSP + "," + testWKP, want: []string{testNSP, testWKP}},
		{
			name: "whitespace and trailing comma",
			raw:  " " + testNSP + " ,\t" + testWKP + " , ",
			want: []string{testNSP, testWKP},
		},
		{name: "host bits masked", raw: "64:ff9b::1/96", want: []string{testWKP}},
		{name: "unparseable", raw: "2001:db8:64::/96,not-a-prefix", wantErr: true},
		{name: "bare address", raw: "64:ff9b::", wantErr: true},
		{name: "not /96", raw: "64:ff9b::/64", wantErr: true},
		{name: "IPv4", raw: "192.0.2.0/24", wantErr: true},
		{name: "IPv4-mapped", raw: "::ffff:0.0.0.0/96", wantErr: true},
		{name: "duplicate", raw: "64:ff9b::/96, 64:ff9b::/96", wantErr: true},
		{name: "duplicate after masking", raw: "64:ff9b::/96,64:ff9b::1/96", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseNAT64Prefixes(tt.raw)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParseNAT64Prefixes(%q) = %v, want an error", tt.raw, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseNAT64Prefixes(%q) error = %v, want nil", tt.raw, err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("ParseNAT64Prefixes(%q) = %v, want %v", tt.raw, got, tt.want)
			}
			for i, w := range tt.want {
				if got[i].String() != w {
					t.Errorf("ParseNAT64Prefixes(%q)[%d] = %s, want %s", tt.raw, i, got[i], w)
				}
			}
		})
	}
}
