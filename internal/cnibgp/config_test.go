// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cnibgp

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/containernetworking/cni/pkg/skel"

	"go.datum.net/galactic/internal/config"
)

// writeTestConflist writes a minimal static conflist to a temp file and
// points the package-level ConfFile var at it for the duration of the
// calling test, restoring the original value on cleanup -- the same
// override pattern TestCmdDelParsesConfigForLogging's own cniConfig reset
// already establishes for this package's tests.
func writeTestConflist(t *testing.T, nodeName, ebpfInterfaces string) {
	t.Helper()
	confFile := filepath.Join(t.TempDir(), "conflist.json")
	conflistJSON := fmt.Sprintf(`{
  "cniVersion": "1.0.0",
  "name": "galactic",
  "plugins": [
    {"type": "galactic-cni", "node_name": %q, "ebpf_interfaces": %q}
  ]
}`, nodeName, ebpfInterfaces)
	if err := os.WriteFile(confFile, []byte(conflistJSON), 0o600); err != nil {
		t.Fatalf("write test conflist: %v", err)
	}
	original := ConfFile
	ConfFile = confFile
	t.Cleanup(func() { ConfFile = original })
}

// runParseConfViaCmdDel drives parseConf through cmdDel -- the cheapest
// existing entry point into it: cmdDel is otherwise a no-op (GC handles
// real cleanup, see its own doc comment), so this exercises parseConf's
// own config-resolution logic (including the EBPFInterfaces env bridge
// below) without needing cmdAdd's much heavier k8s-client/VRF setup.
func runParseConfViaCmdDel(t *testing.T) {
	t.Helper()
	conf := fmt.Sprintf(
		`{"cniVersion":"1.1.0","name":"test","type":"galactic-bgp","vpc":"%s","vpcattachment":"%s"}`,
		testVPC, testAttachment,
	)
	args := &skel.CmdArgs{ContainerID: testContainerID, StdinData: []byte(conf)}
	if err := cmdDel(args); err != nil {
		t.Fatalf("cmdDel = %v, want nil", err)
	}
}

// TestParseConf_BridgesEBPFInterfacesFromConflistIntoEnv is the regression
// test for the real bug this bridge fixes: attach.ResolveInterfaces (used
// by srv6.ResolveNodeSourceAddress/ResolvePublicUplink,
// internal/cnibgp/bgp.go) reads GALACTIC_CNI_EBPF_INTERFACES via plain
// os.Getenv, which a CNI plugin's own exec environment never carries --
// only the long-running DaemonSet container's env does. Without this
// bridge, every CNI ADD on a node where the interface carrying the
// default IPv6 route isn't the real fabric interface (found live,
// exactly this lab's own topology) silently mis-resolves, producing a
// plausible-but-wrong eBPF map entry with no error at all.
func TestParseConf_BridgesEBPFInterfacesFromConflistIntoEnv(t *testing.T) {
	t.Setenv(config.EnvCNINodeName, "test-node")
	t.Setenv(config.EnvCNIEBPFInterfaces, "") // ensure no leftover value competes with the conflist's own
	cniConfig = config.NewCNIConfig()
	t.Cleanup(func() { cniConfig = nil })

	writeTestConflist(t, "test-node", "eth1,eth2")
	runParseConfViaCmdDel(t)

	const want = "eth1,eth2"
	if got := os.Getenv(config.EnvCNIEBPFInterfaces); got != want {
		t.Errorf("%s after parseConf = %q, want %q (bridged from the conflist)", config.EnvCNIEBPFInterfaces, got, want)
	}
}

// TestParseConf_EBPFInterfacesEnvOverrideWinsOverConflist covers the
// bridge's own "don't override an already-set env var" guard: an operator
// who genuinely does set GALACTIC_CNI_EBPF_INTERFACES on this exec
// environment directly must never have it silently replaced by whatever
// the conflist (a different, possibly stale value) carries.
func TestParseConf_EBPFInterfacesEnvOverrideWinsOverConflist(t *testing.T) {
	t.Setenv(config.EnvCNINodeName, "test-node")
	const wantEnvValue = "eth9"
	t.Setenv(config.EnvCNIEBPFInterfaces, wantEnvValue)
	cniConfig = config.NewCNIConfig()
	t.Cleanup(func() { cniConfig = nil })

	writeTestConflist(t, "test-node", "eth1,eth2")
	runParseConfViaCmdDel(t)

	if got := os.Getenv(config.EnvCNIEBPFInterfaces); got != wantEnvValue {
		t.Errorf("%s after parseConf = %q, want %q (the pre-set env value, untouched)",
			config.EnvCNIEBPFInterfaces, got, wantEnvValue)
	}
}
