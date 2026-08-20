// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cnibgp

import (
	"fmt"
	"testing"

	"github.com/containernetworking/cni/pkg/skel"

	"go.datum.net/galactic/internal/config"
)

// TestCmdDelIdempotent returns nil even when the CNI config is invalid, per
// the CNI spec's DEL idempotency requirement.
func TestCmdDelIdempotent(t *testing.T) {
	args := &skel.CmdArgs{
		ContainerID: testContainerID,
		StdinData:   []byte("not valid json"),
	}

	if err := cmdDel(args); err != nil {
		t.Fatalf("cmdDel with invalid config returned error = %v, want nil", err)
	}
}

// TestCmdDelParsesConfigForLogging exercises the valid-config path: DEL has
// nothing to clean up itself (GC handles it), but it should still be able to
// parse the conflist it's given — vpc/vpcAttachment come from that parse,
// and CNIVersion for the printed result comes from pluginConf.CNIVersion,
// not a hardcoded "1.0.0", so a conflist authored with a different version
// still gets a matching result back on DEL the same way ADD/CHECK do.
func TestCmdDelParsesConfigForLogging(t *testing.T) {
	// parseConf resolves cniConfig's node-level env vars, which is normally
	// done once at process startup by InitCNIConfig() (cmd/galactic-bgp's
	// main); tests that go through parseConf need the same setup. Setting
	// GALACTIC_CNI_NODE_NAME explicitly also skips parseConf's fallback to
	// hostconf.DetectNodeNameFromAPI, which would otherwise try (and hang
	// retrying) to reach a real API server that doesn't exist in this test.
	t.Setenv(config.EnvCNINodeName, "test-node")
	cniConfig = config.NewCNIConfig()
	t.Cleanup(func() { cniConfig = nil })

	conf := fmt.Sprintf(
		`{"cniVersion":"1.1.0","name":"test","type":"galactic-bgp","vpc":"%s","vpcattachment":"%s"}`,
		testVPC, testAttachment,
	)
	args := &skel.CmdArgs{
		ContainerID: testContainerID,
		StdinData:   []byte(conf),
	}

	if err := cmdDel(args); err != nil {
		t.Fatalf("cmdDel with valid config returned error = %v, want nil", err)
	}
}
