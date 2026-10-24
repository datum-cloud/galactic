// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package hostattach

import (
	"os"
	"testing"
)

// containerTUNEnv opts in to TestContainerCreateTUN. tests/e2e sets it when it
// runs this test binary in the galactic-edge container as the shipped
// DaemonSet defines it.
const containerTUNEnv = "GALACTIC_EDGE_CONTAINER_TUN"

// TestContainerCreateTUN creates a packet-access attachment's TUN device in a
// provider namespace the way ensureTUN does, from inside the agent's
// container, where /dev/net/tun exists only if the DaemonSet provides it.
func TestContainerCreateTUN(t *testing.T) {
	if os.Getenv(containerTUNEnv) == "" {
		t.Skipf("skipping: set %s=1 in the galactic-edge container", containerTUNEnv)
	}
	pod := newTestNS(t).open(t)
	a := Attachment{ID: "edgefx-container", TUN: &TUN{Name: "edgefx-tun"}}
	if err := pod.do(func() error { return createTUN(a) }); err != nil {
		t.Fatal(err)
	}
	h, err := pod.netlink()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = h.Close() }()
	tun, err := h.LinkByName(a.TUN.Name)
	if err != nil {
		t.Fatalf("TUN device not in the provider namespace: %v", err)
	}
	if got := tun.Attrs().Alias; got != ownerAlias(a.ID) {
		t.Fatalf("TUN owner = %q, want %q", got, ownerAlias(a.ID))
	}
}
