// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"net/netip"
	"os"
	"testing"
	"time"
)

// TestRawSocket probes a real destination over a raw socket. It needs
// CAP_NET_RAW and a reachable target, so it runs only when
// FABRIC_PROBE_SOURCE and FABRIC_PROBE_TARGET are set, e.g. inside a lab
// container.
func TestRawSocket(t *testing.T) {
	srcEnv, dstEnv := os.Getenv("FABRIC_PROBE_SOURCE"), os.Getenv("FABRIC_PROBE_TARGET")
	if srcEnv == "" || dstEnv == "" {
		t.Skip("FABRIC_PROBE_SOURCE and FABRIC_PROBE_TARGET not set")
	}
	src, dst := netip.MustParseAddr(srcEnv), netip.MustParseAddr(dstEnv)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	ping, err := (&Prober{}).Ping(ctx, src, dst, Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("ping: %v", ping)
	if ping.Received == 0 {
		t.Errorf("no echo replies from %s", dst)
	}
	tr, err := (&Prober{}).Traceroute(ctx, src, dst, Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("traceroute: %v", tr)
	if !tr.Reached {
		t.Errorf("traceroute did not reach %s", dst)
	}
}
