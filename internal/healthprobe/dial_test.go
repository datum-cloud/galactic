// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package healthprobe

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"
)

// TestDialUnavailable: a probe over an interface that does not exist, or that
// has no IPv6 link-local address, cannot be sent, which Dial reports as
// ErrUnavailable rather than as a failed probe.
func TestDialUnavailable(t *testing.T) {
	addr := netip.MustParseAddr("fd20::100")
	for _, iface := range []string{"galactic-nonexistent0", "lo"} {
		err := Dial(context.Background(), iface, addr, 80, time.Second)
		if !errors.Is(err, ErrUnavailable) {
			t.Errorf("Dial over %s: err = %v, want ErrUnavailable", iface, err)
		}
	}
}
