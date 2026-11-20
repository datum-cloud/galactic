// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package timing holds the Galactic Edge cell's forwarding-claim timing
// contract (docs/enhancements/networking/galactic-edge/contract.md, "Timing
// and failure bounds"), which every provider instance, galactic-controller and
// galactic-edge in a cell must share, and the monotonic clock they measure it
// on.
package timing

import (
	"time"

	"go.datum.net/galactic/internal/edge/claim"
)

// Params is the cell's claim timing: a renewal grants 15 s on the holder's
// CLOCK_BOOTTIME, any two nodes' clocks run within 1000 ppm of each other, a
// passed deadline stops forwarding within 500 ms, and wall clocks are within
// 2 s. Their TakeoverWait is 15.53 s.
var Params = claim.Params{
	Duration: 15 * time.Second,
	MaxDrift: 0.001,
	Margin:   500 * time.Millisecond,
	MaxSkew:  2 * time.Second,
}

// RenewInterval is how often a provider instance renews its lease: two
// renewals in a row can fail before the lease expires.
const RenewInterval = 5 * time.Second
