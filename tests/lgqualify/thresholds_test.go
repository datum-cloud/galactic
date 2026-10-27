// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package lgqualify_test

import "time"

// The pass thresholds, fixed from docs/designs/looking-glass-service.md
// ("Initial defaults and hard bounds" and "Cancellation, delivery, and
// failure assumptions") before any qualification run. A failure against
// one is a qualification failure, never a reason to change it here.
const (
	// stopBound is how soon reachable node probes stop after an explicit
	// cancellation, disconnect, ownership loss or service disable is
	// received; switchRead is how often each replica reads the switch.
	stopBound  = 2 * time.Second
	switchRead = time.Second
	// blackholeBound is transport liveness detection plus local cleanup.
	blackholeBound = 10*time.Second + 2*time.Second
	// leaseReadBound bounds the leader's uncached Lease read.
	leaseReadBound = time.Second
	// recoveryHold is the hold after every leadership acquisition. Buckets
	// then start empty and a new project key refills from the hold's end,
	// so a new project's first admission comes 1/0.2 s = 5 s after it, plus
	// the cell's 0.5 s; resumeSlack adds the suite's 3 s polling period.
	recoveryHold = 125 * time.Second
	resumeSlack  = 5*time.Second + time.Second + 3*time.Second
	// maxEmission is the latest a node job may emit after dispatch: its 30 s
	// deadline plus the 2 s allowance.
	maxEmission = 32 * time.Second
	// queueWait bounds a router job's wait for a slot.
	queueWait = 10 * time.Second
	// certsReplacementBound is how soon after a replaced fabric-api-certs
	// pod turns Ready a direct operator probe on its node must succeed:
	// certsync copies the new certificate within 10 s, the sidecar reloads
	// it within another 10 s, plus 10 s for the probe and its permit.
	certsReplacementBound = 30 * time.Second
	// cleanupReadyBound is how long after the last scenario every gateway
	// and fabric-router pod must be Ready: kubelet's 5 minute ceiling on a
	// crashed container's restart back-off, plus a minute.
	cleanupReadyBound = 6 * time.Minute

	// The contract's default limits, which the lab runs.
	requestCellRate     = 2.0
	requestCellBurst    = 8
	requestProjectRate  = 0.2
	requestProjectBurst = 2
	packetHostRate      = 20.0
	packetHostBurst     = 640.0
	packetPrefixRate    = 40.0
	packetPrefixBurst   = 640.0
	pingPackets         = 3
	traceroutePackets   = 20

	// convergenceTrials is the minimum number of controlled convergence
	// trials in each of the control and loaded series; convergenceRatio is
	// how much slower the loaded p95 may be.
	convergenceTrials = 20
	convergenceRatio  = 1.10
)
