// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package trafficpolicy

import "time"

// HeartbeatInterval is how often a node refreshes its
// TrafficPolicyBinding status entry while nothing else in it changes.
const HeartbeatInterval = 10 * time.Minute

// StaleAfter is how old a node's heartbeat may be before its entry no longer
// counts as current. It allows one missed refresh on top of the node
// reconciler's 5 minute resync, so a node whose reconciles succeed is never
// reported stale. One that keeps failing retries on controller-runtime's
// backoff, which can exceed it, and so may read Stale instead of Failed;
// either way the binding is not Installed.
const StaleAfter = 25 * time.Minute
