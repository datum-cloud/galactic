// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package srcfilter builds a node's SRv6 ingress source allow-list from the
// routes it already learns and keeps a datapath's source filter in step with
// it.
//
// Every fabric peer sources its SRv6 traffic from inside its own locator, and
// each node carries a route to every peer locator. A route inside the
// configured SR domain prefixes therefore names a legitimate source, and the
// links that route leaves through name the uplinks that source may arrive on.
//
// The package decides what to allow and when; it writes through the Target
// interface, so any datapath with an allow-list, uplink slots and a mode can
// reuse it behind a thin adapter.
package srcfilter
