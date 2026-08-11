// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package cnitap implements galactic-tap, the tap master plugin for
// VM-based workloads (Kata, Firecracker, kraftlet/Unikraft). It mirrors
// internal/cni (the veth master, galactic-veth) but never delegates to
// host-device (no container netns to move anything into — the VM manages
// its own guest interface) and never configures a guest-side netns.
package cnitap

import (
	"go.datum.net/galactic/internal/cnimaster"
	"go.datum.net/galactic/internal/hostconf"
)

// PluginConf is the CNI plugin configuration passed via stdin on each
// invocation of galactic-tap. It's the same shape galactic-veth
// (internal/cni) uses — see internal/cnimaster's own doc comment — so both
// packages alias the one canonical definition rather than each declaring
// their own copy.
type PluginConf = cnimaster.PluginConf

// HostConf holds node-local settings read from /etc/cni/net.d/10-galactic.conflist.
type HostConf = hostconf.HostConf
