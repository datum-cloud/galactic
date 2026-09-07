// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package cnitap implements galactic-tap, the tap master plugin for VM-based
// workloads. It mirrors the veth master but never delegates a device move, there
// being no container namespace to move anything into, the VM managing its own
// guest interface, and never configures a guest-side namespace.
package cnitap

import (
	"go.datum.net/galactic/internal/cnimaster"
	"go.datum.net/galactic/internal/hostconf"
)

// PluginConf is the CNI plugin configuration passed on stdin. It is the same
// shape the veth master uses, so both packages alias the one canonical
// definition rather than each declaring a copy.
type PluginConf = cnimaster.PluginConf

// HostConf holds node-local settings read from /etc/cni/net.d/10-galactic.conflist.
type HostConf = hostconf.HostConf
