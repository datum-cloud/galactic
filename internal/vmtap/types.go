// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package vmtap

import (
	"github.com/containernetworking/cni/pkg/types"
)

// PluginConf is the vmtap-cni configuration passed via stdin on each
// invocation, as a chained entry inside the pod's primary conflist (e.g.
// appended to whatever Cilium installs at /etc/cni/net.d/05-cilium.conflist).
// It carries no VPC/VPCAttachment identifiers — those belong exclusively to
// galactic-cni.
type PluginConf struct {
	types.PluginConf

	// Enabled gates whether this invocation does anything. Defaults to true.
	// Set to false to no-op the plugin for a given conflist entry without
	// removing it from the chain — a cheap kill switch independent of
	// whichever pod-level signal (annotation vs RuntimeClass) ultimately
	// decides which pods get this conflist entry at all (see
	// .local/kraftlet-cilium-tap-plan.md section 7).
	Enabled *bool `json:"enabled,omitempty"`

	// TapName overrides the default tap interface name ("tap0").
	TapName string `json:"tap_name,omitempty"`

	// OwnerUID and OwnerGID set the tap device's owner so kraftlet can open
	// its fd without running as root or holding CAP_NET_ADMIN. Zero (root)
	// if unset.
	OwnerUID uint32 `json:"owner_uid,omitempty"`
	OwnerGID uint32 `json:"owner_gid,omitempty"`

	// FilterPriority overrides the default tc filter priority used for the
	// mirred redirect filters. Only needed if the default collides with
	// Cilium's own bpf hooks on a given cluster/datapath mode — see the
	// Cilium-specific caveats in docs/vmtap-cni/configuration.md.
	FilterPriority uint16 `json:"filter_priority,omitempty"`
}

// enabled reports whether the plugin should act on this invocation.
// Defaults to true when unset.
func (c *PluginConf) enabled() bool {
	return c.Enabled == nil || *c.Enabled
}

// redirectInterfaceInfo describes the interface Cilium already configured
// (typically eth0), read from prevResult and netlink. It is never mutated —
// only used to describe the tap's redirect target and to populate the CNI
// result the guest-side consumer (kraftlet) reads.
type redirectInterfaceInfo struct {
	name string
	mac  string
	mtu  int // link MTU, from prevResult

	// routeMTU is the pod's route MTU (accounting for overlay/tunnel
	// overhead), read from the kernel's routing table rather than copied
	// from the link MTU. See the MTU caveat in
	// .local/kraftlet-cilium-tap-plan.md section 4 — Cilium adjusts the
	// route MTU independently of the interface's link MTU.
	routeMTU int
}
