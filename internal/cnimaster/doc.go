// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package cnimaster holds logic shared by galactic-cni (internal/cni, the
// veth master plugin) and galactic-tap-cni (internal/cnitap, the tap master
// plugin). Both own the same node-level lifecycle — parse the CNI config,
// resolve node/API settings, create a VRF, patch the pod's NAD, and answer
// CHECK/STATUS — differing only in which kernel interface primitive they
// call (veth vs tap) and, for CHECK, whether there's a guest-side netns to
// inspect (tap never enters one). That interface-specific sliver stays in
// each package; everything else lives here so a fix only has to happen
// once.
//
// PluginConf is the shared CNI config shape; internal/cni and internal/cnitap
// each declare their own `type PluginConf = cnimaster.PluginConf` alias
// (mirroring the existing HostConf alias pattern from internal/hostconf) so
// call sites in either package keep referring to their own package's
// PluginConf.
package cnimaster
