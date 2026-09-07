// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package cnimaster holds the logic the two master plugins share. Both own the
// same node-level lifecycle: parse the config, resolve node and API settings,
// create a VRF, patch the pod's attachment definition, and answer CHECK and
// STATUS. They differ only in which kernel interface primitive they call and,
// for CHECK, whether there is a guest namespace to inspect, since tap never
// enters one. That sliver stays in each package; everything else lives here so a
// fix happens once.
//
// PluginConf is the shared config shape, which each master plugin aliases so its
// own call sites keep referring to their own package's type.
package cnimaster
