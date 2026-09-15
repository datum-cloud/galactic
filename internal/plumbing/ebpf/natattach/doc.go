// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package natattach loads the compiled NAT66 XDP program and attaches it to
// every one of a shard's fabric-facing uplinks.
//
// It mirrors the edge attach package's mechanics almost verbatim: pinned maps,
// verifier-error unwrapping, incompatible-map recreation on a schema change, and
// native-driver-mode attach with no generic-mode fallback. See that package for
// the rationale behind each, which applies here unchanged.
//
// # No kernel preflight check
//
// Unlike its sibling, Load runs no preflight check first. The edge preflight
// package is scoped to that datapath's own map types, which do not include the
// LRU hash this connection table uses, and the uSID preflight package is scoped
// to the TC-BPF datapath. Neither fits, and a third package is out of scope for
// now. Loading already surfaces "this kernel cannot load this program" clearly,
// just later than a dedicated check would.
//
// # No re-attachment
//
// Every uplink in the operator-configured list is attached at process startup,
// so a multi-homed shard node translates on all of them and losing one uplink
// does not stop translation on the rest. A single uplink is simply a
// one-element list.
//
// Attachment happens once, though, and nothing here watches for link changes
// afterwards: an interface that appears after startup gets no program until
// the process restarts. That is the remaining gap, and it is a narrower one
// than attaching to a single named uplink was -- a node's fabric uplinks are
// present at boot, where which one carries traffic is decided by routing and
// changes at any time.
package natattach
