// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package plumbing provides low-level kernel and network primitives shared
// between the Galactic CNI plugin and agent. Sub-packages cover SRv6 endpoint
// encoding and ingress routing (intf, srv6), Linux VRF lifecycle (vrf), and
// interface sysctl configuration (sysctl). Functions that require CAP_NET_ADMIN
// or a real kernel are not unit-tested; use the e2e suite for coverage.
package plumbing
