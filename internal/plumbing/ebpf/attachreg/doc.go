// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package attachreg writes one VPC attachment's rows, and this node's own, into
// the uSID datapath's pinned maps.
//
// It has two callers that must write identical values. galactic-bgp registers
// an attachment at CNI ADD through RegisterDatapath and RegisterTenantGateway.
// The galactic-cni daemon rebuilds rows a map recreation has lost through the
// Maps Fill methods, from kernel state and CRDs rather than a CNI result. Both
// derive every value through the helpers here, so the two cannot drift apart.
//
// The Fill methods only write a row that is missing. A row that exists, from
// an ADD, from the ingress sidecar, or from the sidecar return path, is left as
// it is.
package attachreg
