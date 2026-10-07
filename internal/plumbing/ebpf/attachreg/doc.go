// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package attachreg writes one VPC attachment's rows, and this node's own, into
// the uSID datapath's pinned maps. galactic-bgp registers an attachment at CNI
// ADD through RegisterDatapath and RegisterTenantGateway.
package attachreg
