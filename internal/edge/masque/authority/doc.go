// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package authority is the MASQUE grant authority: it authenticates
// connector credentials, keeps the durable connector allocation ledger and
// issues the finite EdgeService of each connector authorization, which the
// MASQUE provider's adapter consumes through masque.Authorizer.
//
// The operator keeps one grant record per connector in a Secret of the
// authority's namespace. A record stores the SHA-256 digest of the
// connector's bearer credential, never the credential, with its revision,
// expiry, enabled flag, VPC and allowed destinations. One ledger ConfigMap
// per VPC and cell holds every connector's /96 and attachment pool; retired
// entries stay as tombstones, so no /96 or pool is ever reassigned.
//
// Authorize matches a credential against every record in constant time,
// rereads the record, the VPC and the ledger without a cache, and issues one
// EdgeService per authorization incarnation, bound to the calling provider
// pod. Its validUntil is the credential expiry or the read start plus TTL
// less IssuerSkew, whichever is earlier. Refresh repeats those reads and
// renews validUntil only while the credential revision is current and
// enabled. Retire, revocation and rotation set validUntil in the past and
// mark the incarnation retired, which is never renewed again. The authority
// keeps no state of its own beyond the API objects, so a restarted or new
// instance rereads everything before issuing anything.
//
// Server serves Authorize, Refresh and Retire over HTTPS to provider pods
// that present a pod-bound ServiceAccount token, and Client is the provider
// side's masque.Authorizer.
package authority
