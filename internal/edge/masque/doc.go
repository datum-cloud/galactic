// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package masque is the MASQUE connector's Galactic Edge provider adapter:
// the connectip.Admission and connectip.PacketBackend that both CONNECT-IP
// transports use to reach a gVPC through the provider contract
// (docs/edge/provider-contract.md).
//
// An Adapter runs in one provider pod. It registers the pod's EdgeInstance
// and holds its lease, requests one PacketAccess EdgeAttachment per
// EdgeService a request's grant names, and claims the EdgeRoute of each
// connector's /96 under the service's PrefixReachability grant. It admits
// a request only after an Authorizer returned a valid Grant, galactic-edge
// programmed the attachment, the adapter opened the TUN device the
// attachment's status names and reported Ready, and core accepted the route
// claim for that attachment under the current lease epoch. Each admitted request is bound
// to the attachment's UID, the route's claim epoch and the lease epoch, and
// forwards packets only while all three are current and its grant's
// deadline has not passed.
//
// A connector forwards through at most one request. A new request of a
// connector with one open replaces it: the open request ends, and the new
// one is registered only once the old one has closed, its packet I/O
// stopped and its queued packets discarded. The route claim and attachment
// stay held across the handoff. Each request's grant is refreshed through
// the Authorizer while it is open; a refused refresh, or Revoke, ends only
// that connector's request.
//
// Requests of one service share its attachment and device, counted per
// request. Ending one request removes only its own packet registration; the
// last request of a connector releases its route claim, and an attachment
// with no request is deleted after an idle period. Deletes carry the
// object's UID as a precondition, so a stale delete cannot remove a
// replacement. The adapter never touches host networking: galactic-edge
// programs and releases host state, and core holds each attachment with a
// finalizer until its node reports it released.
//
// The adapter counts admissions by outcome, request ends by reason, route
// claims by outcome, device-full drops and lease losses, and reports at
// scrape time how many requests are admitted, programmed or forwarding and
// whether it holds its lease. Labels are only those enums. A request's log
// lines name its session ID, connector, service UID, attachment and its
// UID, route, claim epoch and lease epoch; none carries a credential.
//
// Authentication, connector /96 allocation and EdgeService issuance belong
// to the Authorizer, not to this package.
package masque
