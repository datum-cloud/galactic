// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package connectip terminates MASQUE CONNECT-IP (RFC 9484) requests carried
// over HTTP/3 with HTTP Datagrams (RFC 9297) and hands the proxied IP packets
// to a [PacketBackend].
//
// # Request
//
// Clients use the scope-free URI template
//
//	https://<authority>/.well-known/masque/ip/*/*/
//
// that is, an Extended CONNECT with :protocol connect-ip, :authority equal to
// the server's configured authority and :path equal to [TemplatePath]. IP flow
// forwarding scopes (a concrete target or IP protocol) are not supported.
//
// # Admission
//
// A request is admitted before the server accepts it, and a rejected request
// never reaches the backend:
//
//   - Authorization must carry exactly one "Bearer <token>" credential that
//     resolves to a [Principal]; otherwise 401 with WWW-Authenticate: Bearer.
//   - The [VPCHeader] header must name exactly one VPC (one field line, no
//     comma-separated list); otherwise 400.
//   - The principal must be granted that VPC and the VPC must be configured;
//     otherwise 403, so an unknown VPC is indistinguishable from an
//     ungranted one.
//   - The QUIC connection must currently be able to carry an HTTP Datagram
//     holding a 1280-byte inner packet to the client; otherwise 503.
//   - The VPC's address pool must have a free address; otherwise 503.
//
// An admitted request receives one ADDRESS_ASSIGN capsule with a /128 from the
// VPC's pool and one ROUTE_ADVERTISEMENT capsule with the VPC's routes. The
// assigned address is unique per VPC but may repeat across VPCs, and requests
// to different VPCs can share one QUIC connection.
//
// # Packet policy
//
// The proxy drops a packet from the client whose source is not the assigned
// address or whose destination lies outside the advertised routes, and drops a
// packet toward the client whose destination is not the assigned address.
// When a packet toward the client does not fit the connection's datagram size,
// the ICMP Packet Too Big built by the CONNECT-IP layer is written back to the
// backend session.
package connectip
