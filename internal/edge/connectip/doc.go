// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package connectip terminates MASQUE CONNECT-IP (RFC 9484) requests over
// HTTP/3 with HTTP Datagrams (RFC 9297) on the scope-free URI template
// https://<authority>/.well-known/masque/ip/*/*/.
//
// Each request supplies exactly one bearer credential and one Galactic-VPC
// header. Admission authenticates and authorizes the request, returning an
// exclusive connector /96 lease on a programmed gVPC attachment. The server
// validates the grant before opening its packet backend or accepting the tunnel.
// Invalid credentials produce 401, denied gVPC access 403, and unavailable
// authority or insufficient datagram capacity 503. Only an admitted request
// receives the inner MTU probe datagram.
//
// Config.Limits bounds the work before admission: open QUIC connections,
// request streams per connection, requests inside Admit, and admitted
// requests. A connection over its cap is closed with H3_EXCESSIVE_LOAD, and a
// request over either request cap gets 503 before Admit runs. A TUNBackend
// session queues at most 128 packets or 256 KiB toward its client.
//
// ADDRESS_ASSIGN communicates the delegated /96 and ROUTE_ADVERTISEMENT the
// authorized destinations. Clients may use addresses throughout the /96,
// including subdivisions. Source checks reject addresses outside that prefix;
// reverse delivery is restricted to it. TUN demultiplexing uses the delegated
// prefix within one gVPC, allowing overlapping addresses across gVPCs.
// Oversized packets toward a client produce ICMP Packet Too Big toward the
// backend. Every admitted path must support a 1280-byte inner IPv6 packet.
//
// The admission adapter owns authentication, allocation, connector identity,
// claim epochs, route authority and reconnect semantics. It signals expiry or
// revocation through the lease; the server cancels the tunnel, closes packet
// I/O and then releases the lease. Independent datapath and route fencing must
// be enforced by the foundation even when a protocol worker is paused.
// NewTUNBackend consumes a descriptor supplied by the attachment provisioner;
// it does not create devices, enter namespaces or program routes. A
// TUNBackend checks no authority of its own: serve it only through a wrapper
// that does, as internal/edge/masque does for every packet.
//
// This package provides the HTTP/3 protocol component and integration interfaces,
// not a production admission authority or host attachment controller. HTTP/2
// fallback is a separate implementation. The process-local admission authority
// and credential fixtures exist only in tests.
package connectip
