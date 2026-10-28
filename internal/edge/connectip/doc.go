// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package connectip terminates MASQUE CONNECT-IP (RFC 9484) requests on the
// scope-free URI template https://<authority>/.well-known/masque/ip/*/*/,
// over HTTP/3 with HTTP Datagrams (RFC 9297) on Serve, and over HTTP/2 with
// TLS on ServeTLS, where packets travel in DATAGRAM capsules on the request
// stream.
//
// Both transports share one request path after parsing: the limits,
// Admission, grant checks, backend session and packet policy. HTTP/2 needs
// Extended CONNECT (RFC 8441), which net/http offers only when the process
// starts with GODEBUG containing http2xconnect=1; ServeTLS refuses to run
// without it.
//
// Each request supplies exactly one bearer credential and one Galactic-VPC
// header. Admission authenticates and authorizes the request, returning an
// exclusive connector /96 lease on a programmed gVPC attachment. The server
// validates the grant before opening its packet backend or accepting the tunnel.
// Invalid credentials produce 401, denied gVPC access 403, and unavailable
// authority or insufficient datagram capacity 503. Only an admitted HTTP/3
// request receives the inner MTU probe datagram.
//
// Config.Limits bounds the work before admission: open QUIC and TCP
// connections, in total and per source address, the handshake time, request
// streams per connection, the header section size, requests inside Admit, in
// total and per credential, and admitted requests. A QUIC connection over a
// cap is closed with H3_EXCESSIVE_LOAD and a TCP one when accepted, and a
// request over a request cap gets 503 before Admit runs. A TUNBackend session
// queues at most 128 packets or 256 KiB toward its client.
//
// Over HTTP/2 the server parses capsules incrementally and holds at most one
// 1508-byte DATAGRAM capsule per request. It discards larger DATAGRAM
// capsules and unknown capsules as they arrive, and ends a request on a
// malformed or oversized ADDRESS_REQUEST. A capsule write that cannot finish
// within 5 seconds ends that request, so a client that stops reading cannot
// hold its session or another one.
//
// ADDRESS_ASSIGN communicates the delegated /96 and ROUTE_ADVERTISEMENT the
// authorized destinations. Clients may use addresses throughout the /96,
// including subdivisions. Source checks reject addresses outside that prefix;
// reverse delivery is restricted to it. TUN demultiplexing uses the delegated
// prefix within one gVPC, allowing overlapping addresses across gVPCs.
// Oversized packets toward a client produce ICMP Packet Too Big toward the
// backend: over HTTP/3 above the path's datagram size, reporting 1280, and
// over HTTP/2 above 1500 bytes, reporting 1500. Every admitted path must
// support a 1280-byte inner IPv6 packet. When an HTTP/3 path shrinks so that
// a packet of at most 1280 bytes no longer fits, the request ends (RFC 9484
// section 10.1) rather than answering with an error its sender cannot act
// on.
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
// The server counts every answered request by transport (h3, h2) and
// outcome, every accepted request's end by cause, its open connections,
// admissions and tunnels, and the packets and bytes it forwards. Metric
// labels are only the transport, direction and fixed enums. The connector,
// principal, VPC, prefix, attachment, claim and epoch go to the session's
// log lines, which carry the same session ID as the admission authority's.
// Neither carries a credential or packet contents.
//
// This package provides the protocol component and integration interfaces,
// not a production admission authority or host attachment controller. A
// connector that moves from HTTP/3 to HTTP/2 is admitted again through the
// same Admission, which decides whether the new request replaces the old
// owner. The process-local admission authority and credential fixtures exist
// only in tests.
package connectip
