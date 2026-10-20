// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package connectip

import (
	"context"
	"net/netip"
)

// SessionInfo identifies one admitted CONNECT-IP request.
type SessionInfo struct {
	// ID is unique per Server for the server's lifetime.
	ID uint64
	// Principal is the name of the authenticated principal.
	Principal string
	// VPC is the VPC the request was admitted to.
	VPC string
	// Address is the client address assigned to the request.
	Address netip.Addr
}

// PacketBackend carries the IP packets of admitted requests into and out of
// their VPC.
type PacketBackend interface {
	// Open starts a session for one admitted request. It is called once per
	// request, after admission and before the request is accepted; an error
	// rejects the request.
	Open(ctx context.Context, info SessionInfo) (BackendSession, error)
}

// BackendSession is one request's packet path into its VPC.
type BackendSession interface {
	// WritePacket delivers one IP packet from the client, or an ICMP error
	// generated on the client's behalf, into the VPC. The implementation must
	// not retain pkt after returning.
	WritePacket(pkt []byte) error
	// ReadPacket blocks until the VPC has a packet for the client, copies it
	// into buf and returns its length. It returns an error once ctx is done or
	// the session is closed.
	ReadPacket(ctx context.Context, buf []byte) (int, error)
	// Close ends the session. It is called exactly once, when the request ends.
	Close() error
}
