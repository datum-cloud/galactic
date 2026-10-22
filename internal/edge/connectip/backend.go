// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package connectip

import (
	"context"
	"errors"
	"net/netip"
)

// SessionInfo identifies one admitted CONNECT-IP request.
type SessionInfo struct {
	// ID identifies this request within the admission authority.
	ID uint64
	// Principal is the name of the authenticated principal.
	Principal string
	// VPC is the VPC the request was admitted to.
	VPC string
	// Prefix is the connector's authorized, masked IPv6 /96.
	Prefix netip.Prefix
	// Connector, Attachment and Claim are immutable authority identities.
	Connector  string
	Attachment string
	Claim      string
	// Epoch identifies the active forwarding owner.
	Epoch uint64
}

// PacketBackend carries the IP packets of admitted requests into and out of
// their gVPC. Implementations validate the attachment and claim epoch supplied
// by admission and must stop packet I/O when its authority expires.
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
	// not retain pkt after returning. Close must unblock pending writes.
	WritePacket(pkt []byte) error
	// ReadPacket blocks until the VPC has a packet for the client, copies it
	// into buf and returns its length. It returns an error once ctx is done or
	// the session is closed.
	ReadPacket(ctx context.Context, buf []byte) (int, error)
	// Close ends the session and unblocks pending I/O. It must be idempotent.
	Close() error
}

// ErrUnauthenticated indicates a missing or invalid client identity.
var ErrUnauthenticated = errors.New("unauthenticated")

// ErrForbidden indicates that the principal is not authorized for the gVPC.
var ErrForbidden = errors.New("forbidden")

// Admission is the trusted control-plane adapter for a CONNECT-IP request.
// It authenticates the credential, checks gVPC access and acquires the connector's
// exclusive /96 claim on a programmed attachment. A failed call releases any
// partial resources. It must honor ctx and never log or retain raw credentials.
// Allocation, connector identity and reconnect policy belong to this authority.
type Admission interface {
	Admit(ctx context.Context, credential, vpc string) (Lease, error)
}

// Lease binds a request to an authorized attachment and forwarding owner.
// Info and Routes return immutable snapshots. Done closes on expiry, revocation
// or ownership loss. Close releases only this claim epoch, after packet I/O ends.
// The authority must independently fence packet forwarding and route publication;
// cancelling the protocol worker alone does not fence a paused or partitioned owner.
type Lease interface {
	Info() SessionInfo
	Routes() []netip.Prefix
	Done() <-chan struct{}
	Close() error
}
