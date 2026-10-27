// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package node

import (
	"context"
	"log/slog"
	"sync"

	"google.golang.org/grpc"

	permitv1 "go.datum.net/galactic/api/fabric/permit/v1"
)

// GatewayConn is a PermitGateway over a connection to the cell gateway that
// Redial replaces. A TLS connection presents the certificate it was opened
// with for as long as it lasts, while the gateway re-verifies its caller on
// every call; a connection outliving the node's credentials (a renewal, or
// a replaced fabric-api-certs pod, which changes the node's identity) is
// refused until it happens to close. Redial on every credential load keeps
// the connection's identity current.
type GatewayConn struct {
	dial func() (*grpc.ClientConn, error)

	mu  sync.Mutex
	cur *gatewayConn
}

type gatewayConn struct {
	conn   *grpc.ClientConn
	client permitv1.PermitServiceClient
	calls  sync.WaitGroup
}

// NewGatewayConn returns a GatewayConn whose connections dial makes.
func NewGatewayConn(dial func() (*grpc.ClientConn, error)) (*GatewayConn, error) {
	g := &GatewayConn{dial: dial}
	c, err := g.open()
	if err != nil {
		return nil, err
	}
	g.cur = c
	return g, nil
}

func (g *GatewayConn) open() (*gatewayConn, error) {
	conn, err := g.dial()
	if err != nil {
		return nil, err
	}
	return &gatewayConn{conn: conn, client: permitv1.NewPermitServiceClient(conn)}, nil
}

// Redial replaces the connection for later calls. The previous one closes
// once the calls already running on it end, so a redial never interrupts a
// permit request. If dialing fails, the previous connection stays in use.
func (g *GatewayConn) Redial() {
	next, err := g.open()
	if err != nil {
		slog.Warn("probe permit connection to the gateway not replaced", "error", err)
		return
	}
	g.mu.Lock()
	prev := g.cur
	g.cur = next
	g.mu.Unlock()
	go func() {
		prev.calls.Wait()
		_ = prev.conn.Close()
	}()
}

// Close closes the current connection.
func (g *GatewayConn) Close() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.cur.conn.Close()
}

// acquire returns the current connection, which the caller releases with
// its calls.Done once its call ends.
func (g *GatewayConn) acquire() *gatewayConn {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.cur.calls.Add(1)
	return g.cur
}

// RequestPermit implements PermitGateway.
func (g *GatewayConn) RequestPermit(
	ctx context.Context, in *permitv1.RequestPermitRequest, opts ...grpc.CallOption,
) (*permitv1.RequestPermitResponse, error) {
	c := g.acquire()
	defer c.calls.Done()
	return c.client.RequestPermit(ctx, in, opts...)
}

// ReleasePermit implements PermitGateway.
func (g *GatewayConn) ReleasePermit(
	ctx context.Context, in *permitv1.ReleasePermitRequest, opts ...grpc.CallOption,
) (*permitv1.ReleasePermitResponse, error) {
	c := g.acquire()
	defer c.calls.Done()
	return c.client.ReleasePermit(ctx, in, opts...)
}
