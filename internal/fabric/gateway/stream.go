// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gateway

import (
	"errors"
	"net"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"

	forwardv1 "go.datum.net/galactic/api/fabric/forward/v1"
	servicev1 "go.datum.net/galactic/api/fabric/service/v1"
	"go.datum.net/galactic/internal/fabric/errcode"
	"go.datum.net/galactic/internal/fabric/gateway/limit"
	"go.datum.net/galactic/internal/fabric/identity"
)

// Delivery and transport bounds of the Looking Glass service, per gateway
// replica.
const (
	// SendBound bounds how long a finished router outcome may wait to enter
	// a stream's buffer, and how long one write to the stream's consumer
	// may block. Either running out cancels the request and ends its stream.
	SendBound = 2 * time.Second
	// MaxServiceRPCs bounds the RunDiagnostic calls one replica serves at
	// once.
	MaxServiceRPCs = 32
	// MaxForwardRPCs bounds the forwarded calls the leader serves at once.
	MaxForwardRPCs = 16
	// MaxServiceConns bounds the TLS connections service identities hold
	// open to one replica.
	MaxServiceConns = 64
	// transportWindow is every connection's and stream's flow-control
	// window and read and write buffer. A fixed window also turns off
	// gRPC's bandwidth-delay window growth.
	transportWindow = 64 << 10
	// keepaliveTime and keepaliveTimeout bound how long a silent connection
	// lives: the server pings a peer it has not heard from for
	// keepaliveTime and closes the connection keepaliveTimeout later, so a
	// blackholed peer's calls are cancelled within 10 s of its last frame.
	keepaliveTime    = 4 * time.Second
	keepaliveTimeout = 4 * time.Second
	// keepaliveMinTime is the most often a client may ping.
	keepaliveMinTime = 5 * time.Second
)

// errConsumerStalled is the cause with which a request is cancelled when its
// consumer stops reading.
var errConsumerStalled = errors.New("the stream's consumer stopped reading")

// stalledStatus is the status a request ends with when its consumer stopped
// reading.
func stalledStatus() error {
	return errcode.Status(errcode.Cancelled, "the stream's consumer did not read within the write bound")
}

// eventWriter is a stream's only writer. Each write must finish within
// SendBound. A write that does not is left to the transport, which ends it
// once the handler returns and the stream is reset; every later write then
// fails at once.
type eventWriter struct {
	events  chan *servicev1.DiagnosticEvent
	errs    chan error
	bound   time.Duration
	stalled bool
}

// newEventWriter starts a writer that sends through send. Its owner must
// call close once it stops writing.
func newEventWriter(send func(*servicev1.DiagnosticEvent) error) *eventWriter {
	w := &eventWriter{events: make(chan *servicev1.DiagnosticEvent), errs: make(chan error, 1), bound: SendBound}
	go func() {
		for ev := range w.events {
			w.errs <- send(ev)
		}
	}()
	return w
}

// write sends ev and waits for the transport to take it, at most the write
// bound; past it, write fails with stalledStatus. write is not safe for
// concurrent use.
func (w *eventWriter) write(ev *servicev1.DiagnosticEvent) error {
	if w.stalled {
		return stalledStatus()
	}
	w.events <- ev
	t := time.NewTimer(w.bound)
	defer t.Stop()
	select {
	case err := <-w.errs:
		return err
	case <-t.C:
		w.stalled = true
		return stalledStatus()
	}
}

// close stops the writer once its current write, if any, ends.
func (w *eventWriter) close() { close(w.events) }

// rpcCaps refuses a diagnostic call beyond its method's per-replica cap
// with QueueFull, rather than queueing it.
type rpcCaps map[string]chan struct{}

func newRPCCaps() rpcCaps {
	return rpcCaps{
		servicev1.LookingGlassService_RunDiagnostic_FullMethodName: make(chan struct{}, MaxServiceRPCs),
		forwardv1.ForwardService_ForwardDiagnostic_FullMethodName:  make(chan struct{}, MaxForwardRPCs),
	}
}

func (c rpcCaps) stream(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	slots, ok := c[info.FullMethod]
	if !ok {
		return handler(srv, ss)
	}
	select {
	case slots <- struct{}{}:
		defer func() { <-slots }()
		return handler(srv, ss)
	default:
		return errcode.Retry(errcode.QueueFull, "this gateway replica is serving its maximum number of diagnostic calls",
			string(limit.ScopeQueue), time.Second)
	}
}

// connLimitCreds refuses a service identity's connection once
// MaxServiceConns of them are open, after the TLS handshake identifies it.
type connLimitCreds struct {
	credentials.TransportCredentials
	slots chan struct{}
}

func (c *connLimitCreds) ServerHandshake(raw net.Conn) (net.Conn, credentials.AuthInfo, error) {
	conn, info, err := c.TransportCredentials.ServerHandshake(raw)
	if err != nil {
		return conn, info, err
	}
	tlsInfo, ok := info.(credentials.TLSInfo)
	if !ok {
		return conn, info, nil
	}
	if id, err := identity.PeerID(tlsInfo.State); err != nil || id.Role != identity.RoleService {
		return conn, info, nil
	}
	select {
	case c.slots <- struct{}{}:
		return &releasingConn{Conn: conn, release: sync.OnceFunc(func() { <-c.slots })}, info, nil
	default:
		_ = conn.Close()
		return nil, nil, errors.New("this gateway replica holds its maximum number of service connections")
	}
}

func (c *connLimitCreds) Clone() credentials.TransportCredentials {
	return &connLimitCreds{TransportCredentials: c.TransportCredentials.Clone(), slots: c.slots}
}

// releasingConn frees its connection slot when closed.
type releasingConn struct {
	net.Conn
	release func()
}

func (c *releasingConn) Close() error {
	c.release()
	return c.Conn.Close()
}

// transportOptions bound every connection to the gateway listener: fixed
// flow-control windows and buffers, keepalive that closes a silent
// connection, and the service connection cap.
func transportOptions(creds credentials.TransportCredentials) []grpc.ServerOption {
	return []grpc.ServerOption{
		grpc.Creds(&connLimitCreds{TransportCredentials: creds, slots: make(chan struct{}, MaxServiceConns)}),
		grpc.InitialWindowSize(transportWindow),
		grpc.InitialConnWindowSize(transportWindow),
		grpc.ReadBufferSize(transportWindow),
		grpc.WriteBufferSize(transportWindow),
		grpc.KeepaliveParams(keepalive.ServerParameters{Time: keepaliveTime, Timeout: keepaliveTimeout}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{MinTime: keepaliveMinTime, PermitWithoutStream: true}),
	}
}

// leaderDialOptions bound a follower's connection to the leader like the
// listener bounds its own: fixed windows, and keepalive that ends a
// forwarded call when the leader goes silent. gRPC raises a client's ping
// interval to at least 10 s.
func leaderDialOptions() []grpc.DialOption {
	return []grpc.DialOption{
		grpc.WithInitialWindowSize(transportWindow),
		grpc.WithInitialConnWindowSize(transportWindow),
		grpc.WithReadBufferSize(transportWindow),
		grpc.WithWriteBufferSize(transportWindow),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{Time: 10 * time.Second, Timeout: keepaliveTimeout}),
	}
}

// relay hands each event of a forwarded call to the consumer through w.
// It reads the next event only after the last was written, so a follower
// holds at most the event being written and the one gRPC is receiving.
func relay(recv func() (*servicev1.DiagnosticEvent, error), w *eventWriter) error {
	for {
		ev, err := recv()
		if err != nil {
			return err
		}
		if err := w.write(ev); err != nil {
			return err
		}
	}
}
