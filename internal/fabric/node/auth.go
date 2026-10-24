// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package node

import (
	"context"
	"crypto/tls"
	"log/slog"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	fabricv1 "go.datum.net/galactic/api/fabric/v1"
	"go.datum.net/galactic/internal/fabric/errcode"
	"go.datum.net/galactic/internal/fabric/identity"
)

type callerKey struct{}

// CallerFrom returns the authenticated caller attached by the interceptor.
func CallerFrom(ctx context.Context) (identity.ID, bool) {
	id, ok := ctx.Value(callerKey{}).(identity.ID)
	return id, ok
}

// WithCaller attaches an identity to ctx, as the interceptor does.
func WithCaller(ctx context.Context, id identity.ID) context.Context {
	return context.WithValue(ctx, callerKey{}, id)
}

// AllowedCaller is the handshake-time check for the node's server: only the
// cell gateway and operator identities may connect. Per-RPC rules follow in
// the interceptor.
func AllowedCaller(id identity.ID) error {
	if id.Role == identity.RoleGateway || id.Role == identity.RoleOperator {
		return nil
	}
	return errcode.Status(errcode.Unauthorized, "identity "+id.URI()+" may not call fabric-api nodes")
}

// nodeMethods lists the RPCs each role may call.
var nodeMethods = map[identity.Role]map[string]bool{
	identity.RoleGateway: {
		fabricv1.FabricService_Execute_FullMethodName: true,
		fabricv1.FabricService_Info_FullMethodName:    true,
	},
	identity.RoleOperator: {
		fabricv1.FabricService_Execute_FullMethodName: true,
		fabricv1.FabricService_Info_FullMethodName:    true,
	},
}

// AuthInterceptor authorizes each call from the verified mTLS identity,
// attaches it to the context, and logs the call with its outcome. methods
// maps each role to the full method names it may call; nil selects the
// node's own table.
func AuthInterceptor(methods map[identity.Role]map[string]bool) grpc.UnaryServerInterceptor {
	if methods == nil {
		methods = nodeMethods
	}
	return (&Authorizer{Methods: methods}).Unary()
}

// Authorizer authorizes unary and streaming calls from the verified mTLS
// identity and attaches it to the call's context.
type Authorizer struct {
	// Methods maps each role to the full method names it may call.
	Methods map[identity.Role]map[string]bool
	// Credentials, when set, re-verifies the peer's chain against the
	// current trust bundle, its validity and its cell on every call, refusing
	// a failure as UNAUTHENTICATED like a failed handshake, and ends each
	// call's context when the peer's certificate expires; a stream then
	// refuses every further send and receive. A handler must still watch its
	// context: a send or receive already blocked in the transport is not
	// interrupted. Without Credentials the handshake's verification stands
	// for the connection's life.
	Credentials *identity.Credentials
	// Allow, when set, is checked on every call after the method table,
	// e.g. an allowlist of identities.
	Allow func(identity.ID) error
}

// authorize returns the caller's identity, a context carrying it and ending
// no later than its certificate, and the context's cancel function.
func (a *Authorizer) authorize(
	ctx context.Context, method string,
) (identity.ID, context.Context, context.CancelFunc, error) {
	id, notAfter, err := a.peer(ctx)
	if err != nil {
		return identity.ID{}, nil, nil, err
	}
	if !a.Methods[id.Role][method] {
		return identity.ID{}, nil, nil, errcode.Status(errcode.Unauthorized, id.URI()+" may not call "+method)
	}
	if a.Allow != nil {
		if err := a.Allow(id); err != nil {
			return identity.ID{}, nil, nil, err
		}
	}
	ctx = WithCaller(ctx, id)
	if notAfter.IsZero() {
		ctx, cancel := context.WithCancel(ctx)
		return id, ctx, cancel, nil
	}
	ctx, cancel := context.WithDeadline(ctx, notAfter)
	return id, ctx, cancel, nil
}

// peer returns the caller's identity and, when Credentials is set, the
// expiry of its re-verified certificate.
func (a *Authorizer) peer(ctx context.Context) (identity.ID, time.Time, error) {
	if a.Credentials == nil {
		id, err := peerIdentity(ctx)
		if err != nil {
			return identity.ID{}, time.Time{}, errcode.Status(errcode.Unauthorized, err.Error())
		}
		return id, time.Time{}, nil
	}
	state, err := peerTLS(ctx)
	if err != nil {
		return identity.ID{}, time.Time{}, status.Error(codes.Unauthenticated, err.Error())
	}
	id, err := a.Credentials.VerifyClient(state)
	if err != nil {
		return identity.ID{}, time.Time{},
			status.Error(codes.Unauthenticated, "peer certificate no longer verifies: "+err.Error())
	}
	return id, state.PeerCertificates[0].NotAfter, nil
}

// Unary returns the unary server interceptor, which also logs each call
// with its outcome.
func (a *Authorizer) Unary() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		id, ctx, cancel, err := a.authorize(ctx, info.FullMethod)
		if err != nil {
			return nil, err
		}
		defer cancel()
		start := time.Now()
		resp, err := handler(ctx, req)
		attrs := []any{"method", info.FullMethod, "caller", id.URI(), "duration", time.Since(start)}
		if r, ok := req.(interface{ GetRequestId() string }); ok {
			attrs = append(attrs, "requestID", r.GetRequestId())
		}
		logCall(attrs, err)
		return resp, err
	}
}

// Stream returns the streaming server interceptor, which also logs each
// stream with its outcome.
func (a *Authorizer) Stream() grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		id, ctx, cancel, err := a.authorize(ss.Context(), info.FullMethod)
		if err != nil {
			return err
		}
		defer cancel()
		start := time.Now()
		err = handler(srv, &callerStream{ServerStream: ss, ctx: ctx})
		logCall([]any{"method", info.FullMethod, "caller", id.URI(), "duration", time.Since(start)}, err)
		return err
	}
}

func logCall(attrs []any, err error) {
	if err != nil {
		slog.Info("rpc failed", append(attrs, "code", errcode.Of(err), "error", errcode.Message(err))...)
	} else {
		slog.Debug("rpc", attrs...)
	}
}

// callerStream is a server stream whose context carries the caller and
// which refuses to send or receive once that context has ended.
type callerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *callerStream) Context() context.Context { return s.ctx }

func (s *callerStream) SendMsg(m any) error {
	if err := s.ctx.Err(); err != nil {
		return status.FromContextError(err).Err()
	}
	return s.ServerStream.SendMsg(m)
}

func (s *callerStream) RecvMsg(m any) error {
	if err := s.ctx.Err(); err != nil {
		return status.FromContextError(err).Err()
	}
	return s.ServerStream.RecvMsg(m)
}

func peerIdentity(ctx context.Context) (identity.ID, error) {
	state, err := peerTLS(ctx)
	if err != nil {
		return identity.ID{}, err
	}
	return identity.PeerID(state)
}

func peerTLS(ctx context.Context) (tls.ConnectionState, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return tls.ConnectionState{}, errNoPeer
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(tlsInfo.State.PeerCertificates) == 0 {
		return tls.ConnectionState{}, errNoPeer
	}
	return tlsInfo.State, nil
}

type authError string

func (e authError) Error() string { return string(e) }

const errNoPeer = authError("call has no verified mTLS peer")
