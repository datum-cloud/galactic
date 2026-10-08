// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package node

import (
	"context"
	"log/slog"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"

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
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		id, err := peerIdentity(ctx)
		if err != nil {
			return nil, errcode.Status(errcode.Unauthorized, err.Error())
		}
		if !methods[id.Role][info.FullMethod] {
			return nil, errcode.Status(errcode.Unauthorized, id.URI()+" may not call "+info.FullMethod)
		}
		start := time.Now()
		resp, err := handler(WithCaller(ctx, id), req)
		attrs := []any{"method", info.FullMethod, "caller", id.URI(), "duration", time.Since(start)}
		if r, ok := req.(interface{ GetRequestId() string }); ok {
			attrs = append(attrs, "requestID", r.GetRequestId())
		}
		if err != nil {
			slog.Info("rpc failed", append(attrs, "code", errcode.Of(err), "error", errcode.Message(err))...)
		} else {
			slog.Debug("rpc", attrs...)
		}
		return resp, err
	}
}

func peerIdentity(ctx context.Context) (identity.ID, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return identity.ID{}, errNoPeer
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return identity.ID{}, errNoPeer
	}
	return identity.PeerID(tlsInfo.State)
}

type authError string

func (e authError) Error() string { return string(e) }

const errNoPeer = authError("call has no verified mTLS peer")
