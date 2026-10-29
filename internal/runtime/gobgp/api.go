// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gobgp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"path"
	"path/filepath"
	"time"

	gobgpserver "github.com/osrg/gobgp/v4/pkg/server"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"k8s.io/apimachinery/pkg/types"
)

// maxSocketPath is the longest path a Linux unix socket address holds, less
// the terminating NUL.
const maxSocketPath = 107

// readOnlyMethods are the GoBgpService methods the socket serves. Each only
// reads state. Every other method, including any a later GoBGP adds, is
// refused, and a test fails on a method this list and deniedMethods (in the
// test) don't classify.
var readOnlyMethods = map[string]bool{
	"GetBgp": true, "GetTable": true, "WatchEvent": true,
	"ListPeer": true, "ListPeerGroup": true, "ListDynamicNeighbor": true,
	"ListPath": true, "ListVrf": true, "ListPolicy": true, "ListDefinedSet": true,
	"ListStatement": true, "ListPolicyAssignment": true, "ListRpki": true,
	"ListRpkiTable": true, "ListBmp": true, "ListTcpAoKeychain": true,
}

// socketReadyTimeout bounds how long a new server's API takes to listen.
const socketReadyTimeout = 5 * time.Second

// apiSocketPath returns the GoBGP API socket path for the runtime of key in
// dir, or "" when dir is empty. The file is named <namespace>_<name>.sock,
// which cannot collide because Kubernetes names never contain an underscore.
// A name too long for a socket address falls back to a hash of the key.
func apiSocketPath(dir string, key types.NamespacedName) string {
	if dir == "" {
		return ""
	}
	name := key.Name
	if key.Namespace != "" {
		name = key.Namespace + "_" + key.Name
	}
	p := filepath.Join(dir, name+".sock")
	if len(p) > maxSocketPath {
		sum := sha256.Sum256([]byte(key.String()))
		p = filepath.Join(dir, hex.EncodeToString(sum[:8])+".sock")
	}
	return p
}

// apiServerOptions returns the options that serve the GoBGP API read-only on
// the unix socket at socket. It removes a socket file a previous server left
// behind, since a listener that exits without closing, as on a crash, leaves
// its file and the next listen on that path fails. It returns nil, serving no
// API, when the socket cannot be bound: GoBGP's own listen failure only
// reaches its logger, which this package discards.
func apiServerOptions(socket string) []gobgpserver.ServerOption {
	if err := os.Remove(socket); err != nil && !errors.Is(err, fs.ErrNotExist) {
		slog.Warn("gobgp api: remove stale socket", "socket", socket, "err", err)
		return nil
	}
	lis, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", socket)
	if err != nil {
		slog.Warn("gobgp api: socket not served", "socket", socket, "err", err)
		return nil
	}
	// Closing a unix listener created this way removes its socket file.
	_ = lis.Close()
	return []gobgpserver.ServerOption{
		gobgpserver.GrpcListenAddress("unix://" + socket),
		gobgpserver.GrpcOption([]grpc.ServerOption{
			grpc.UnaryInterceptor(readOnlyUnary),
			grpc.StreamInterceptor(readOnlyStream),
		}),
	}
}

// waitForAPISocket waits until the API on socket accepts a connection. GoBGP
// listens in its own goroutine, which Stop does not wait for: a server stopped
// before it listened would bind the path afterwards, taking it from the
// replacement server or unlinking its socket on exit. Waiting here means a
// server is always listening before anything can stop it. A socket that never
// comes up is logged, since GoBGP's own listen error reaches only its
// discarded logger.
func waitForAPISocket(socket string) {
	ctx, cancel := context.WithTimeout(context.Background(), socketReadyTimeout)
	defer cancel()
	var d net.Dialer
	for {
		conn, err := d.DialContext(ctx, "unix", socket)
		if err == nil {
			_ = conn.Close()
			return
		}
		select {
		case <-ctx.Done():
			slog.Warn("gobgp api: socket not served", "socket", socket, "err", err)
			return
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// readOnlyMethod reports whether fullMethod, a gRPC method path such as
// /api.GoBgpService/ListPeer, only reads state.
func readOnlyMethod(fullMethod string) bool {
	return readOnlyMethods[path.Base(fullMethod)]
}

func errReadOnly(fullMethod string) error {
	return status.Errorf(codes.PermissionDenied, "%s: galactic-router serves the GoBGP API read-only", fullMethod)
}

func readOnlyUnary(
	ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler,
) (any, error) {
	if !readOnlyMethod(info.FullMethod) {
		return nil, errReadOnly(info.FullMethod)
	}
	return handler(ctx, req)
}

func readOnlyStream(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	if !readOnlyMethod(info.FullMethod) {
		return errReadOnly(info.FullMethod)
	}
	return handler(srv, ss)
}
