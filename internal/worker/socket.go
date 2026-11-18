// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package worker

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"google.golang.org/grpc"

	"go.datum.net/galactic/internal/worker/auth"
)

// Listen opens Worker's unix socket at path with mode 0660, owned by gid
// when gid is not negative. A stale socket from an earlier process is
// replaced. No TCP listener serves the mutating API.
func Listen(ctx context.Context, path string, gid int) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, fmt.Errorf("worker: socket directory: %w", err)
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("worker: remove stale socket: %w", err)
	}
	lis, err := (&net.ListenConfig{}).Listen(ctx, "unix", path)
	if err != nil {
		return nil, fmt.Errorf("worker: listen on %s: %w", path, err)
	}
	if err := os.Chmod(path, 0o660); err != nil {
		_ = lis.Close()
		return nil, fmt.Errorf("worker: chmod socket: %w", err)
	}
	if gid >= 0 {
		if err := os.Chown(path, -1, gid); err != nil {
			_ = lis.Close()
			return nil, fmt.Errorf("worker: chown socket: %w", err)
		}
	}
	return lis, nil
}

// NewServer returns a gRPC server whose connections carry the peer's
// SO_PEERCRED, with the Worker service registered.
func (w *Worker) NewServer(opts ...grpc.ServerOption) *grpc.Server {
	s := grpc.NewServer(append([]grpc.ServerOption{grpc.Creds(auth.PeerCredentials{})}, opts...)...)
	w.Register(s)
	return s
}
