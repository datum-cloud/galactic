// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package gobgp manages the lifecycle of an embedded GoBGP server and
// implements runtime.RouterRuntime using that server.
package gobgp

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"sync/atomic"

	gobgpserver "github.com/osrg/gobgp/v4/pkg/server"
)

const defaultLogLevel = "panic"

// Config holds configuration for the embedded GoBGP server.
type Config struct {
	// LogLevel controls GoBGP's internal log verbosity.
	// Valid values: debug, info, warn, error, panic. Defaults to panic.
	LogLevel string
}

// Server wraps an embedded GoBGP BgpServer.
type Server struct {
	cfg   Config
	bgp   atomic.Pointer[gobgpserver.BgpServer]
	ready chan struct{}
}

// newServer creates a Server with the given config. Call Start to run it.
func newServer(cfg Config) *Server {
	if cfg.LogLevel == "" {
		cfg.LogLevel = defaultLogLevel
	}
	return &Server{
		cfg:   cfg,
		ready: make(chan struct{}),
	}
}

// Start runs the embedded GoBGP server until ctx is cancelled.
// It blocks until the server has stopped.
func (s *Server) Start(ctx context.Context) error {
	b := s.newBgpServer()
	s.bgp.Store(b)
	close(s.ready)

	go b.Serve()

	<-ctx.Done()
	if current := s.bgp.Load(); current != nil {
		current.Stop()
	}
	return nil
}

// Reconfigure replaces the running BgpServer with a fresh instance.
// StopBgp in GoBGP v4 terminates the Serve loop, making the server permanently
// dead. Call this instead of StopBgp+StartBgp when reconfiguration is needed.
// The caller must call StartBgp on the returned server.
func (s *Server) Reconfigure() (*gobgpserver.BgpServer, error) {
	if old := s.bgp.Load(); old != nil {
		old.Stop()
	}
	b := s.newBgpServer()
	s.bgp.Store(b)
	go b.Serve()
	return b, nil
}

func (s *Server) newBgpServer() *gobgpserver.BgpServer {
	level := parseLogLevel(s.cfg.LogLevel)
	levelVar := &slog.LevelVar{}
	levelVar.Set(level)
	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: levelVar}))
	return gobgpserver.NewBgpServer(gobgpserver.LoggerOption(logger, levelVar))
}

// WaitReady blocks until the GoBGP server is initialized or ctx is cancelled.
func (s *Server) WaitReady(ctx context.Context) error {
	select {
	case <-s.ready:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("gobgp not ready: %w", ctx.Err())
	}
}

func parseLogLevel(level string) slog.Level {
	switch level {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelError + 4 // above error — effectively silent
	}
}
