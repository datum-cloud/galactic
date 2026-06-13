// Package gobgp manages the lifecycle of an embedded GoBGP server.
package gobgp

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"time"

	gobgpserver "github.com/osrg/gobgp/v4/pkg/server"
)

// Config holds configuration for the embedded GoBGP server.
type Config struct {
	// APIPort is the port the GoBGP gRPC API listens on. Cosmos dials this port.
	APIPort int
	// LogLevel controls GoBGP's internal log verbosity.
	// Valid values: debug, info, warn, error, panic. Defaults to panic.
	LogLevel string
}

// Server wraps an embedded GoBGP BgpServer.
type Server struct {
	cfg Config
	bgp *gobgpserver.BgpServer
}

// New creates a Server with the given config. Call Start to run it.
func New(cfg Config) *Server {
	if cfg.APIPort == 0 {
		cfg.APIPort = 50051
	}
	if cfg.LogLevel == "" {
		cfg.LogLevel = "panic"
	}
	return &Server{cfg: cfg}
}

// Addr returns the gRPC API address the server listens on.
func (s *Server) Addr() string {
	return fmt.Sprintf("localhost:%d", s.cfg.APIPort)
}

// Start runs the embedded GoBGP server until ctx is cancelled.
// It blocks until the server has stopped.
func (s *Server) Start(ctx context.Context) error {
	level := parseLogLevel(s.cfg.LogLevel)
	levelVar := &slog.LevelVar{}
	levelVar.Set(level)
	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: levelVar}))

	s.bgp = gobgpserver.NewBgpServer(
		gobgpserver.GrpcListenAddress(s.Addr()),
		gobgpserver.LoggerOption(logger, levelVar),
	)

	go s.bgp.Serve()

	<-ctx.Done()
	s.bgp.Stop()
	return nil
}

// WaitReady blocks until the GoBGP gRPC API port accepts TCP connections or
// ctx is cancelled. Returns an error if ctx is cancelled before the port is ready.
func (s *Server) WaitReady(ctx context.Context) error {
	addr := s.Addr()
	for {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("gobgp not ready at %s: %w", addr, ctx.Err())
		case <-time.After(50 * time.Millisecond):
		}
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
