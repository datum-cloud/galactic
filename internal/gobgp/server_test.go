package gobgp

import (
	"context"
	"testing"
	"time"
)

func TestNew_Defaults(t *testing.T) {
	s := New(Config{})
	if s.cfg.LogLevel != defaultLogLevel {
		t.Errorf("default LogLevel = %q, want %q", s.cfg.LogLevel, defaultLogLevel)
	}
}

func TestWaitReady(t *testing.T) {
	s := New(Config{})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go func() {
		startCtx, startCancel := context.WithCancel(context.Background())
		defer startCancel()
		_ = s.Start(startCtx)
	}()

	if err := s.WaitReady(ctx); err != nil {
		t.Errorf("WaitReady returned error: %v", err)
	}
}

func TestWaitReady_Cancelled(t *testing.T) {
	s := New(Config{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled

	err := s.WaitReady(ctx)
	if err == nil {
		t.Error("expected error for cancelled context, got nil")
	}
}

func TestParseLogLevel(t *testing.T) {
	cases := []string{"debug", "info", "warn", "error", defaultLogLevel, "", "unknown"}
	for _, tc := range cases {
		_ = parseLogLevel(tc)
	}
}
