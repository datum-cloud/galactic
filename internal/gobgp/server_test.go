package gobgp

import (
	"testing"
)

func TestNew_Defaults(t *testing.T) {
	s := New(Config{})
	if s.cfg.APIPort != 50051 {
		t.Errorf("default APIPort = %d, want 50051", s.cfg.APIPort)
	}
	if s.cfg.LogLevel != defaultLogLevel {
		t.Errorf("default LogLevel = %q, want %q", s.cfg.LogLevel, defaultLogLevel)
	}
}

func TestAddr(t *testing.T) {
	s := New(Config{APIPort: 12345})
	if got := s.Addr(); got != "localhost:12345" {
		t.Errorf("Addr() = %q, want localhost:12345", got)
	}
}

func TestParseLogLevel(t *testing.T) {
	cases := []struct {
		input string
	}{
		{"debug"},
		{"info"},
		{"warn"},
		{"error"},
		{defaultLogLevel},
		{""},
		{"unknown"},
	}
	for _, tc := range cases {
		_ = parseLogLevel(tc.input)
	}
}
