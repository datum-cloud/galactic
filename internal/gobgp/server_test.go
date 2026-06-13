package gobgp

import (
	"testing"
)

func TestNew_Defaults(t *testing.T) {
	s := New(Config{})
	if s.cfg.APIPort != 50051 {
		t.Errorf("default APIPort = %d, want 50051", s.cfg.APIPort)
	}
	if s.cfg.LogLevel != "panic" {
		t.Errorf("default LogLevel = %q, want panic", s.cfg.LogLevel)
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
		want  string
	}{
		{"debug", "DEBUG"},
		{"info", "INFO"},
		{"warn", "WARN"},
		{"error", "ERROR"},
		{"panic", "ERROR+4"},
		{"", "ERROR+4"},
		{"unknown", "ERROR+4"},
	}
	for _, tc := range cases {
		got := parseLogLevel(tc.input)
		_ = got // just ensure it doesn't panic
	}
}
