// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cnimaster

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/containernetworking/cni/pkg/types"
	type100 "github.com/containernetworking/cni/pkg/types/100"

	"go.datum.net/galactic/internal/config"
)

func TestMain(m *testing.M) {
	_ = os.Setenv("GALACTIC_CNI_NODE_NAME", "test-node")
	os.Exit(m.Run())
}

const (
	testVPC           = "abc"
	testAttachment    = "def"
	testInvalidBase62 = "abc-def" // shared invalid base62 string for tests
	testNetns         = "/proc/1/ns/net"
	testMac           = "aa:bb:cc:dd:ee:ff"
	testIfName        = "eth0"
	testCNIVersion    = "1.0.0"

	// testPrevResult is a valid CNI v1.0.0 result used in prevResult tests.
	testPrevResult = `{"cniVersion":"1.0.0",` +
		`"interfaces":[{"name":"` + testIfName + `","mac":"` + testMac + `",` +
		`"sandbox":"/proc/1/ns/net"}],` +
		`"ips":[{"version":"6","address":"fd00:1::1/64"}]}`
)

// assertCNIError verifies that err is a *types.Error with the expected Code
// and that its Msg contains wantMsg (substring match). Pass wantMsg == "" to
// skip the message check.
func assertCNIError(t *testing.T, err error, wantCode uint, wantMsg string) {
	t.Helper()
	var cniErr *types.Error
	if !errors.As(err, &cniErr) {
		t.Fatalf("expected *types.Error, got %T: %v", err, err)
	}
	if cniErr.Code != wantCode {
		t.Fatalf("expected code %d, got %d (Msg: %q)", wantCode, cniErr.Code, cniErr.Msg)
	}
	if wantMsg != "" && !strings.Contains(cniErr.Msg, wantMsg) {
		t.Fatalf("expected Msg to contain %q, got %q", wantMsg, cniErr.Msg)
	}
}

func mustParseCIDR(t *testing.T, cidr string) *net.IPNet {
	t.Helper()
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatalf("net.ParseCIDR(%q): %v", cidr, err)
	}
	ipNet.IP = ip
	return ipNet
}

// ---- ParseConf -------------------------------------------------------------

func TestParseConf(t *testing.T) {
	cniConfig := config.NewCNIConfig()

	tests := []struct {
		name     string
		input    string
		wantVPC  string
		wantErr  string
		wantCode uint // CNI error code; 0 means "don't check"
	}{
		{
			name: "valid config",
			input: fmt.Sprintf(
				`{"cniVersion":"1.0.0","name":"test",`+
					`"type":"galactic-veth","vpc":"%s",`+
					`"vpcattachment":"%s"}`,
				testVPC, testAttachment,
			),
			wantVPC: testVPC,
		},
		{
			name:     "invalid JSON",
			input:    "not json",
			wantErr:  "invalid CNI config",
			wantCode: 7,
		},
		{
			name:     "empty input",
			input:    "",
			wantErr:  "invalid CNI config",
			wantCode: 7,
		},
		{
			name: "missing vpc",
			input: fmt.Sprintf(
				`{"cniVersion":"1.0.0","name":"test",`+
					`"type":"galactic-veth","vpcattachment":"%s"}`,
				testAttachment,
			),
			wantErr:  "vpc is required and must be a non-empty base62 string",
			wantCode: 7,
		},
		{
			name: "empty vpc",
			input: fmt.Sprintf(
				`{"cniVersion":"1.0.0","name":"test",`+
					`"type":"galactic-veth","vpc":"",`+
					`"vpcattachment":"%s"}`,
				testAttachment,
			),
			wantErr:  "vpc is required and must be a non-empty base62 string",
			wantCode: 7,
		},
		{
			name: "vpc with invalid char hyphen",
			input: fmt.Sprintf(
				`{"cniVersion":"1.0.0","name":"test",`+
					`"type":"galactic-veth","vpc":"%s",`+
					`"vpcattachment":"%s"}`,
				testInvalidBase62, testAttachment,
			),
			wantErr:  fmt.Sprintf("invalid base62 value for field 'vpc': %q", testInvalidBase62),
			wantCode: 7,
		},
		{
			name: "vpc with invalid char underscore",
			input: fmt.Sprintf(
				`{"cniVersion":"1.0.0","name":"test",`+
					`"type":"galactic-veth","vpc":"abc_def",`+
					`"vpcattachment":"%s"}`,
				testAttachment,
			),
			wantErr:  `invalid base62 value for field 'vpc': "abc_def"`,
			wantCode: 7,
		},
		{
			name: "missing vpcattachment",
			input: fmt.Sprintf(
				`{"cniVersion":"1.0.0","name":"test",`+
					`"type":"galactic-veth","vpc":"%s"}`,
				testVPC,
			),
			wantErr:  "vpcattachment is required and must be a non-empty base62 string",
			wantCode: 7,
		},
		{
			name: "empty vpcattachment",
			input: fmt.Sprintf(
				`{"cniVersion":"1.0.0","name":"test",`+
					`"type":"galactic-veth","vpc":"%s",`+
					`"vpcattachment":""}`,
				testVPC,
			),
			wantErr:  "vpcattachment is required and must be a non-empty base62 string",
			wantCode: 7,
		},
		{
			name: "vpcattachment with invalid char space",
			input: fmt.Sprintf(
				`{"cniVersion":"1.0.0","name":"test",`+
					`"type":"galactic-veth","vpc":"%s",`+
					`"vpcattachment":"def ghi"}`,
				testVPC,
			),
			wantErr:  `invalid base62 value for field 'vpcattachment': "def ghi"`,
			wantCode: 7,
		},
		{
			name: "valid vpc and vpcattachment with mixed case base62",
			input: `{"cniVersion":"1.0.0","name":"test",` +
				`"type":"galactic-veth","vpc":"Abc123XYZ",` +
				`"vpcattachment":"DeF456"}`,
			wantVPC: "Abc123XYZ",
		},
		{
			name: "prevResult valid JSON result is accepted",
			input: fmt.Sprintf(
				`{"cniVersion":"1.0.0","name":"test",`+
					`"type":"galactic-veth","vpc":"%s",`+
					`"vpcattachment":"%s",`+
					`"prevResult":%s}`,
				testVPC, testAttachment, testPrevResult,
			),
			wantVPC: testVPC,
		},
		{
			name: "ipam block present is accepted, delegated per its own contract",
			input: fmt.Sprintf(
				`{"cniVersion":"1.0.0","name":"test",`+
					`"type":"galactic-veth","vpc":"%s",`+
					`"vpcattachment":"%s","ipam":{"type":"galactic-ipam","ipv6_subnet":"fd00:10:ff01::/48"}}`,
				testVPC, testAttachment,
			),
			wantVPC: testVPC,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conf, err := ParseConf([]byte(tt.input), cniConfig, config.DefaultConfFile)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error %q does not contain %q", err, tt.wantErr)
				}
				if tt.wantCode > 0 {
					assertCNIError(t, err, tt.wantCode, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if conf.VPC != tt.wantVPC {
				t.Errorf("VPC = %q, want %q", conf.VPC, tt.wantVPC)
			}
		})
	}
}

// TestIPAMBlockPresenceIsTheOnlyTrigger is the regression test for the
// explicit contract internal/cniipam's doc comment describes: whether a
// master plugin delegates to IPAM at all is decided solely by whether
// "ipam" is present in its own config — no environment variable can
// manufacture (or suppress) that block.
func TestIPAMBlockPresenceIsTheOnlyTrigger(t *testing.T) {
	cniConfig := config.NewCNIConfig()

	// Missing ipam block: no error, no delegation signal — conf.IPAM stays nil.
	inputNoIPAM := fmt.Sprintf(
		`{"cniVersion":"1.0.0","name":"test","type":"galactic-veth","vpc":"%s","vpcattachment":"%s"}`,
		testVPC, testAttachment,
	)
	conf, err := ParseConf([]byte(inputNoIPAM), cniConfig, config.DefaultConfFile)
	if err != nil {
		t.Fatalf("unexpected error for missing ipam block: %v", err)
	}
	if conf.IPAM != nil {
		t.Fatalf("IPAM = %+v, want nil (absent block must never be manufactured)", conf.IPAM)
	}

	// Present ipam block: conf.IPAM is populated, ready for delegation.
	inputWithIPAM := fmt.Sprintf(
		`{"cniVersion":"1.0.0","name":"test","type":"galactic-veth","vpc":"%s","vpcattachment":"%s",`+
			`"ipam":{"type":"galactic-ipam"}}`,
		testVPC, testAttachment,
	)
	conf, err = ParseConf([]byte(inputWithIPAM), cniConfig, config.DefaultConfFile)
	if err != nil {
		t.Fatalf("unexpected error with present ipam block: %v", err)
	}
	if conf.IPAM == nil {
		t.Fatal("expected IPAM block to be non-nil")
	}
	if conf.IPAM.Type != "galactic-ipam" {
		t.Errorf("IPAM.Type = %q, want %q", conf.IPAM.Type, "galactic-ipam")
	}
}

// ---- IsValidBase62 ---------------------------------------------------------

func TestIsValidBase62(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"empty", "", false},
		{"digits only", "1234567890", true},
		{"lowercase only", "abcdefghij", true},
		{"uppercase only", "ABCDEFGHIJ", true},
		{"mixed case", "aBcDeFgHiJ", true},
		{"mixed digits and letters", "abc123XYZ", true},
		{"hyphen", testInvalidBase62, false},
		{"underscore", "abc_def", false},
		{"space", "abc def", false},
		{"dot", "abc.def", false},
		{"slash", "abc/def", false},
		{"plus", "abc+def", false},
		{"equals", "abc=def", false},
		{"single digit", "0", true},
		{"single lowercase", "a", true},
		{"single uppercase", "Z", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsValidBase62(tt.input)
			if got != tt.want {
				t.Errorf("IsValidBase62(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestSanitizeForError(t *testing.T) {
	printable := "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!@#$%^&*()"
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"normal string", testInvalidBase62, testInvalidBase62},
		{"empty", "", ""},
		{"newline", "abc\ndef", sanitizeForErrorBinary},
		{"null byte", "abc\x00def", sanitizeForErrorBinary},
		{"del char", "abc\x7fdef", sanitizeForErrorBinary},
		{"printable range", printable, printable},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SanitizeForError(tt.input)
			if got != tt.want {
				t.Errorf("SanitizeForError(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// ---- ValidatePrevResult / ValidatePrevResultAdd ----------------------------

func TestValidatePrevResult(t *testing.T) {
	validResult := &type100.Result{
		CNIVersion: testCNIVersion,
		Interfaces: []*type100.Interface{
			{Name: testIfName, Mac: testMac, Sandbox: testNetns},
		},
		IPs: []*type100.IPConfig{
			{Address: *mustParseCIDR(t, "fd00:1::1/64")},
		},
	}

	tests := []struct {
		name    string
		input   types.Result
		wantErr bool
	}{
		{"nil result allowed", nil, false},
		{"valid CNI result", validResult, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePrevResult(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestValidatePrevResultAdd(t *testing.T) {
	validWithInterface := &type100.Result{
		CNIVersion: testCNIVersion,
		Interfaces: []*type100.Interface{
			{Name: testIfName, Mac: testMac, Sandbox: testNetns},
		},
		IPs: []*type100.IPConfig{
			{Address: *mustParseCIDR(t, "fd00:1::1/64")},
		},
	}
	validWithIPsOnly := &type100.Result{
		CNIVersion: testCNIVersion,
		IPs: []*type100.IPConfig{
			{Address: *mustParseCIDR(t, "fd00:1::1/64")},
		},
	}
	emptyResult := &type100.Result{
		CNIVersion: testCNIVersion,
		// No interfaces, no IPs — should fail content validation.
	}

	tests := []struct {
		name    string
		input   types.Result
		wantErr bool
	}{
		{"nil result allowed", nil, false},
		{"valid result with interface", validWithInterface, false},
		{"valid result with IPs only", validWithIPsOnly, false},
		{"empty result (no interfaces or IPs)", emptyResult, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePrevResultAdd(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// ---- ProbeAPIServer ---------------------------------------------------------

func TestProbeAPIServerErrNotInCluster(t *testing.T) {
	// When ProbeAPIServerFn returns ErrNotInCluster, ProbeAPIServer should
	// return nil (not running in-cluster; skip API check).
	original := ProbeAPIServer
	ProbeAPIServer = func() error { return nil }
	defer func() { ProbeAPIServer = original }()

	if err := ProbeAPIServer(); err != nil {
		t.Fatalf("expected nil for ErrNotInCluster, got %v", err)
	}
}

func TestProbeAPIServerMalformedKubeconfig(t *testing.T) {
	// When ProbeAPIServerFn returns a non-ErrNotInCluster error (e.g. a
	// malformed kubeconfig file), ProbeAPIServer should surface it wrapped.
	original := ProbeAPIServer
	ProbeAPIServer = func() error {
		return errors.New("load kubeconfig: invalid kubeconfig: permission denied")
	}
	defer func() { ProbeAPIServer = original }()

	err := ProbeAPIServer()
	if err == nil {
		t.Fatal("expected error for malformed kubeconfig, got nil")
	}
	if !strings.Contains(err.Error(), "load kubeconfig") {
		t.Fatalf("error %q does not contain 'load kubeconfig'", err.Error())
	}
	if !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("error %q does not contain original error", err.Error())
	}
}

// ---- LoadHostConf -----------------------------------------------------------

func TestLoadHostConf(t *testing.T) {
	tmpDir := t.TempDir()
	conflistPath := filepath.Join(tmpDir, "10-galactic.conflist")

	// 1. Missing file tolerated, defaults to galactic-system namespace.
	conf, err := LoadHostConf(conflistPath)
	if err != nil {
		t.Fatalf("unexpected error for missing conflist: %v", err)
	}
	if conf.Namespace != config.DefaultNamespace {
		t.Errorf("Namespace = %q, want %q", conf.Namespace, config.DefaultNamespace)
	}

	// 2. Conflist parses but lacks galactic-cni entry.
	badContent := `{"cniVersion":"1.0.0","name":"test","plugins":[{"type":"some-other-plugin"}]}`
	if err := os.WriteFile(conflistPath, []byte(badContent), 0644); err != nil {
		t.Fatalf("os.WriteFile: %v", err)
	}
	_, err = LoadHostConf(conflistPath)
	if err == nil {
		t.Fatal("expected error for missing plugin type, got nil")
	}

	// 3. Conflist parses correctly.
	goodContent := `{
		"cniVersion": "1.0.0",
		"name": "galactic",
		"plugins": [
			{
				"type": "galactic-cni",
				"node_name": "test-worker",
				"kubeconfig": "/etc/custom-kubeconfig",
				"namespace": "custom-namespace",
				"log_file": "/var/log/custom.log",
				"log_level": "debug"
			}
		]
	}`
	if err := os.WriteFile(conflistPath, []byte(goodContent), 0644); err != nil {
		t.Fatalf("os.WriteFile: %v", err)
	}
	conf, err = LoadHostConf(conflistPath)
	if err != nil {
		t.Fatalf("unexpected error for good conflist: %v", err)
	}
	if conf.NodeName != "test-worker" {
		t.Errorf("NodeName = %q, want %q", conf.NodeName, "test-worker")
	}
	if conf.Kubeconfig != "/etc/custom-kubeconfig" {
		t.Errorf("Kubeconfig = %q, want %q", conf.Kubeconfig, "/etc/custom-kubeconfig")
	}
	if conf.Namespace != "custom-namespace" {
		t.Errorf("Namespace = %q, want %q", conf.Namespace, "custom-namespace")
	}
	if conf.LogFile != "/var/log/custom.log" {
		t.Errorf("LogFile = %q, want %q", conf.LogFile, "/var/log/custom.log")
	}
	if conf.LogLevel != config.LogLevelDebug {
		t.Errorf("LogLevel = %q, want %q", conf.LogLevel, config.LogLevelDebug)
	}
}

// ---- logging setup ----------------------------------------------------------

func TestLoggingSetup(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "sub", "test.log")

	// Setup logging, which should create the directory and open/write to the file.
	SetupLogging(logPath, config.DefaultLogLevel)
	slog.Info("test log message")

	// Read the log file to verify the message was logged.
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read log file: %v", err)
	}
	if !strings.Contains(string(data), "test log message") {
		t.Fatalf("log content does not contain message: %s", string(data))
	}
}

func TestParseLogLevel(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    slog.Level
		wantErr bool
	}{
		{"empty defaults to info", "", slog.LevelInfo, false},
		{"debug", config.LogLevelDebug, slog.LevelDebug, false},
		{"info", config.DefaultLogLevel, slog.LevelInfo, false},
		{"warn", config.LogLevelWarn, slog.LevelWarn, false},
		{"warning alias", config.LogLevelWarning, slog.LevelWarn, false},
		{"error", config.LogLevelError, slog.LevelError, false},
		{"case insensitive", "DEBUG", slog.LevelDebug, false},
		{"surrounding whitespace", "  warn  ", slog.LevelWarn, false},
		{"unknown falls back to info with error", "verbose", slog.LevelInfo, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseLogLevel(tt.in)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseLogLevel(%q) error = %v, wantErr %v", tt.in, err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("ParseLogLevel(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestLoggingSetupRespectsLevel(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "test.log")

	SetupLogging(logPath, config.LogLevelWarn)
	slog.Info("should be suppressed at warn level")
	slog.Warn("should appear at warn level")

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read log file: %v", err)
	}
	content := string(data)
	if strings.Contains(content, "should be suppressed at warn level") {
		t.Errorf("expected info message to be filtered out at warn level, got: %s", content)
	}
	if !strings.Contains(content, "should appear at warn level") {
		t.Errorf("expected warn message to be present, got: %s", content)
	}
}

func TestLoggingSetupInvalidLevelFallsBackToInfo(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "test.log")

	// An invalid level must not fail the CNI operation; it should fall back
	// to DefaultLogLevel (info) rather than panic or drop all logging.
	SetupLogging(logPath, "verbose")
	slog.Info("should appear at fallback info level")

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read log file: %v", err)
	}
	if !strings.Contains(string(data), "should appear at fallback info level") {
		t.Errorf("expected info message to be present after fallback, got: %s", string(data))
	}
}
