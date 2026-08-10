// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cnimaster

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/containernetworking/cni/pkg/types"
	type100 "github.com/containernetworking/cni/pkg/types/100"

	"go.datum.net/galactic/internal/cniipam"
	"go.datum.net/galactic/internal/config"
	"go.datum.net/galactic/internal/hostconf"
)

// PluginConf is the CNI plugin configuration passed via stdin on each
// invocation of either master plugin (galactic-cni or galactic-tap-cni).
//
// IPAM addressing fields (ipv6_subnet, ipv4_subnet, address_families,
// static_ip) live entirely inside the "ipam" block — see
// go.datum.net/galactic/internal/cniipam's doc comment for the explicit
// delegation contract: this struct only decides *whether* to delegate
// (IPAM != nil), never anything about how allocation itself works.
// Termination routes are galactic-route's own concern (see
// internal/cniroute) — neither master plugin's own JSON stanza carries a
// "terminations" field of its own to read.
type PluginConf struct {
	types.PluginConf
	VPC           string        `json:"vpc"`
	VPCAttachment string        `json:"vpcattachment"`
	MTU           int           `json:"mtu,omitempty"`
	IPAM          *cniipam.IPAM `json:"ipam"`
	Namespace     string        `json:"namespace,omitempty"`
}

const sanitizeForErrorBinary = "<binary>"

// errInvalidCNIConfig is the message for CNI config parse errors (code 7).
const errInvalidCNIConfig = "invalid CNI config"

// errVPCRequired and errVPCAttachmentRequired are messages for missing
// identifier fields (code 7).
const (
	errVPCRequired           = "vpc is required and must be a non-empty base62 string"
	errVPCAttachmentRequired = "vpcattachment is required and must be a non-empty base62 string"
)

// IsValidBase62 reports whether s contains only valid base62 characters
// ([0-9a-zA-Z]) and is non-empty. VPC and VPCAttachment identifiers are
// base62-encoded and used throughout the ADD path (interface naming,
// BGP CRD population). Rejecting them early in ParseConf prevents cryptic
// errors deep in the stack after partial kernel state has been created.
func IsValidBase62(s string) bool {
	if len(s) == 0 {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') {
			return false
		}
	}
	return true
}

// LoadHostConf loads node-local settings from the static per-node conflist.
// If the file is missing, it returns a zero-value HostConf (tolerating local
// test runs) but still defaulting Namespace to config.DefaultNamespace.
func LoadHostConf(filePath string) (*hostconf.HostConf, error) {
	if filePath == "" {
		filePath = config.DefaultConfFile
	}
	conf, err := hostconf.Load(filePath, hostconf.PluginType)
	if err != nil {
		if os.IsNotExist(UnwrapPathError(err)) {
			return &hostconf.HostConf{Namespace: config.DefaultNamespace}, nil
		}
		return nil, err
	}
	if conf.Namespace == "" {
		conf.Namespace = config.DefaultNamespace
	}
	return conf, nil
}

// UnwrapPathError returns the innermost *os.PathError-shaped error wrapped
// by err, if any, so os.IsNotExist (which does not itself traverse %w
// wrapping) can still recognize a missing conflist file wrapped by
// hostconf.Load's fmt.Errorf("read conflist file %q: %w", ...).
func UnwrapPathError(err error) error {
	for {
		unwrapped := errors.Unwrap(err)
		if unwrapped == nil {
			return err
		}
		err = unwrapped
	}
}

// ParseLogLevel maps a config-supplied level name to a slog.Level. Matching
// is case-insensitive. An empty string resolves to config.DefaultLogLevel.
// Unrecognized values return an error alongside the info-level fallback, so
// callers can warn without failing the CNI operation over a typo'd setting.
func ParseLogLevel(s string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "":
		return ParseLogLevel(config.DefaultLogLevel)
	case config.LogLevelDebug:
		return slog.LevelDebug, nil
	case config.DefaultLogLevel:
		return slog.LevelInfo, nil
	case config.LogLevelWarn, config.LogLevelWarning:
		return slog.LevelWarn, nil
	case config.LogLevelError:
		return slog.LevelError, nil
	default:
		return slog.LevelInfo, fmt.Errorf("unknown log level %q (want %s, %s, %s, or %s)",
			s, config.LogLevelDebug, config.DefaultLogLevel, config.LogLevelWarn, config.LogLevelError)
	}
}

// SetupLogging configures the slog default logger to write to the specified
// path at the specified verbosity. If opening the file fails, it logs a
// warning to os.Stderr and falls back. An unrecognized logLevel also logs a
// warning and falls back to config.DefaultLogLevel rather than failing the
// operation.
func SetupLogging(logPath, logLevel string) {
	if logPath == "" {
		logPath = config.DefaultLogFile
	}
	level, err := ParseLogLevel(logLevel)
	if err != nil {
		slog.Warn("Invalid log level, falling back to default",
			"value", logLevel, "default", config.DefaultLogLevel, "err", err)
	}
	// Ensure parent directory exists.
	if err := os.MkdirAll(filepath.Dir(logPath), 0755); err != nil {
		slog.Warn("Failed to create log directory", "path", filepath.Dir(logPath), "err", err)
		return
	}
	file, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		slog.Warn("Failed to open log file, falling back to Stderr", "path", logPath, "err", err)
		return
	}
	// Use JSON handler for structured logging to file.
	handler := slog.NewJSONHandler(file, &slog.HandlerOptions{Level: level})
	slog.SetDefault(slog.New(handler))
}

// statusConf holds the minimal CNI config fields needed for STATUS validation.
//
// STATUS only checks that the config is parseable and the API server is
// reachable; it does not validate attachment-specific fields (VPC,
// VPCAttachment) because STATUS must succeed before any ADD has ever run.
type statusConf struct {
	CNIVersion string `json:"cniVersion"`
	Type       string `json:"type"`
}

// ParseStatusConf validates that the CNI config is parseable and contains
// the required top-level fields (cniVersion, type). Unlike ParseConf, it
// does not validate VPC or VPCAttachment because STATUS must succeed on a
// freshly started node before any ADD has run.
func ParseStatusConf(data []byte) error {
	var sc statusConf
	if err := json.Unmarshal(data, &sc); err != nil {
		return &types.Error{Code: 7, Msg: errInvalidCNIConfig, Details: err.Error()}
	}
	if sc.CNIVersion == "" {
		return &types.Error{Code: 7, Msg: "cniVersion is required"}
	}
	if sc.Type == "" {
		return &types.Error{Code: 7, Msg: "type is required"}
	}
	return nil
}

// ValidatePrevResult checks that the prevResult (from a preceding plugin in
// the CNI chain) is a valid, parseable CNI result. Returns an error if the
// result is non-nil but cannot be parsed as a versioned CNI result, ensuring
// the master plugin fails fast rather than silently operating on garbage
// state.
func ValidatePrevResult(res types.Result) error {
	if res == nil {
		return nil
	}
	// Marshal to JSON and re-parse to verify the result is structurally valid.
	// This catches malformed results that survived CNI framework unmarshaling.
	jsonBytes, err := json.Marshal(res)
	if err != nil {
		return fmt.Errorf("marshal prevResult: %w", err)
	}
	if _, err := type100.NewResult(jsonBytes); err != nil {
		return fmt.Errorf("parse prevResult: %w", err)
	}
	return nil
}

// ValidatePrevResultAdd performs content-level validation of prevResult
// during the ADD operation. It ensures the preceding plugin produced a
// result with at least one interface or IP assignment, which is the minimum
// expected structure for any meaningful CNI chain. Returns nil when
// prevResult is nil (no preceding plugin) or structurally valid with
// expected content.
func ValidatePrevResultAdd(res types.Result) error {
	if res == nil {
		return nil
	}
	jsonBytes, err := json.Marshal(res)
	if err != nil {
		return fmt.Errorf("marshal prevResult: %w", err)
	}
	result, err := type100.NewResult(jsonBytes)
	if err != nil {
		return fmt.Errorf("parse prevResult: %w", err)
	}
	versioned, err := type100.GetResult(result)
	if err != nil {
		return fmt.Errorf("get prevResult version: %w", err)
	}
	// A valid prevResult must declare at least one interface or IP assignment.
	if len(versioned.Interfaces) == 0 && len(versioned.IPs) == 0 {
		return errors.New("prevResult declares no interfaces or IP assignments")
	}
	return nil
}

// ParseConf unmarshals the CNI configuration from stdin data and validates
// the base62-encoded identifier fields. It resolves the host configuration
// and sets up process environment variables and logging.
//
// cniConfig is the caller's own *config.CNIConfig singleton (each master
// plugin binary owns one, initialized once via its own InitCNIConfig() at
// process startup) and confFile is the caller's own ConfFile package var —
// both are caller state, not shared, since each binary resolves its own
// GALACTIC_CNI_* environment independently.
func ParseConf(data []byte, cniConfig *config.CNIConfig, confFile string) (*PluginConf, error) {
	conf := &PluginConf{}
	if err := json.Unmarshal(data, &conf); err != nil {
		return nil, &types.Error{Code: 7, Msg: errInvalidCNIConfig, Details: err.Error()}
	}
	if !IsValidBase62(conf.VPC) {
		if len(conf.VPC) == 0 {
			return nil, &types.Error{Code: 7, Msg: errVPCRequired}
		}
		return nil, &types.Error{
			Code: 7,
			Msg:  fmt.Sprintf("invalid base62 value for field 'vpc': %q", SanitizeForError(conf.VPC)),
		}
	}
	if !IsValidBase62(conf.VPCAttachment) {
		if len(conf.VPCAttachment) == 0 {
			return nil, &types.Error{Code: 7, Msg: errVPCAttachmentRequired}
		}
		return nil, &types.Error{
			Code: 7,
			Msg:  fmt.Sprintf("invalid base62 value for field 'vpcattachment': %q", SanitizeForError(conf.VPCAttachment)),
		}
	}

	// Load host CNI config
	hostConf, err := LoadHostConf(confFile)
	if err != nil {
		return nil, fmt.Errorf("load host CNI config: %w", err)
	}

	// Resolve config: env var > conflist > default.
	cniConfig.Resolve(&config.ConflistValues{
		NodeName:   hostConf.NodeName,
		Kubeconfig: hostConf.Kubeconfig,
		Namespace:  hostConf.Namespace,
		LogFile:    hostConf.LogFile,
		LogLevel:   hostConf.LogLevel,
	})

	// NodeName fallback: auto-detect from the Kubernetes API by matching local
	// interface addresses against node InternalIPs. This handles cases where
	// the conflist file is missing (e.g. hostPath mount issues in container-
	// based environments like Kind).
	if cniConfig.NodeName == "" {
		detected, detectErr := hostconf.DetectNodeNameFromAPI()
		if detectErr != nil {
			slog.Warn("Node name auto-detection failed", "err", detectErr)
		}
		cniConfig.NodeName = detected
	}
	if cniConfig.NodeName == "" {
		return nil, &types.Error{Code: 4, Msg: "node name is required (or set GALACTIC_CNI_NODE_NAME)"}
	}
	_ = os.Setenv("NODE_NAME", cniConfig.NodeName)

	// Propagate Kubeconfig
	_ = os.Setenv("KUBECONFIG", cniConfig.Kubeconfig)

	// Resolve and propagate Namespace fallback
	namespace := conf.Namespace
	if namespace == "" {
		namespace = cniConfig.Namespace
	}
	conf.Namespace = namespace

	// Setup Logging
	SetupLogging(cniConfig.LogFile, cniConfig.LogLevel)
	slog.Debug("CNI config received", "stdin", string(data))

	// Refuse a config still written against the old flat addressing shape
	// before anything else happens — those keys would otherwise be dropped
	// as unknown fields and the pod would attach with no addresses at all.
	if err := hostconf.RejectMovedIPAMKeys(data); err != nil {
		return nil, err
	}

	// Whether IPAM runs at all is decided entirely by whether "ipam" is
	// present — no environment variable or sibling field can trigger or
	// suppress that. Addressing fields (ipv6_subnet, ipv4_subnet,
	// address_families, static_ip) and their own default-filling/CIDR
	// validation live inside internal/cniipam, since they're only ever
	// read by whichever binary "ipam.type" names — the master plugin passes
	// its own StdinData straight through unmodified when it delegates, so
	// validating them here too would just be redundant work on the same
	// bytes. Their *placement* is this plugin's concern, though — see the
	// RejectMovedIPAMKeys call above.

	if conf.PrevResult != nil {
		if err := ValidatePrevResult(conf.PrevResult); err != nil {
			return nil, &types.Error{Code: 6, Msg: fmt.Sprintf("invalid prevResult: %v", err)}
		}
	}
	return conf, nil
}

// SanitizeForError returns s unchanged if it contains only printable ASCII
// characters; otherwise returns "<binary>" to avoid corrupting log output.
func SanitizeForError(s string) string {
	for _, c := range s {
		if c < 0x20 || c > 0x7e {
			return sanitizeForErrorBinary
		}
	}
	return s
}
