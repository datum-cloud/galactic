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

// PluginConf is the CNI plugin configuration passed on stdin to either master
// plugin.
//
// Addressing fields live entirely inside the "ipam" block; this struct decides
// only whether to delegate, never anything about how allocation works.
// Termination routes are the routing plugin's concern, so neither master
// plugin's stanza carries a field for them.
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

// IsValidBase62 reports whether s is non-empty and contains only base62
// characters. VPC and attachment identifiers are base62 and used throughout the
// ADD path for interface naming and CRD population, so rejecting them early
// avoids cryptic errors deep in the stack after partial kernel state exists.
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

// LoadHostConf loads node-local settings from the static per-node conflist. A
// missing file yields a zero-value HostConf, tolerating local test runs, with
// Namespace still defaulted.
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

// UnwrapPathError returns the innermost path error wrapped by err, if any, so a
// missing-file check can recognise a missing conflist through the wrapping the
// loader adds.
func UnwrapPathError(err error) error {
	for {
		unwrapped := errors.Unwrap(err)
		if unwrapped == nil {
			return err
		}
		err = unwrapped
	}
}

// ParseLogLevel maps a config-supplied level name to a slog level,
// case-insensitively. An empty string resolves to the default. An unrecognised
// value returns an error alongside the info-level fallback, so callers can warn
// without failing the CNI operation over a typo.
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

// SetupLogging points the default logger at logPath with verbosity logLevel. A
// failure to open the file, or an unrecognised level, logs a warning to stderr
// and falls back rather than failing the operation.
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

// statusConf holds the minimal config fields STATUS validation needs. STATUS
// only checks that the config parses and the API server is reachable, not
// attachment-specific fields, since it must succeed before any ADD has run.
type statusConf struct {
	CNIVersion string `json:"cniVersion"`
	Type       string `json:"type"`
}

// ParseStatusConf validates that the CNI config parses and carries the required
// top-level fields. Unlike ParseConf it does not validate the attachment
// identifiers, since STATUS must succeed on a freshly started node.
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

// ValidatePrevResult checks that a preceding plugin's result is a parseable,
// versioned CNI result. A non-nil result that cannot be parsed is an error, so
// the master plugin fails fast rather than operating on garbage.
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

// ValidatePrevResultAdd checks a preceding plugin's result during ADD for at
// least one interface or IP assignment, the minimum for a meaningful chain. A
// nil result, meaning no preceding plugin, is fine.
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

// ParseConf unmarshals the CNI configuration from data, validates the
// base62 identifier fields, resolves the host configuration, and sets up
// process environment and logging.
//
// cniConfig and confFile are the caller's own state, one per master plugin
// binary, since each resolves its own environment independently. confFile names
// the conflist for error reporting.
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
		DANDir:     hostConf.DANDir,
	})

	// Fall back to auto-detecting the node name from the API by matching local
	// interface addresses against node addresses, for when the conflist is
	// missing.
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

	// Refuse a config written against the old flat addressing shape before
	// anything else: those keys would be dropped as unknown fields and the pod
	// would attach with no addresses at all.
	if err := hostconf.RejectMovedIPAMKeys(data); err != nil {
		return nil, err
	}

	// Whether IPAM runs at all is decided entirely by whether "ipam" is
	// present; no environment variable or sibling field can trigger or suppress
	// it. The addressing fields and their own validation live in the IPAM
	// package, since only the binary named by "ipam.type" reads them and the
	// master plugin passes its stdin through unmodified when it delegates.
	// Their placement is this plugin's concern, which the check above
	// enforces.

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
