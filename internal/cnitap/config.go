// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cnitap

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

	"go.datum.net/galactic/internal/cni/hostconf"
	"go.datum.net/galactic/internal/config"
)

var ConfFile = config.DefaultConfFile

// cniConfig is the shared config resolver for env var resolution.
// Initialized by InitCNIConfig() (called from cmd/galactic-tap-cni/main.go).
var cniConfig *config.CNIConfig

// InitCNIConfig initializes the shared config resolver for CNI env var
// resolution. Callers should invoke this once at process startup before any
// config lookups.
func InitCNIConfig() {
	cniConfig = config.NewCNIConfig()
}

const sanitizeForErrorBinary = "<binary>"

const errInvalidCNIConfig = "invalid CNI config"

const (
	errVPCRequired           = "vpc is required and must be a non-empty base62 string"
	errVPCAttachmentRequired = "vpcattachment is required and must be a non-empty base62 string"
)

// isValidBase62 reports whether s contains only valid base62 characters
// ([0-9a-zA-Z]) and is non-empty.
func isValidBase62(s string) bool {
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

// loadHostConf loads node-local settings from the static per-node conflist.
// If the file is missing, it returns a zero-value HostConf (tolerating local
// test runs) but still defaulting Namespace to config.DefaultNamespace.
func loadHostConf(filePath string) (*HostConf, error) {
	if filePath == "" {
		filePath = config.DefaultConfFile
	}
	conf, err := hostconf.Load(filePath, hostconf.PluginType)
	if err != nil {
		if os.IsNotExist(unwrapPathError(err)) {
			return &HostConf{Namespace: config.DefaultNamespace}, nil
		}
		return nil, err
	}
	if conf.Namespace == "" {
		conf.Namespace = config.DefaultNamespace
	}
	return conf, nil
}

// unwrapPathError returns the innermost error wrapped by err, so
// os.IsNotExist (which does not itself traverse %w wrapping) can still
// recognize a missing conflist file wrapped by hostconf.Load.
func unwrapPathError(err error) error {
	for {
		unwrapped := errors.Unwrap(err)
		if unwrapped == nil {
			return err
		}
		err = unwrapped
	}
}

// parseLogLevel maps a config-supplied level name to a slog.Level. Matching is
// case-insensitive. An empty string resolves to config.DefaultLogLevel.
// Unrecognized values return an error alongside the info-level fallback, so
// callers can warn without failing the CNI operation over a typo'd setting.
func parseLogLevel(s string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "":
		return parseLogLevel(config.DefaultLogLevel)
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

// setupLogging configures the slog default logger to write to the specified
// path at the specified verbosity. If opening the file fails, it logs a
// warning to os.Stderr and falls back. An unrecognized logLevel also logs a
// warning and falls back to config.DefaultLogLevel rather than failing the
// operation.
func setupLogging(logPath, logLevel string) {
	if logPath == "" {
		logPath = config.DefaultLogFile
	}
	level, err := parseLogLevel(logLevel)
	if err != nil {
		slog.Warn("Invalid log level, falling back to default",
			"value", logLevel, "default", config.DefaultLogLevel, "err", err)
	}
	if err := os.MkdirAll(filepath.Dir(logPath), 0755); err != nil {
		slog.Warn("Failed to create log directory", "path", filepath.Dir(logPath), "err", err)
		return
	}
	file, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		slog.Warn("Failed to open log file, falling back to Stderr", "path", logPath, "err", err)
		return
	}
	handler := slog.NewJSONHandler(file, &slog.HandlerOptions{Level: level})
	slog.SetDefault(slog.New(handler))
}

// statusConf holds the minimal CNI config fields needed for STATUS validation.
type statusConf struct {
	CNIVersion string `json:"cniVersion"`
	Type       string `json:"type"`
}

func parseStatusConf(data []byte) error {
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

func validatePrevResult(res types.Result) error {
	if res == nil {
		return nil
	}
	jsonBytes, err := json.Marshal(res)
	if err != nil {
		return fmt.Errorf("marshal prevResult: %w", err)
	}
	if _, err := type100.NewResult(jsonBytes); err != nil {
		return fmt.Errorf("parse prevResult: %w", err)
	}
	return nil
}

func validatePrevResultAdd(res types.Result) error {
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
	if len(versioned.Interfaces) == 0 && len(versioned.IPs) == 0 {
		return errors.New("prevResult declares no interfaces or IP assignments")
	}
	return nil
}

// parseConf unmarshals the CNI configuration from stdin data and validates
// the base62-encoded identifier fields. It resolves the host configuration
// and sets up process environment variables and logging.
func parseConf(data []byte) (*PluginConf, error) {
	conf := &PluginConf{}
	if err := json.Unmarshal(data, &conf); err != nil {
		return nil, &types.Error{Code: 7, Msg: errInvalidCNIConfig, Details: err.Error()}
	}
	if !isValidBase62(conf.VPC) {
		if len(conf.VPC) == 0 {
			return nil, &types.Error{Code: 7, Msg: errVPCRequired}
		}
		return nil, &types.Error{
			Code: 7,
			Msg:  fmt.Sprintf("invalid base62 value for field 'vpc': %q", sanitizeForError(conf.VPC)),
		}
	}
	if !isValidBase62(conf.VPCAttachment) {
		if len(conf.VPCAttachment) == 0 {
			return nil, &types.Error{Code: 7, Msg: errVPCAttachmentRequired}
		}
		return nil, &types.Error{
			Code: 7,
			Msg:  fmt.Sprintf("invalid base62 value for field 'vpcattachment': %q", sanitizeForError(conf.VPCAttachment)),
		}
	}

	hostConf, err := loadHostConf(ConfFile)
	if err != nil {
		return nil, fmt.Errorf("load host CNI config: %w", err)
	}

	cniConfig.Resolve(&config.ConflistValues{
		NodeName:   hostConf.NodeName,
		Kubeconfig: hostConf.Kubeconfig,
		Namespace:  hostConf.Namespace,
		LogFile:    hostConf.LogFile,
		LogLevel:   hostConf.LogLevel,
	})

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
	_ = os.Setenv("KUBECONFIG", cniConfig.Kubeconfig)

	namespace := conf.Namespace
	if namespace == "" {
		namespace = cniConfig.Namespace
	}
	conf.Namespace = namespace

	setupLogging(cniConfig.LogFile, cniConfig.LogLevel)
	slog.Debug("CNI config received", "stdin", string(data))

	// Whether IPAM runs at all is decided entirely by "ipam" block
	// presence — see internal/cni's own parseConf for the full reasoning,
	// identical here. Addressing fields and their validation live inside
	// internal/cniipam, invoked via delegation with this plugin's own
	// StdinData passed straight through unmodified.

	if conf.PrevResult != nil {
		if err := validatePrevResult(conf.PrevResult); err != nil {
			return nil, &types.Error{Code: 6, Msg: fmt.Sprintf("invalid prevResult: %v", err)}
		}
	}
	return conf, nil
}

func sanitizeForError(s string) string {
	for _, c := range s {
		if c < 0x20 || c > 0x7e {
			return sanitizeForErrorBinary
		}
	}
	return s
}
