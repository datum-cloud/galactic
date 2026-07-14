// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cni

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/containernetworking/cni/pkg/types"
	type100 "github.com/containernetworking/cni/pkg/types/100"
	"github.com/vishvananda/netlink"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	DefaultConfFile   = "/etc/cni/net.d/10-galactic.conflist"
	DefaultKubeconfig = "/var/lib/galactic/kubeconfig"
	DefaultNamespace  = "galactic-system"
	DefaultLogFile    = "/var/log/galactic/galactic-cni.log"
)

var ConfFile = DefaultConfFile

const sanitizeForErrorBinary = "<binary>"

// isValidBase62 reports whether s contains only valid base62 characters
// ([0-9a-zA-Z]) and is non-empty. VPC and VPCAttachment identifiers are
// base62-encoded and used throughout the ADD path (interface naming,
// BGP CRD population). Rejecting them early in parseConf prevents cryptic
// errors deep in the stack after partial kernel state has been created.
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

// conflistEnvelope matches standard CNI conflist JSON structure.
type conflistEnvelope struct {
	CNIVersion string            `json:"cniVersion"`
	Name       string            `json:"name"`
	Plugins    []json.RawMessage `json:"plugins"`
}

// loadHostConf loads node-local settings from the CNI conflist.
// If the file is missing, it returns a zero-value HostConf (tolerating local test runs)
// but still defaulting Namespace to DefaultNamespace.
func loadHostConf(filePath string) (*HostConf, error) {
	if filePath == "" {
		filePath = DefaultConfFile
	}
	data, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			// Tolerated, return defaulted config.
			return &HostConf{
				Namespace: DefaultNamespace,
			}, nil
		}
		return nil, fmt.Errorf("read conflist file %q: %w", filePath, err)
	}

	var env conflistEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("parse conflist envelope: %w", err)
	}

	for _, raw := range env.Plugins {
		var meta struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(raw, &meta); err != nil {
			continue
		}
		if meta.Type == "galactic-cni" {
			var conf HostConf
			if err := json.Unmarshal(raw, &conf); err != nil {
				return nil, fmt.Errorf("parse host CNI config: %w", err)
			}
			if conf.Namespace == "" {
				conf.Namespace = DefaultNamespace
			}
			return &conf, nil
		}
	}

	return nil, fmt.Errorf("conflist at %q does not contain a plugin with type \"galactic-cni\"", filePath)
}

// detectNodeNameFromAPI queries the Kubernetes API and matches the node's
// InternalIP addresses against local interface addresses. Returns the first
// matching node name, or empty string with no error if detection fails
// (allowing callers to fall through to other resolution methods).
func detectNodeNameFromAPI() (string, error) {
	restCfg, err := ctrl.GetConfig()
	if err != nil {
		return "", fmt.Errorf("get kubeconfig: %w", err)
	}

	k8sClient, err := client.New(restCfg, client.Options{
		Scheme: buildDetectScheme(),
	})
	if err != nil {
		return "", fmt.Errorf("create k8s client: %w", err)
	}

	var nodeList corev1.NodeList
	if err := k8sClient.List(context.Background(), &nodeList, &client.ListOptions{
		Limit: 1000,
	}); err != nil {
		return "", fmt.Errorf("list nodes: %w", err)
	}

	// Collect all local interface addresses
	addrs, err := netlink.AddrList(nil, netlink.FAMILY_ALL)
	if err != nil {
		return "", fmt.Errorf("list local addresses: %w", err)
	}

	localIPs := make(map[string]bool, len(addrs))
	for _, addr := range addrs {
		localIPs[addr.IP.String()] = true
	}

	// Match against node InternalIPs
	for _, node := range nodeList.Items {
		for _, addr := range node.Status.Addresses {
			if addr.Type == corev1.NodeInternalIP && localIPs[addr.Address] {
				slog.Info("Auto-detected node name from Kubernetes API",
					"nodeName", node.Name, "matchedIP", addr.Address)
				return node.Name, nil
			}
		}
	}

	return "", errors.New("no local interface address matched any node InternalIP")
}

// buildDetectScheme returns a minimal scheme containing only corev1 types
// needed for node name detection.
func buildDetectScheme() *runtime.Scheme {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	return scheme
}

// setupLogging configures the slog default logger to write to the specified path.
// If opening the file fails, it logs a warning to os.Stderr and falls back.
func setupLogging(logPath string) {
	if logPath == "" {
		logPath = DefaultLogFile
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
	handler := slog.NewJSONHandler(file, &slog.HandlerOptions{Level: slog.LevelInfo})
	slog.SetDefault(slog.New(handler))
}

// statusConf holds the minimal CNI config fields needed for STATUS validation.

// STATUS only checks that the config is parseable and the API server is reachable;
// it does not validate attachment-specific fields (VPC, VPCAttachment) because
// STATUS must succeed before any ADD has ever run.
type statusConf struct {
	CNIVersion    string `json:"cniVersion"`
	Type          string `json:"type"`
	InterfaceType string `json:"interface_type"`
}

// parseStatusConf validates that the CNI config is parseable and contains the
// required top-level fields (cniVersion, type). Unlike parseConf, it does not
// validate VPC or VPCAttachment because STATUS must succeed on a freshly
// started node before any ADD has run. However, interface_type is validated
// if present because it is a structural config field, not an attachment
// identifier.
func parseStatusConf(data []byte) error {
	var sc statusConf
	if err := json.Unmarshal(data, &sc); err != nil {
		return fmt.Errorf("parse CNI config: %w", err)
	}
	if sc.CNIVersion == "" {
		return errors.New("cniVersion is required")
	}
	if sc.Type == "" {
		return errors.New("type is required")
	}
	// Validate interface_type if present.
	if sc.InterfaceType != "" {
		switch sc.InterfaceType {
		case interfaceTypeVeth, interfaceTypeTap:
		default:
			return fmt.Errorf(
				"invalid interface_type %q: must be %q or %q",
				sc.InterfaceType, interfaceTypeVeth, interfaceTypeTap,
			)
		}
	}
	return nil
}

// validatePrevResult checks that the prevResult (from a preceding plugin in
// the CNI chain) is a valid, parseable CNI result. Returns an error if the
// result is non-nil but cannot be parsed as a versioned CNI result, ensuring
// galactic-cni fails fast rather than silently operating on garbage state.
func validatePrevResult(res types.Result) error {
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

// validatePrevResultAdd performs content-level validation of prevResult during
// the ADD operation. It ensures the preceding plugin produced a result with at
// least one interface or IP assignment, which is the minimum expected structure
// for any meaningful CNI chain. Returns nil when prevResult is nil (no
// preceding plugin) or structurally valid with expected content.
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
	// A valid prevResult must declare at least one interface or IP assignment.
	if len(versioned.Interfaces) == 0 && len(versioned.IPs) == 0 {
		return errors.New("prevResult declares no interfaces or IP assignments")
	}
	return nil
}

// parseConf unmarshals the CNI configuration from stdin data and validates
// the interface type and base62-encoded identifier fields. It resolves the
// host configuration and sets up process environment variables and logging.
func parseConf(data []byte) (*PluginConf, error) {
	conf := &PluginConf{}
	if err := json.Unmarshal(data, &conf); err != nil {
		return nil, fmt.Errorf("parse CNI config: %w", err)
	}
	if !isValidBase62(conf.VPC) {
		if len(conf.VPC) == 0 {
			return nil, errors.New("vpc is required and must be a non-empty base62 string")
		}
		return nil, fmt.Errorf("invalid base62 value for field 'vpc': %q", sanitizeForError(conf.VPC))
	}
	if !isValidBase62(conf.VPCAttachment) {
		if len(conf.VPCAttachment) == 0 {
			return nil, errors.New("vpcattachment is required and must be a non-empty base62 string")
		}
		return nil, fmt.Errorf("invalid base62 value for field 'vpcattachment': %q", sanitizeForError(conf.VPCAttachment))
	}

	// Load host CNI config
	hostConf, err := loadHostConf(ConfFile)
	if err != nil {
		return nil, fmt.Errorf("load host CNI config: %w", err)
	}

	// Resolve and propagate NodeName
	nodeName := os.Getenv("GALACTIC_CNI_NODE_NAME")
	if nodeName == "" {
		nodeName = os.Getenv("NODE_NAME")
	}
	if nodeName == "" {
		nodeName = hostConf.NodeName
	}
	if nodeName == "" {
		// Fallback: auto-detect from the Kubernetes API by matching local
		// interface addresses against node InternalIPs. This handles cases
		// where the conflist file is missing (e.g. hostPath mount issues
		// in container-based environments like Kind).
		detected, detectErr := detectNodeNameFromAPI()
		if detectErr != nil {
			slog.Warn("Node name auto-detection failed", "err", detectErr)
		}
		nodeName = detected
	}
	if nodeName == "" {
		return nil, errors.New("node name is required (or set GALACTIC_CNI_NODE_NAME)")
	}
	_ = os.Setenv("NODE_NAME", nodeName)

	// Resolve and propagate Kubeconfig
	kubeconfig := os.Getenv("GALACTIC_CNI_KUBECONFIG")
	if kubeconfig == "" {
		kubeconfig = hostConf.Kubeconfig
	}
	if kubeconfig == "" {
		kubeconfig = DefaultKubeconfig
	}
	_ = os.Setenv("KUBECONFIG", kubeconfig)

	// Resolve and propagate Namespace fallback
	namespace := conf.Namespace
	if namespace == "" {
		namespace = os.Getenv("GALACTIC_CNI_NAMESPACE")
	}
	if namespace == "" {
		namespace = hostConf.Namespace
	}
	if namespace == "" {
		namespace = DefaultNamespace
	}
	conf.Namespace = namespace

	// Resolve and setup Logging
	logFile := os.Getenv("GALACTIC_CNI_LOG_FILE")
	if logFile == "" {
		logFile = hostConf.LogFile
	}
	if logFile == "" {
		logFile = DefaultLogFile
	}
	setupLogging(logFile)

	// Resolve local IPAM flag
	if val := os.Getenv("GALACTIC_CNI_ENABLE_LOCAL_IPAM"); val != "" {
		enableLocalIPAM = (val == "true" || val == "1")
	}

	// Enforce required IPAM block if local IPAM is enabled
	if enableLocalIPAM && conf.IPAM == nil {
		return nil, errors.New("local IPAM is enabled, but no 'ipam' block is present in the configuration")
	}

	if conf.PrevResult != nil {
		if err := validatePrevResult(conf.PrevResult); err != nil {
			return nil, fmt.Errorf("invalid prevResult: %w", err)
		}
	}
	if conf.InterfaceType == "" {
		conf.InterfaceType = interfaceTypeVeth
	}
	switch conf.InterfaceType {
	case interfaceTypeVeth, interfaceTypeTap:
	default:
		return nil, fmt.Errorf(
			"invalid interface_type %q: must be %q or %q",
			conf.InterfaceType, interfaceTypeVeth, interfaceTypeTap,
		)

	}
	return conf, nil
}

// sanitizeForError returns s unchanged if it contains only printable ASCII
// characters; otherwise returns "<binary>" to avoid corrupting log output.
func sanitizeForError(s string) string {
	for _, c := range s {
		if c < 0x20 || c > 0x7e {
			return sanitizeForErrorBinary
		}
	}
	return s
}

// subnetAnnotationKey returns the annotation key for storing the allocated
// subnet for the given container ID. Kubernetes limits the name part of an
// annotation key to 63 bytes; "allocated-subnet." is 17 bytes, leaving 46
// bytes for the container ID prefix.
func subnetAnnotationKey(containerID string) string {
	id := containerID
	if len(id) > annotationContainerIDLen {
		id = id[:annotationContainerIDLen]
	}
	return fmt.Sprintf("%s.%s", annotationAllocatedSubnet, id)
}

// netnsAnnotationKey returns the annotation key for storing the network
// namespace path used by the given container ID. Mirrors subnetAnnotationKey.
func netnsAnnotationKey(containerID string) string {
	id := containerID
	if len(id) > annotationContainerIDLen {
		id = id[:annotationContainerIDLen]
	}
	return fmt.Sprintf("%s.%s", annotationNetNS, id)
}
