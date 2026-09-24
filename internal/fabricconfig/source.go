// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package fabricconfig resolves a node's FRR configuration for the
// fabric-router DaemonSet from its own per-node ConfigMap, writes it into the
// FRR configuration directory, and keeps the running FRR instance converged on
// it with frr-reload.
package fabricconfig

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"
)

const (
	// ConfigMapPrefix prefixes a node name to form the name of that node's own
	// configuration ConfigMap.
	ConfigMapPrefix = "fabric-router."

	// DefaultLegacyConfigMap is the shared ConfigMap that carried every node's
	// frr.conf under a per-node key before per-node ConfigMaps.
	DefaultLegacyConfigMap = "fabric-config"

	// KeyFRRConf, KeyDaemons and KeyVtyshConf are the files a per-node
	// ConfigMap may carry. Only KeyFRRConf is required; the other two override
	// the image's defaults when present.
	KeyFRRConf   = "frr.conf"
	KeyDaemons   = "daemons"
	KeyVtyshConf = "vtysh.conf"

	legacyFRRConfKeyPrefix = "frr.conf."
)

// knownKeys lists every key a per-node ConfigMap may carry.
var knownKeys = []string{KeyFRRConf, KeyDaemons, KeyVtyshConf}

var (
	// ErrNotFound reports that no configuration exists for the node in either
	// its per-node ConfigMap or the legacy shared ConfigMap.
	ErrNotFound = errors.New("no fabric-router configuration for node")

	// ErrInvalid reports a per-node ConfigMap whose keys are unusable.
	ErrInvalid = errors.New("invalid fabric-router configuration")
)

// ConfigMapName returns the name of nodeName's own configuration ConfigMap.
func ConfigMapName(nodeName string) string {
	return ConfigMapPrefix + nodeName
}

// Source is a node's resolved configuration and the ConfigMap it came from.
type Source struct {
	// ConfigMap is the object the files were read from.
	ConfigMap *corev1.ConfigMap
	// Legacy is true when ConfigMap is the shared legacy ConfigMap rather
	// than the node's own.
	Legacy bool
	// Files maps each file name under the FRR configuration directory to its
	// contents. It always contains KeyFRRConf.
	Files map[string]string
}

// Resolve returns nodeName's configuration. perNode is the node's own
// ConfigMap and legacy the shared legacy ConfigMap; either may be nil when it
// does not exist. perNode always takes precedence. It returns ErrNotFound when
// neither carries configuration for the node, and ErrInvalid when perNode
// lacks KeyFRRConf or carries a key other than the known ones.
func Resolve(nodeName string, perNode, legacy *corev1.ConfigMap) (*Source, error) {
	if perNode != nil {
		var unknown []string
		for k := range perNode.Data {
			if !slices.Contains(knownKeys, k) {
				unknown = append(unknown, k)
			}
		}
		for k := range perNode.BinaryData {
			unknown = append(unknown, k)
		}
		if len(unknown) > 0 {
			slices.Sort(unknown)
			return nil, fmt.Errorf("%w: ConfigMap %s has unknown keys %s (allowed: %s)",
				ErrInvalid, perNode.Name, strings.Join(unknown, ", "), strings.Join(knownKeys, ", "))
		}
		if _, ok := perNode.Data[KeyFRRConf]; !ok {
			return nil, fmt.Errorf("%w: ConfigMap %s has no %s key", ErrInvalid, perNode.Name, KeyFRRConf)
		}
		return &Source{ConfigMap: perNode, Files: maps.Clone(perNode.Data)}, nil
	}

	if legacy != nil {
		conf, ok := legacy.Data[legacyFRRConfKeyPrefix+nodeName]
		if ok {
			files := map[string]string{KeyFRRConf: conf}
			for _, k := range []string{KeyDaemons, KeyVtyshConf} {
				if v, ok := legacy.Data[k]; ok {
					files[k] = v
				}
			}
			return &Source{ConfigMap: legacy, Legacy: true, Files: files}, nil
		}
	}

	return nil, fmt.Errorf("%w %s: neither ConfigMap %s nor key %s%s in the legacy ConfigMap exists",
		ErrNotFound, nodeName, ConfigMapName(nodeName), legacyFRRConfKeyPrefix, nodeName)
}

// Hash returns a short, stable digest of contents, for reporting which version
// of a file a node is running.
func Hash(contents string) string {
	sum := sha256.Sum256([]byte(contents))
	return hex.EncodeToString(sum[:])[:12]
}
