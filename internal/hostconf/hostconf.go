// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package hostconf reads node-local settings (node name, kubeconfig,
// namespace, log file/level) from the static per-node CNI conflist written
// once by internal/installer.Bootstrap. Every binary in the galactic CNI
// plugin chain needs this same lookup, so it lives here rather than being
// duplicated per binary — internal/cni and internal/installer both used to
// carry their own near-identical copy, hardcoded to match a single plugin
// type ("galactic-cni").
//
// The static conflist is not the per-attachment chain conflist the CNI
// runtime execs each plugin with (that one carries vpc/vpcattachment and is
// templated per VPCAttachment by the external companion operator) — it
// exists solely so any binary in the chain can find node-level settings by
// reading a well-known path off disk, independent of how it was actually
// invoked. Bootstrap only ever writes one entry, typed PluginType, so every
// caller in this repo passes that same constant.
package hostconf

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/vishvananda/netlink"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// PluginType is the "type" value Bootstrap always writes into the static
// conflist's single plugin entry, regardless of which binary is actually
// reading it. Every caller in the chain passes this to Load.
const PluginType = "galactic-cni"

// HostConf holds node-local settings read from the static per-node conflist
// (default /etc/cni/net.d/10-galactic.conflist).
type HostConf struct {
	NodeName   string `json:"node_name"`
	Kubeconfig string `json:"kubeconfig"`
	Namespace  string `json:"namespace"`
	LogFile    string `json:"log_file"`
	LogLevel   string `json:"log_level,omitempty"`
}

// conflistEnvelope matches standard CNI conflist JSON structure.
type conflistEnvelope struct {
	CNIVersion string            `json:"cniVersion"`
	Name       string            `json:"name"`
	Plugins    []json.RawMessage `json:"plugins"`
}

// Load reads and parses the conflist at filePath and returns the HostConf
// carried by whichever plugin entry's "type" matches one of acceptedTypes.
// Returns an error wrapping fs.ErrNotExist (checkable via errors.Is) when
// filePath does not exist, so tolerant callers can fall back to defaults.
func Load(filePath string, acceptedTypes ...string) (*HostConf, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("read conflist file %q: %w", filePath, err)
	}

	var env conflistEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("parse conflist envelope: %w", err)
	}

	accepted := make(map[string]bool, len(acceptedTypes))
	for _, t := range acceptedTypes {
		accepted[t] = true
	}

	for _, raw := range env.Plugins {
		var meta struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(raw, &meta); err != nil {
			continue
		}
		if accepted[meta.Type] {
			var conf HostConf
			if err := json.Unmarshal(raw, &conf); err != nil {
				return nil, fmt.Errorf("parse host CNI config: %w", err)
			}
			return &conf, nil
		}
	}

	return nil, fmt.Errorf("conflist at %q does not contain a plugin with type in %v", filePath, acceptedTypes)
}

// detectScheme returns a minimal scheme containing only corev1 types needed
// for node name detection.
func detectScheme() *runtime.Scheme {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	return scheme
}

// DetectNodeNameFromAPI queries the Kubernetes API and matches the node's
// InternalIP addresses against local interface addresses. Returns the first
// matching node name, or empty string with no error if detection fails
// (allowing callers to fall through to other resolution methods). Used as a
// fallback by any binary's config resolution when the static conflist is
// missing or doesn't carry a node name (e.g. hostPath mount issues in
// container-based test environments like Kind).
func DetectNodeNameFromAPI() (string, error) {
	restCfg, err := ctrl.GetConfig()
	if err != nil {
		return "", fmt.Errorf("get kubeconfig: %w", err)
	}

	k8sClient, err := client.New(restCfg, client.Options{
		Scheme: detectScheme(),
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

	addrs, err := netlink.AddrList(nil, netlink.FAMILY_ALL)
	if err != nil {
		return "", fmt.Errorf("list local addresses: %w", err)
	}

	localIPs := make(map[string]bool, len(addrs))
	for _, addr := range addrs {
		localIPs[addr.IP.String()] = true
	}

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
