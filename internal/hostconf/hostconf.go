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
//
// It also carries RejectMovedIPAMKeys, the guard every master plugin runs
// over that per-attachment config — shared here for the same reason Load
// is, so the two master plugins cannot drift apart on which keys they
// refuse.
package hostconf

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/containernetworking/cni/pkg/types"
	"github.com/vishvananda/netlink"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// PluginType is the "type" value Bootstrap always writes into the static
// conflist's single plugin entry. It names galactic-cni, the installer that
// actually authors this file, not any particular master plugin — veth, tap,
// and bgp all read this same value regardless of which binary is actually
// reading it. Every caller in the chain passes this to Load.
const PluginType = "galactic-cni"

// BGPPluginType is the "type" value a conflist entry must carry for
// galactic-bgp, the chained plugin that publishes BGP/SRv6/eBPF state after
// a master plugin (galactic-veth/galactic-tap) creates the interface. Both
// master plugins check for its presence in their own attachment's conflist
// before doing any other work — see VerifyChainIncludes.
const BGPPluginType = "galactic-bgp"

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

// VerifyChainIncludes parses configJSON as a CNI NetConfList — the same
// {"plugins":[{"type":...}, ...]} envelope Load already parses, here read
// from a NetworkAttachmentDefinition's own spec.config rather than a file —
// and reports a CNI error (code 7) naming expectedType if no entry's "type"
// field equals it anywhere in the list.
//
// Presence-only, not position-aware: a conflist that names expectedType out
// of order is a separate authoring bug this does not catch. Presence is
// what issue #331 asks for ("attach fails when the chain is incomplete")
// and is the cheapest check that catches the actual failure mode reported
// there — a stale/hand-edited conflist that drops the entry entirely. A
// conflist with no "plugins" key at all (the pre-#305 flat single-plugin
// shape) has zero entries to match and fails the same way a conflist
// missing just the galactic-bgp entry does.
func VerifyChainIncludes(configJSON []byte, expectedType string) error {
	var env conflistEnvelope
	if err := json.Unmarshal(configJSON, &env); err != nil {
		return fmt.Errorf("parse attachment conflist: %w", err)
	}

	for _, raw := range env.Plugins {
		var meta struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(raw, &meta); err != nil {
			continue
		}
		if meta.Type == expectedType {
			return nil
		}
	}

	return &types.Error{
		Code: 7,
		Msg: fmt.Sprintf("attachment conflist is missing required plugin %q — "+
			"the attachment would succeed with no path to its VPC", expectedType),
	}
}

// movedIPAMKeys holds exactly the addressing keys that used to sit at the
// top level of a master plugin's config and now live inside its "ipam"
// block. Every field is a json.RawMessage so presence is all that is
// decoded: a wrong-typed value must still be reported as present rather
// than failing the decode, and no value here is ever read.
type movedIPAMKeys struct {
	IPv6Subnet      json.RawMessage `json:"ipv6_subnet"`
	IPv4Subnet      json.RawMessage `json:"ipv4_subnet"`
	AddressFamilies json.RawMessage `json:"address_families"`
	StaticIP        json.RawMessage `json:"static_ip"`
}

// RejectMovedIPAMKeys reports a CNI validation error (code 7) when data
// carries any of the moved addressing keys at the top level of a master
// plugin's config.
//
// Whether a master plugin allocates addresses at all is decided purely by
// whether the "ipam" block is present. encoding/json drops unknown fields,
// so a config still written against the old flat shape parses cleanly, the
// pod attaches with a working interface and no addresses, and its
// BGPAdvertisement is created advertising nothing — no error, no warning.
// Guessing wrong about a pod's addressing is worse than refusing to attach
// it, so the keys are refused by name instead.
func RejectMovedIPAMKeys(data []byte) error {
	var moved movedIPAMKeys
	// A decode error here is the caller's own to report: every master
	// plugin unmarshals the same bytes into its full config first, so
	// malformed JSON has already been rejected with its own message.
	if err := json.Unmarshal(data, &moved); err != nil {
		return nil
	}

	var found []string
	for _, key := range []struct {
		name string
		raw  json.RawMessage
	}{
		{"ipv6_subnet", moved.IPv6Subnet},
		{"ipv4_subnet", moved.IPv4Subnet},
		{"address_families", moved.AddressFamilies},
		{"static_ip", moved.StaticIP},
	} {
		// An explicit JSON null carries no addressing intent, so it reads
		// the same as the key being absent.
		if len(key.raw) > 0 && string(key.raw) != "null" {
			found = append(found, "'"+key.name+"'")
		}
	}
	if len(found) == 0 {
		return nil
	}

	field, belong := "field", "belongs"
	if len(found) > 1 {
		field, belong = "fields", "belong"
	}
	return &types.Error{
		Code: 7,
		Msg: fmt.Sprintf("addressing %s %s %s inside the 'ipam' block, not at the top level of the config",
			field, strings.Join(found, ", "), belong),
	}
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
