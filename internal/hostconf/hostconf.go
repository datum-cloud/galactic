// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package hostconf reads node-local settings, the node name, kubeconfig,
// namespace, and log file and level, from the static per-node CNI conflist
// written once by the installer. Every binary in the plugin chain needs the
// same lookup, so it lives here rather than being duplicated per binary.
//
// That static conflist is not the per-attachment conflist the CNI runtime execs
// each plugin with, which carries the VPC identifiers and is templated per
// attachment by an external operator. It exists so any binary in the chain can
// find node-level settings at a well-known path, whatever it was invoked as.
// The installer writes exactly one entry, typed PluginType, which every caller
// here passes.
//
// It also carries RejectMovedIPAMKeys, the guard every master plugin runs over
// the per-attachment config, shared here for the same reason: so the two master
// plugins cannot drift apart on which keys they refuse.
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

// PluginType is the "type" value the installer writes into the static
// conflist's single entry. It names the installer that authors the file, not
// any particular master plugin, so every binary in the chain passes it to
// Load.
const PluginType = "galactic-cni"

// BGPPluginType is the "type" a conflist entry must carry for the chained
// plugin that publishes BGP, SRv6, and eBPF state after a master plugin creates
// the interface. Both master plugins check for its presence in their own
// attachment's conflist before doing any other work.
const BGPPluginType = "galactic-bgp"

// HostConf holds node-local settings read from the static per-node conflist
// (default /etc/cni/net.d/10-galactic.conflist).
type HostConf struct {
	NodeName   string `json:"node_name"`
	Kubeconfig string `json:"kubeconfig"`
	Namespace  string `json:"namespace"`
	LogFile    string `json:"log_file"`
	LogLevel   string `json:"log_level,omitempty"`

	// NAT66ShardSIDs is the comma-separated NAT66 shard SID list, written by
	// the installer from its own environment and read by the BGP plugin: a CNI
	// plugin's exec environment carries none of this on its own.
	NAT66ShardSIDs string `json:"nat66_shard_sids,omitempty"`

	// EBPFInterfaces is the comma-separated interface list, written by the
	// installer from its own environment or auto-detection. The installer runs
	// as an init container sharing its pod's environment with the long-running
	// one, so its detection is correct there.
	//
	// The BGP plugin, invoked per pod by the CNI runtime rather than being a
	// long-lived process with configurable environment, would otherwise never
	// see the setting and would silently fall back to its own auto-detection.
	// That is wrong on any node where the interface carrying the default IPv6
	// route is not the fabric interface, and produces a plausible but wrong
	// uplink entry for the DSR reply redirect.
	EBPFInterfaces string `json:"ebpf_interfaces,omitempty"`
}

// conflistEnvelope matches standard CNI conflist JSON structure.
type conflistEnvelope struct {
	CNIVersion string            `json:"cniVersion"`
	Name       string            `json:"name"`
	Plugins    []json.RawMessage `json:"plugins"`
}

// Load reads and parses the conflist at filePath and returns the HostConf from
// whichever plugin entry's type matches one of acceptedTypes. A missing file
// returns an error wrapping fs.ErrNotExist, so a tolerant caller can fall back
// to defaults.
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

// VerifyChainIncludes parses configJSON as a CNI plugin list, the same envelope
// Load parses but read from an attachment definition rather than a file, and
// returns a CNI error naming expectedType if no entry's type equals it.
//
// Presence only, not position: a conflist naming expectedType out of order is a
// separate authoring bug this does not catch. Presence is the cheapest check
// that catches the real failure, a stale or hand-edited conflist that drops the
// entry. A conflist with no plugin list at all has zero entries to match and
// fails the same way.
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

// movedIPAMKeys holds exactly the addressing keys that once sat at the top
// level of a master plugin's config and now live inside its "ipam" block. Every
// field is a raw message so only presence is decoded: a wrong-typed value must
// still report as present rather than failing the decode, and no value is ever
// read.
type movedIPAMKeys struct {
	IPv6Subnet      json.RawMessage `json:"ipv6_subnet"`
	IPv4Subnet      json.RawMessage `json:"ipv4_subnet"`
	AddressFamilies json.RawMessage `json:"address_families"`
	StaticIP        json.RawMessage `json:"static_ip"`
}

// RejectMovedIPAMKeys returns a CNI validation error when data carries any of
// the moved addressing keys at the top level of a master plugin's config.
//
// Whether a master plugin allocates addresses at all is decided purely by
// whether the "ipam" block is present, and JSON decoding drops unknown fields.
// A config written against the old flat shape therefore parses cleanly, the pod
// attaches with a working interface and no addresses, and its advertisement is
// created advertising nothing, with no error or warning. Guessing wrong about a
// pod's addressing is worse than refusing to attach it.
func RejectMovedIPAMKeys(data []byte) error {
	var moved movedIPAMKeys
	// A decode error is the caller's to report: every master plugin unmarshals
	// the same bytes into its full config first, so malformed JSON has already
	// been rejected with its own message.
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

// DetectNodeNameFromAPI queries the Kubernetes API and matches nodes' internal
// addresses against local interface addresses, returning the first match. It
// returns "" with no error when detection fails, so callers can fall through to
// other methods. Used when the static conflist is missing or carries no node
// name.
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
