// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package virtualnode maps virtual kubelet Nodes to the host Nodes that run
// their pods.
//
// A virtual kubelet, such as the one Unikraft instances run under, registers
// its own Node for the host it runs on. Pods are bound to that virtual Node,
// while their taps, host links and attachments live on the host, the Node
// galactic-cni runs on and programs them from.
package virtualnode

import corev1 "k8s.io/api/core/v1"

// Label marks a Node that a virtual kubelet registers for the host it shares
// an internal address with.
const Label = "unikraft.com/virtual-kubelet"

// labelTrue is the value Label carries on a virtual kubelet Node.
const labelTrue = "true"

// IsVirtual reports whether node is a virtual kubelet Node.
func IsVirtual(node *corev1.Node) bool {
	return node.Labels[Label] == labelTrue
}

// Selector returns the labels that select virtual kubelet Nodes.
func Selector() map[string]string {
	return map[string]string{Label: labelTrue}
}

// Hosts maps each virtual kubelet Node in nodes to the Node in nodes that is
// not one and shares one of its internal addresses. A virtual Node with no
// such host is left out.
func Hosts(nodes []corev1.Node) map[string]string {
	byAddress := map[string]string{}
	for i := range nodes {
		if IsVirtual(&nodes[i]) {
			continue
		}
		for _, addr := range nodes[i].Status.Addresses {
			if addr.Type == corev1.NodeInternalIP {
				byAddress[addr.Address] = nodes[i].Name
			}
		}
	}
	hosts := map[string]string{}
	for i := range nodes {
		if !IsVirtual(&nodes[i]) {
			continue
		}
		for _, addr := range nodes[i].Status.Addresses {
			if host, ok := byAddress[addr.Address]; ok && addr.Type == corev1.NodeInternalIP {
				hosts[nodes[i].Name] = host
				break
			}
		}
	}
	return hosts
}
