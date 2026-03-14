// Package nodeutil provides helpers for extracting information from Kubernetes Node objects.
package nodeutil

import (
	"context"
	"fmt"
	"net"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// LocalNodeIPv6 returns the IPv6 InternalIP of the given node.
func LocalNodeIPv6(ctx context.Context, k8sClient kubernetes.Interface, nodeName string) (net.IP, error) {
	node, err := k8sClient.CoreV1().Nodes().Get(ctx, nodeName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("get node %s: %w", nodeName, err)
	}
	ip := NodeIPv6(*node)
	if ip == nil {
		return nil, fmt.Errorf("node %s has no IPv6 InternalIP", nodeName)
	}
	return ip, nil
}

// NodeIPv6 extracts the IPv6 InternalIP from a Node object. Returns nil if not found.
func NodeIPv6(node corev1.Node) net.IP {
	for _, addr := range node.Status.Addresses {
		if addr.Type != corev1.NodeInternalIP {
			continue
		}
		ip := net.ParseIP(addr.Address)
		if ip != nil && ip.To4() == nil {
			return ip
		}
	}
	return nil
}
