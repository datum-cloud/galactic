package underlay

import (
	"context"
	"fmt"
	"net"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// PeerInfo holds the name and IPv6 address of a peer node.
type PeerInfo struct {
	Name    string
	Address net.IP
}

// ListPeerAddresses returns the IPv6 InternalIP of every node except localNodeName.
func ListPeerAddresses(ctx context.Context, k8sClient kubernetes.Interface, localNodeName string) ([]PeerInfo, error) {
	nodes, err := k8sClient.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list nodes: %w", err)
	}

	var peers []PeerInfo
	for _, node := range nodes.Items {
		if node.Name == localNodeName {
			continue
		}
		if ip := nodeIPv6(node); ip != nil {
			peers = append(peers, PeerInfo{Name: node.Name, Address: ip})
		}
	}
	return peers, nil
}

// LocalNodeIPv6 returns the IPv6 InternalIP of the given node.
func LocalNodeIPv6(ctx context.Context, k8sClient kubernetes.Interface, nodeName string) (net.IP, error) {
	node, err := k8sClient.CoreV1().Nodes().Get(ctx, nodeName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("get node %s: %w", nodeName, err)
	}
	ip := nodeIPv6(*node)
	if ip == nil {
		return nil, fmt.Errorf("node %s has no IPv6 InternalIP", nodeName)
	}
	return ip, nil
}

func nodeIPv6(node corev1.Node) net.IP {
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
