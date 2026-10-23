// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	runtimev1 "k8s.io/cri-api/pkg/apis/runtime/v1"
)

// ErrNamespaceUnavailable is wrapped by a NamespaceResolver that cannot find
// exactly one running sandbox, and its network namespace, for a pod.
var ErrNamespaceUnavailable = errors.New("pod network namespace unavailable")

// NamespaceResolver finds the network namespace of a pod on this node.
type NamespaceResolver interface {
	// PodNetNS returns the path of the network namespace of the one ready
	// sandbox of the pod with podUID. The sandbox's own metadata must
	// carry podUID; a name or a label match alone is not enough.
	PodNetNS(ctx context.Context, podUID string) (string, error)
}

// CRIResolver resolves pod network namespaces through the node's container
// runtime (CRI) socket. It reads the namespace path from the runtime's
// verbose sandbox status, which containerd provides.
type CRIResolver struct {
	client runtimev1.RuntimeServiceClient
	conn   *grpc.ClientConn
}

// NewCRIResolver connects to the CRI endpoint, such as
// unix:///run/containerd/containerd.sock.
func NewCRIResolver(endpoint string) (*CRIResolver, error) {
	conn, err := grpc.NewClient(endpoint, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("connect to CRI endpoint %s: %w", endpoint, err)
	}
	return &CRIResolver{client: runtimev1.NewRuntimeServiceClient(conn), conn: conn}, nil
}

// Close closes the connection.
func (r *CRIResolver) Close() error { return r.conn.Close() }

// podUIDLabel is the sandbox label the kubelet sets to the pod's UID.
const podUIDLabel = "io.kubernetes.pod.uid"

// PodNetNS implements NamespaceResolver.
func (r *CRIResolver) PodNetNS(ctx context.Context, podUID string) (string, error) {
	list, err := r.client.ListPodSandbox(ctx, &runtimev1.ListPodSandboxRequest{Filter: &runtimev1.PodSandboxFilter{
		State:         &runtimev1.PodSandboxStateValue{State: runtimev1.PodSandboxState_SANDBOX_READY},
		LabelSelector: map[string]string{podUIDLabel: podUID},
	}})
	if err != nil {
		return "", fmt.Errorf("list sandboxes of pod %s: %w", podUID, err)
	}
	if n := len(list.Items); n != 1 {
		return "", fmt.Errorf("%w: pod %s has %d ready sandboxes", ErrNamespaceUnavailable, podUID, n)
	}
	status, err := r.client.PodSandboxStatus(ctx, &runtimev1.PodSandboxStatusRequest{
		PodSandboxId: list.Items[0].Id, Verbose: true,
	})
	if err != nil {
		return "", fmt.Errorf("sandbox status of pod %s: %w", podUID, err)
	}
	if md := status.GetStatus().GetMetadata(); md.GetUid() != podUID {
		return "", fmt.Errorf("%w: sandbox %s belongs to pod %s, not %s",
			ErrNamespaceUnavailable, list.Items[0].Id, md.GetUid(), podUID)
	}
	return netnsFromInfo(status.GetInfo()["info"])
}

// netnsFromInfo extracts the network namespace path from containerd's
// verbose sandbox info, the sandbox's OCI runtime spec.
func netnsFromInfo(info string) (string, error) {
	var v struct {
		RuntimeSpec struct {
			Linux struct {
				Namespaces []struct {
					Type string `json:"type"`
					Path string `json:"path"`
				} `json:"namespaces"`
			} `json:"linux"`
		} `json:"runtimeSpec"`
	}
	if err := json.Unmarshal([]byte(info), &v); err != nil {
		return "", fmt.Errorf("%w: sandbox info: %w", ErrNamespaceUnavailable, err)
	}
	for _, ns := range v.RuntimeSpec.Linux.Namespaces {
		if ns.Type == "network" && ns.Path != "" {
			return ns.Path, nil
		}
	}
	return "", fmt.Errorf("%w: sandbox info names no network namespace path", ErrNamespaceUnavailable)
}
