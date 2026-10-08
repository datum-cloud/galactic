// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gateway

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	fabricv1 "go.datum.net/galactic/api/fabric/v1"
	"go.datum.net/galactic/internal/fabric/errcode"
	"go.datum.net/galactic/internal/fabric/identity"
	"go.datum.net/galactic/internal/fabric/node"
	"go.datum.net/galactic/internal/fabric/query"
)

// operatorHeader carries the original operator's name on a call a follower
// forwards to the leader. The leader trusts it only from the gateway
// identity.
const operatorHeader = "x-fabric-api-operator"

// DebugMethods is the debug server's per-role method table. Operators call
// it directly; the gateway identity appears only on calls a follower
// forwards to the leader.
var DebugMethods = map[identity.Role]map[string]bool{
	identity.RoleOperator: {
		fabricv1.FabricGatewayService_Query_FullMethodName:     true,
		fabricv1.FabricGatewayService_ListNodes_FullMethodName: true,
	},
	identity.RoleGateway: {
		fabricv1.FabricGatewayService_Query_FullMethodName: true,
	},
}

// AllowedDebugCaller is the debug server's handshake check.
func AllowedDebugCaller(id identity.ID) error {
	if id.Role == identity.RoleOperator || id.Role == identity.RoleGateway {
		return nil
	}
	return errcode.Status(errcode.Unauthorized, "identity "+id.URI()+" may not call the fabric-api gateway")
}

// Debug implements the operator debug service. Only the leader executes;
// a follower forwards Query to the leader, found from the election lease, so
// the Service can balance across both replicas.
type Debug struct {
	fabricv1.UnimplementedFabricGatewayServiceServer

	Discoverer *Discoverer
	Runner     *Runner
	Ceilings   query.Budgets
	// Elected reports whether this replica leads.
	Elected func() bool
	// Reader reads the election lease and the leader's pod.
	Reader      client.Reader
	Namespace   string
	LeaseName   string
	PodName     string
	Port        int
	Credentials *identity.Credentials
	Cell        string
	// DialOptions are added to the connection to the leader.
	DialOptions []grpc.DialOption
	conns       sync.Map
}

// Query runs a query on the cell's eligible nodes.
func (d *Debug) Query(ctx context.Context, req *fabricv1.QueryRequest) (*fabricv1.QueryResponse, error) {
	operator, err := d.operator(ctx)
	if err != nil {
		return nil, err
	}
	if !d.Elected() {
		return d.forward(ctx, operator, req)
	}
	q, err := query.Canonicalize(node.QueryFromProto(req.GetQuery()))
	if err != nil {
		return nil, errcode.FromError(err)
	}
	if q.Type.Probe() {
		if _, err := query.ResolvedProbe(q); err != nil {
			return nil, errcode.FromError(err)
		}
	}
	timeout := query.MaxNodeExecution
	if t := req.GetTimeout().AsDuration(); t > 0 && t < timeout {
		timeout = t
	}
	expires := time.Now().Add(timeout)
	ceil := d.Ceilings.Clamp()
	nodes, err := d.Discoverer.Snapshot(ctx, nil, ceil.MaxNodes)
	if err != nil {
		return nil, errcode.Status(errcode.Internal, err.Error())
	}
	if len(req.GetNodes()) > 0 {
		want := map[string]bool{}
		for _, n := range req.GetNodes() {
			want[n] = true
		}
		for i := range nodes {
			if !want[nodes[i].Name] {
				nodes[i].Selected = false
			}
		}
	}
	budgets := req.GetBudgets()
	if budgets == nil {
		budgets = &fabricv1.Budgets{}
	}
	id := "debug-" + randomID()
	outcomes := d.Runner.Run(ctx, "operator/"+operator, id, q, nodes, budgets, expires)
	resp := &fabricv1.QueryResponse{RequestId: id}
	for _, o := range outcomes {
		nr := &fabricv1.NodeResult{Node: o.Node.Name, Observation: o.Observation}
		if o.Err != nil {
			nr.ErrorCode, nr.ErrorMessage = string(errcode.Of(o.Err)), errcode.Message(o.Err)
		}
		resp.Results = append(resp.Results, nr)
	}
	return resp, nil
}

// ListNodes lists the nodes a query would execute on. Any replica answers.
func (d *Debug) ListNodes(ctx context.Context, _ *fabricv1.ListNodesRequest) (*fabricv1.ListNodesResponse, error) {
	nodes, err := d.Discoverer.Snapshot(ctx, nil, d.Ceilings.Clamp().MaxNodes)
	if err != nil {
		return nil, errcode.Status(errcode.Internal, err.Error())
	}
	resp := &fabricv1.ListNodesResponse{}
	for _, n := range nodes {
		resp.Nodes = append(resp.Nodes, &fabricv1.NodeEndpoint{
			Node: n.Name, Pod: n.Pod, PodUid: n.PodUID, HostIp: n.HostIP, Ready: n.Selected,
		})
	}
	return resp, nil
}

// operator returns the operator a call acts for: the caller itself, or, for
// a call forwarded by a gateway follower, the operator it names.
func (d *Debug) operator(ctx context.Context) (string, error) {
	id, ok := node.CallerFrom(ctx)
	if !ok {
		return "", errcode.Status(errcode.Unauthorized, "no caller identity")
	}
	switch id.Role {
	case identity.RoleOperator:
		return id.Name, nil
	case identity.RoleGateway:
		md, _ := metadata.FromIncomingContext(ctx)
		if v := md.Get(operatorHeader); len(v) == 1 && v[0] != "" {
			return v[0], nil
		}
	}
	return "", errcode.Status(errcode.Unauthorized, "only operators may run debug queries")
}

// forward sends Query to the leader with this replica's gateway identity.
func (d *Debug) forward(
	ctx context.Context, operator string, req *fabricv1.QueryRequest,
) (*fabricv1.QueryResponse, error) {
	addr, err := d.leaderAddress(ctx)
	if err != nil {
		return nil, errcode.Status(errcode.NodeUnreachable, "no leader is elected: "+err.Error())
	}
	conn, err := d.conn(addr)
	if err != nil {
		return nil, errcode.Status(errcode.NodeUnreachable, err.Error())
	}
	ctx = metadata.AppendToOutgoingContext(ctx, operatorHeader, operator)
	return fabricv1.NewFabricGatewayServiceClient(conn).Query(ctx, req)
}

func (d *Debug) conn(addr string) (*grpc.ClientConn, error) {
	if c, ok := d.conns.Load(addr); ok {
		return c.(*grpc.ClientConn), nil
	}
	opts := append([]grpc.DialOption{
		grpc.WithTransportCredentials(credentials.NewTLS(d.Credentials.ClientConfig(identity.Gateway(d.Cell)))),
	}, d.DialOptions...)
	c, err := grpc.NewClient(addr, opts...)
	if err != nil {
		return nil, err
	}
	if prev, loaded := d.conns.LoadOrStore(addr, c); loaded {
		_ = c.Close()
		return prev.(*grpc.ClientConn), nil
	}
	return c, nil
}

// leaderAddress resolves the lease holder (controller-runtime names it
// "<pod>_<uuid>") to its pod IP.
func (d *Debug) leaderAddress(ctx context.Context) (string, error) {
	var lease coordinationv1.Lease
	if err := d.Reader.Get(ctx, client.ObjectKey{Namespace: d.Namespace, Name: d.LeaseName}, &lease); err != nil {
		return "", err
	}
	if lease.Spec.HolderIdentity == nil || *lease.Spec.HolderIdentity == "" {
		return "", fmt.Errorf("lease %s has no holder", d.LeaseName)
	}
	pod, _, _ := strings.Cut(*lease.Spec.HolderIdentity, "_")
	if pod == d.PodName {
		return "", errors.New("lease names this replica, which is not leading")
	}
	var p corev1.Pod
	if err := d.Reader.Get(ctx, client.ObjectKey{Namespace: d.Namespace, Name: pod}, &p); err != nil {
		return "", err
	}
	if p.Status.PodIP == "" {
		return "", fmt.Errorf("leader pod %s has no IP", pod)
	}
	return fmt.Sprintf("%s:%d", hostPort(p.Status.PodIP), d.Port), nil
}

func randomID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
