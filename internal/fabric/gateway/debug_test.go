// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gateway

import (
	"context"
	"net"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	fabricv1 "go.datum.net/galactic/api/fabric/v1"
	fabricapi "go.datum.net/galactic/internal/fabric/api/v1alpha1"
	"go.datum.net/galactic/internal/fabric/errcode"
	"go.datum.net/galactic/internal/fabric/identity"
	"go.datum.net/galactic/internal/fabric/node"
	"go.datum.net/galactic/internal/fabric/query"
	"go.datum.net/galactic/internal/fabric/testpki"
)

func loadCreds(t *testing.T, ca *testpki.CA, dir string, id identity.ID) *identity.Credentials {
	t.Helper()
	f := ca.Issue(t, filepath.Join(dir, string(id.Role)+id.Name), testpki.Options{URIs: []string{id.URI()}})
	c := &identity.Credentials{CertFile: f.Cert, KeyFile: f.Key, CAFile: f.CA, Self: id}
	if err := c.Reload(); err != nil {
		t.Fatal(err)
	}
	return c
}

// testLeaseName is the leader-election lease the debug tests point at.
const testLeaseName = "fabric-api-gateway"

func serveDebug(t *testing.T, d *Debug, creds *identity.Credentials) string {
	t.Helper()
	srv := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(creds.ServerConfig(AllowedDebugCaller))),
		grpc.ChainUnaryInterceptor(node.AuthInterceptor(DebugMethods)),
	)
	fabricv1.RegisterFabricGatewayServiceServer(srv, d)
	var lc net.ListenConfig
	l, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(srv.Stop)
	return l.Addr().String()
}

func TestDebugForwardsToLeader(t *testing.T) {
	dir := t.TempDir()
	ca := testpki.NewCA(t, testSite)
	gwCreds := loadCreds(t, ca, dir, identity.Gateway(testSite))
	opCreds := loadCreds(t, ca, dir, identity.Operator(testSite, "alice"))

	s := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(s)
	sel, _ := labels.Parse(DefaultPodSelector)
	pods := fake.NewClientBuilder().WithScheme(s).
		WithObjects(fabricPod("fr-a", "edge-a", nil), fabricPod("fr-b", testNodeB, nil)).
		Build()
	nodes := &fakeNodes{answer: summaryAnswer}
	leader := &Debug{
		Discoverer: &Discoverer{Reader: pods, Namespace: DefaultNamespace, Selector: sel},
		Runner:     &Runner{Clients: nodes, Executor: NewExecutor(4, 1, 16)},
		Elected:    func() bool { return true },
	}
	leaderAddr := serveDebug(t, leader, gwCreds)
	host, portStr, _ := net.SplitHostPort(leaderAddr)
	port, _ := strconv.Atoi(portStr)

	holder := "gw-leader_1234"
	lease := &coordinationv1.Lease{ObjectMeta: metav1.ObjectMeta{Name: testLeaseName, Namespace: DefaultNamespace},
		Spec: coordinationv1.LeaseSpec{HolderIdentity: &holder}}
	leaderPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "gw-leader", Namespace: DefaultNamespace},
		Status:     corev1.PodStatus{PodIP: host},
	}
	reader := fake.NewClientBuilder().WithScheme(s).WithObjects(lease, leaderPod).Build()
	follower := &Debug{
		Discoverer: leader.Discoverer, Runner: leader.Runner, Elected: func() bool { return false },
		Reader: reader, Namespace: DefaultNamespace, LeaseName: testLeaseName, PodName: "gw-follower",
		Port: port, Credentials: gwCreds, Cell: testSite,
	}
	followerAddr := serveDebug(t, follower, gwCreds)

	conn, err := grpc.NewClient(followerAddr,
		grpc.WithTransportCredentials(credentials.NewTLS(opCreds.ClientConfig(identity.Gateway(testSite)))))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp, err := fabricv1.NewFabricGatewayServiceClient(conn).Query(ctx, &fabricv1.QueryRequest{
		Query: node.QueryToProto(query.Query{Type: query.TypeBGPSummary, AddressFamily: query.IPv4}),
		Nodes: []string{testNodeB},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.GetResults()) != 1 || resp.GetResults()[0].GetNode() != testNodeB ||
		resp.GetResults()[0].GetObservation() == nil {
		t.Fatalf("results = %+v", resp.GetResults())
	}
	// The leader accepted the forwarded call only because it carried the
	// operator: a gateway identity without the forwarding header is refused.
	gwConn, _ := grpc.NewClient(leaderAddr,
		grpc.WithTransportCredentials(credentials.NewTLS(gwCreds.ClientConfig(identity.Gateway(testSite)))))
	defer func() { _ = gwConn.Close() }()
	_, err = fabricv1.NewFabricGatewayServiceClient(gwConn).Query(ctx, &fabricv1.QueryRequest{
		Query: node.QueryToProto(query.Query{Type: query.TypeBGPSummary, AddressFamily: query.IPv4})})
	if errcode.Of(err) != errcode.Unauthorized {
		t.Errorf("unforwarded gateway call: %v", err)
	}

	// No leader: the follower reports it rather than executing.
	none := &Debug{Elected: func() bool { return false }, Reader: fake.NewClientBuilder().WithScheme(s).Build(),
		Namespace: DefaultNamespace, LeaseName: testLeaseName}
	_, err = none.Query(node.WithCaller(ctx, identity.Operator(testSite, "alice")), &fabricv1.QueryRequest{})
	if errcode.Of(err) != errcode.NodeUnreachable {
		t.Errorf("no leader: %v", err)
	}
}

func TestJanitor(t *testing.T) {
	now := time.Now()
	old := metav1.NewTime(now.Add(-2 * time.Hour))
	recent := metav1.NewTime(now.Add(-30 * time.Minute))
	completedLate := metav1.NewTime(now.Add(-10 * time.Minute))
	objs := []client.Object{
		newQuery("expired-long-ago", func(fq *fabricapi.FabricQuery) { fq.Spec.ExpiresAt = old }),
		newQuery("expired-recently", func(fq *fabricapi.FabricQuery) { fq.Spec.ExpiresAt = recent }),
		newQuery("live", nil),
		newQuery("completed-recently", func(fq *fabricapi.FabricQuery) {
			fq.Spec.ExpiresAt = old
			fq.Status.CompletionTime = &completedLate
		}),
	}
	s := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(s)
	_ = fabricapi.AddToScheme(s)
	c := fake.NewClientBuilder().WithScheme(s).WithStatusSubresource(&fabricapi.FabricQuery{}).WithObjects(objs...).Build()
	j := &Janitor{Client: c, Now: func() time.Time { return now }}
	n, err := j.Sweep(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("deleted %d, want 1", n)
	}
	var list fabricapi.FabricQueryList
	_ = c.List(context.Background(), &list)
	left := map[string]bool{}
	for _, i := range list.Items {
		left[i.Name] = true
	}
	if left["expired-long-ago"] || !left["expired-recently"] || !left["live"] || !left["completed-recently"] {
		t.Errorf("remaining = %v", left)
	}
}
