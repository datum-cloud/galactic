// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package node

import (
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	fabricv1 "go.datum.net/galactic/api/fabric/v1"
	"go.datum.net/galactic/internal/fabric/errcode"
	"go.datum.net/galactic/internal/fabric/identity"
	"go.datum.net/galactic/internal/fabric/query"
	"go.datum.net/galactic/internal/fabric/testpki"
)

func creds(t *testing.T, ca *testpki.CA, dir string, id identity.ID) *identity.Credentials {
	t.Helper()
	f := ca.Issue(t, filepath.Join(dir, id.Name+string(id.Role)), testpki.Options{URIs: []string{id.URI()}})
	c := &identity.Credentials{CertFile: f.Cert, KeyFile: f.Key, CAFile: f.CA, Self: id}
	if err := c.Reload(); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestGRPCOverMTLS(t *testing.T) {
	dir := t.TempDir()
	ca := testpki.NewCA(t, "dfw")
	nodeID := identity.Node("dfw", "galactic-system", "fabric-router-a")
	nodeCreds := creds(t, ca, dir, nodeID)

	s := newServer(t, newFakeFRR(t), func(c *Config) { c.Credentials = nodeCreds })
	srv := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(nodeCreds.ServerConfig(AllowedCaller))),
		grpc.ChainUnaryInterceptor(AuthInterceptor(nil)),
	)
	fabricv1.RegisterFabricServiceServer(srv, s)
	var lc net.ListenConfig
	l, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(srv.Stop)

	dial := func(client *identity.Credentials, want identity.ID) fabricv1.FabricServiceClient {
		conn, err := grpc.NewClient(l.Addr().String(),
			grpc.WithTransportCredentials(credentials.NewTLS(client.ClientConfig(want))))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		return fabricv1.NewFabricServiceClient(conn)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	gw := dial(creds(t, ca, dir, identity.Gateway("dfw")), nodeID)
	resp, err := gw.Execute(ctx, request(query.Query{Type: query.TypeBGPSummary}))
	if err != nil || resp.GetObservation().GetSummary() == nil {
		t.Fatalf("gateway Execute: %v", err)
	}
	info, err := gw.Info(ctx, &fabricv1.InfoRequest{})
	if err != nil || !info.GetDiagnosticsAvailable() || info.GetSite() != "dfw" {
		t.Fatalf("Info = %+v, %v", info, err)
	}

	// Typed errors survive the wire.
	bad := request(query.Query{Type: query.TypeBGPSummary})
	bad.Node = "elsewhere"
	_, err = gw.Execute(ctx, bad)
	if errcode.Of(err) != errcode.WrongNode {
		t.Errorf("wrong node over gRPC: %v", err)
	}

	// The operator's policy applies to operator callers end to end.
	op := dial(creds(t, ca, dir, identity.Operator("dfw", "lab")), nodeID)
	if _, err := op.Execute(ctx, request(query.Query{Type: query.TypePing, Target: testLoopback})); err != nil {
		t.Errorf("operator probe of an excepted loopback: %v", err)
	}
	_, err = gw.Execute(ctx, request(query.Query{Type: query.TypePing, Target: testLoopback}))
	if errcode.Of(err) != errcode.DestinationNotAllowed {
		t.Errorf("gateway probe of a loopback: %v", err)
	}

	// Another node may not call a node.
	peer := dial(creds(t, ca, dir, identity.Node("dfw", "galactic-system", "fabric-router-b")), nodeID)
	if _, err := peer.Info(ctx, &fabricv1.InfoRequest{}); err == nil {
		t.Error("a node identity was allowed to call another node")
	}

	// The gateway refuses a server presenting the wrong pod identity.
	wrong := dial(creds(t, ca, dir, identity.Gateway("dfw")), identity.Node("dfw", "galactic-system", "fabric-router-z"))
	if _, err := wrong.Info(ctx, &fabricv1.InfoRequest{}); err == nil {
		t.Error("client accepted the wrong server identity")
	}
}
