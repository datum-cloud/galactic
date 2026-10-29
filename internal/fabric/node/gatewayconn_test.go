// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package node

import (
	"context"
	"crypto/x509"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	permitv1 "go.datum.net/galactic/api/fabric/permit/v1"
	"go.datum.net/galactic/internal/fabric/identity"
	"go.datum.net/galactic/internal/fabric/testpki"
)

// recordingPermits records the identity each permit request arrives with,
// and holds a request whose node is "hold" until release closes.
type recordingPermits struct {
	permitv1.UnimplementedPermitServiceServer
	mu      sync.Mutex
	callers []string
	held    chan struct{}
	release chan struct{}
}

func (r *recordingPermits) RequestPermit(
	ctx context.Context, req *permitv1.RequestPermitRequest,
) (*permitv1.RequestPermitResponse, error) {
	id, err := peerIdentity(ctx)
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	r.callers = append(r.callers, id.Name)
	r.mu.Unlock()
	if req.GetNode() == "hold" {
		close(r.held)
		<-r.release
	}
	return &permitv1.RequestPermitResponse{}, nil
}

func (r *recordingPermits) last() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.callers[len(r.callers)-1]
}

// A node's permit requests present its current certificate after the
// credentials reload with a new certs pod's identity, and a request
// running across the reload completes on its own connection.
func TestGatewayConnFollowsCredentials(t *testing.T) {
	dir := t.TempDir()
	ca := testpki.NewCA(t, "dfw")
	gwCreds := creds(t, ca, dir, identity.Gateway("dfw"))
	permits := &recordingPermits{held: make(chan struct{}), release: make(chan struct{})}
	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(gwCreds.ServerConfig(func(identity.ID) error { return nil }))))
	permitv1.RegisterPermitServiceServer(srv, permits)
	var lc net.ListenConfig
	l, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(srv.Stop)

	nodeDir := filepath.Join(dir, "node")
	issue := func(pod string) {
		id := identity.Node("dfw", "galactic-system", pod)
		ca.Issue(t, nodeDir, testpki.Options{URIs: []string{id.URI()}})
	}
	issue("fabric-api-certs-a")
	nodeCreds := &identity.Credentials{
		CertFile: filepath.Join(nodeDir, "tls.crt"), KeyFile: filepath.Join(nodeDir, "tls.key"),
		CAFile: filepath.Join(nodeDir, "ca.crt"), Self: identity.Node("dfw", "galactic-system", ""), AcceptAnyNode: true,
	}
	if err := nodeCreds.Reload(); err != nil {
		t.Fatal(err)
	}
	gw, err := NewGatewayConn(func() (*grpc.ClientConn, error) {
		return grpc.NewClient(l.Addr().String(),
			grpc.WithTransportCredentials(credentials.NewTLS(nodeCreds.ClientConfig(identity.Gateway("dfw")))))
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = gw.Close() })
	nodeCreds.OnLoad(func(*x509.Certificate) { gw.Redial() })

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	if _, err := gw.RequestPermit(ctx, &permitv1.RequestPermitRequest{Node: "n"}); err != nil {
		t.Fatal(err)
	}
	if got := permits.last(); got != "fabric-api-certs-a" {
		t.Fatalf("first request from %q", got)
	}

	held := make(chan error, 1)
	go func() {
		_, err := gw.RequestPermit(ctx, &permitv1.RequestPermitRequest{Node: "hold"})
		held <- err
	}()
	<-permits.held

	// The certs pod is replaced: the node's certificate names the new pod.
	issue("fabric-api-certs-b")
	if err := nodeCreds.Reload(); err != nil {
		t.Fatal(err)
	}
	if _, err := gw.RequestPermit(ctx, &permitv1.RequestPermitRequest{Node: "n"}); err != nil {
		t.Fatal(err)
	}
	if got := permits.last(); got != "fabric-api-certs-b" {
		t.Errorf("request after the reload from %q, want the new certs pod", got)
	}

	close(permits.release)
	if err := <-held; err != nil {
		t.Errorf("request running across the reload: %v", err)
	}
}
