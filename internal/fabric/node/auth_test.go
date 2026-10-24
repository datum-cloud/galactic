// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package node

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"go.datum.net/galactic/internal/fabric/errcode"
	"go.datum.net/galactic/internal/fabric/identity"
	"go.datum.net/galactic/internal/fabric/testpki"
)

const testMethod = "/test.Service/Method"

// peerContext returns a context carrying a verified TLS peer that presents
// the certificate in f.
func peerContext(t *testing.T, f testpki.Files) (context.Context, *x509.Certificate) {
	t.Helper()
	b, err := os.ReadFile(f.Cert)
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode(b)
	leaf, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	p := &peer.Peer{AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}}}
	return peer.NewContext(t.Context(), p), leaf
}

type fakeStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *fakeStream) Context() context.Context { return s.ctx }

func TestAuthorizer(t *testing.T) {
	dir := t.TempDir()
	ca := testpki.NewCA(t, "dfw")
	gwID := identity.Gateway("dfw")
	server := creds(t, ca, dir, gwID)
	now := time.Now()
	server.Now = func() time.Time { return now }

	opID := identity.Operator("dfw", "alice")
	opFiles := ca.Issue(t, filepath.Join(dir, "alice"), testpki.Options{
		URIs: []string{opID.URI()}, NotAfter: now.Add(time.Hour),
	})
	ctx, leaf := peerContext(t, opFiles)
	denied := errors.New("not listed")
	a := &Authorizer{
		Methods:     map[identity.Role]map[string]bool{identity.RoleOperator: {testMethod: true}},
		Credentials: server,
		Allow: func(id identity.ID) error {
			if id.Name != "alice" {
				return denied
			}
			return nil
		},
	}

	// A permitted stream sees its caller and ends at the certificate's
	// expiry.
	var seen context.Context
	err := a.Stream()(nil, &fakeStream{ctx: ctx}, &grpc.StreamServerInfo{FullMethod: testMethod},
		func(_ any, ss grpc.ServerStream) error {
			seen = ss.Context()
			return nil
		})
	if err != nil {
		t.Fatalf("stream: %v", err)
	}
	if id, ok := CallerFrom(seen); !ok || id != opID {
		t.Errorf("stream caller = %v, %v", id, ok)
	}
	if d, ok := seen.Deadline(); !ok || !d.Equal(leaf.NotAfter) {
		t.Errorf("stream deadline = %v, %v; want %v", d, ok, leaf.NotAfter)
	}

	// The same for a unary call.
	unary := &grpc.UnaryServerInfo{FullMethod: testMethod}
	_, err = a.Unary()(ctx, nil, unary, func(ctx context.Context, _ any) (any, error) {
		seen = ctx
		return nil, nil
	})
	if d, ok := seen.Deadline(); err != nil || !ok || !d.Equal(leaf.NotAfter) {
		t.Errorf("unary: %v, deadline %v %v", err, d, ok)
	}

	reached := func(context.Context, any) (any, error) { return nil, errors.New("handler reached") }

	// A method outside the role's table.
	_, err = a.Unary()(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/test.Service/Other"}, reached)
	if errcode.Of(err) != errcode.Unauthorized {
		t.Errorf("unlisted method: %v", err)
	}

	// An identity the allow check refuses.
	otherID := identity.Operator("dfw", "bob")
	otherFiles := ca.Issue(t, filepath.Join(dir, "other"), testpki.Options{URIs: []string{otherID.URI()}})
	otherCtx, _ := peerContext(t, otherFiles)
	if _, err = a.Unary()(otherCtx, nil, &grpc.UnaryServerInfo{FullMethod: testMethod}, reached); !errors.Is(err, denied) {
		t.Errorf("refused identity: %v", err)
	}

	// The chain is re-verified on every call: once the client's CA leaves
	// the server's bundle, the connection it opened authorizes nothing.
	rotated := testpki.NewCA(t, "dfw rotated")
	rotated.Issue(t, filepath.Join(dir, "gateway"), testpki.Options{URIs: []string{gwID.URI()}})
	if err := server.Reload(); err != nil {
		t.Fatal(err)
	}
	_, err = a.Unary()(ctx, nil, &grpc.UnaryServerInfo{FullMethod: testMethod}, reached)
	if status.Code(err) != codes.Unauthenticated {
		t.Errorf("CA left the bundle: %v", err)
	}
	ca.Issue(t, filepath.Join(dir, "gateway"), testpki.Options{URIs: []string{gwID.URI()}},
		append(append([]byte{}, ca.PEM...), rotated.PEM...))
	if err := server.Reload(); err != nil {
		t.Fatal(err)
	}
	if _, err = a.Unary()(ctx, nil, unary, func(context.Context, any) (any, error) { return nil, nil }); err != nil {
		t.Errorf("CA back in an overlapping bundle: %v", err)
	}

	// Validity is checked on every call too: once the clock passes the
	// certificate's expiry, the connection it opened authorizes nothing.
	now = leaf.NotAfter.Add(time.Second)
	_, err = a.Unary()(ctx, nil, &grpc.UnaryServerInfo{FullMethod: testMethod}, reached)
	if status.Code(err) != codes.Unauthenticated {
		t.Errorf("expired certificate: %v", err)
	}
	err = a.Stream()(nil, &fakeStream{ctx: ctx}, &grpc.StreamServerInfo{FullMethod: testMethod},
		func(any, grpc.ServerStream) error { return errors.New("handler reached") })
	if status.Code(err) != codes.Unauthenticated {
		t.Errorf("expired certificate on a stream: %v", err)
	}

	// A call with no TLS peer.
	_, err = a.Unary()(t.Context(), nil, &grpc.UnaryServerInfo{FullMethod: testMethod}, reached)
	if status.Code(err) != codes.Unauthenticated {
		t.Errorf("no peer: %v", err)
	}
}
